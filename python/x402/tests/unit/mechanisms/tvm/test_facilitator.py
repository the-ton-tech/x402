"""Tests for TVM exact facilitator settlement confirmation."""

from __future__ import annotations

import base64
from dataclasses import replace
import threading
import time

import pytest

pytest.importorskip("pytoniq_core")

from x402.mechanisms.tvm import (
    ERR_INVALID_JETTON_TRANSFER,
    ERR_INVALID_RECIPIENT,
    ERR_INVALID_SETTLEMENT_BOC,
    TVM_TESTNET,
)
from x402.mechanisms.tvm.exact.facilitator import ExactTvmScheme
from x402.mechanisms.tvm.types import (
    ParsedJettonTransfer,
    ParsedTvmSettlement,
    TvmAccountState,
    TvmRelayRequest,
    W5InitData,
)
from x402.schemas import PaymentPayload, PaymentRequirements, ResourceInfo, VerifyResponse

PAYER = "0:" + "1" * 64
MERCHANT = "0:" + "2" * 64
ASSET = "0:" + "3" * 64
SOURCE_WALLET_1 = "0:" + "4" * 64
SOURCE_WALLET_2 = "0:" + "5" * 64


class FakeCell:
    def __init__(self, raw_hash: bytes) -> None:
        self.hash = raw_hash


class MockSigner:
    def __init__(self, finalized_trace: dict[str, object]) -> None:
        self.finalized_trace = finalized_trace
        self.sent_batches: list[list[TvmRelayRequest]] = []

    def get_addresses(self) -> list[str]:
        return ["0:" + "f" * 64]

    def get_jetton_wallet(self, asset: str, owner: str, network: str) -> str:
        _ = asset, owner, network
        return SOURCE_WALLET_1

    def build_relay_external_boc_batch(
        self,
        network: str,
        relay_requests: list[TvmRelayRequest],
        *,
        for_emulation: bool = False,
    ) -> bytes:
        _ = network, for_emulation
        self.sent_batches.append(relay_requests)
        return b"external-boc"

    def send_external_message(self, network: str, external_boc: bytes) -> str:
        _ = network, external_boc
        return "trace-hash-1"

    def wait_for_trace_confirmation(
        self,
        network: str,
        trace_external_hash_norm: str,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        _ = network, trace_external_hash_norm, timeout_seconds
        return self.finalized_trace


def _make_requirements(*, amount: str) -> PaymentRequirements:
    return PaymentRequirements(
        scheme="exact",
        network=TVM_TESTNET,
        asset=ASSET,
        amount=amount,
        pay_to=MERCHANT,
        max_timeout_seconds=300,
        extra={"areFeesSponsored": True},
    )


def _make_payload(settlement_boc: str, *, amount: str) -> PaymentPayload:
    return PaymentPayload(
        x402_version=2,
        resource=ResourceInfo(
            url="https://example.com/protected",
            description="test",
            mime_type="application/json",
        ),
        accepted=_make_requirements(amount=amount),
        payload={
            "settlementBoc": settlement_boc,
            "asset": ASSET,
        },
    )


def _make_settlement(*, settlement_hash: str, source_wallet: str, amount: int) -> ParsedTvmSettlement:
    body_hash = f"{settlement_hash}-body".encode("ascii")
    transfer_body_hash = f"{settlement_hash}-transfer".encode("ascii")
    return ParsedTvmSettlement(
        payer=PAYER,
        wallet_id=1,
        valid_until=9999999999,
        seqno=1,
        settlement_hash=settlement_hash,
        body=FakeCell(body_hash),  # type: ignore[arg-type]
        signed_slice_hash=b"",
        signature=b"",
        state_init=None,
        transfer=ParsedJettonTransfer(
            source_wallet=source_wallet,
            destination=MERCHANT,
            response_destination=MERCHANT,
            jetton_amount=amount,
            forward_ton_amount=1,
            body_hash=transfer_body_hash,
        ),
    )


def _hash_string(raw_hash: bytes) -> str:
    return base64.b64encode(raw_hash).decode("ascii")


def _make_finalized_trace(
    *,
    settlement: ParsedTvmSettlement,
    source_wallet_tx_hash: str = "source-wallet-tx-1",
    include_action: bool = True,
    include_source_wallet_tx: bool = True,
) -> dict[str, object]:
    payer_out_hash = f"{source_wallet_tx_hash}-in".encode("ascii")
    action: dict[str, object] = {
        "type": "jetton_transfer",
        "success": True,
        "details": {
            "asset": ASSET,
            "receiver": MERCHANT,
            "sender": PAYER,
            "sender_jetton_wallet": settlement.transfer.source_wallet,
            "amount": str(settlement.transfer.jetton_amount),
        },
    }
    transactions: dict[str, object] = {
        "payer-wallet-tx": {
            "hash": "payer-wallet-tx",
            "account": PAYER,
            "description": {
                "aborted": False,
                "action": {"success": True},
                "compute_ph": {"success": True, "skipped": False},
            },
            "in_msg": {
                "message_content": {
                    "hash": _hash_string(settlement.body.hash),
                },
            },
            "out_msgs": [
                {
                    "hash": _hash_string(payer_out_hash),
                    "hash_norm": _hash_string(payer_out_hash),
                    "destination": settlement.transfer.source_wallet,
                    "message_content": {
                        "hash": _hash_string(settlement.transfer.body_hash or b""),
                    },
                }
            ],
        },
    }
    if include_source_wallet_tx:
        transactions[source_wallet_tx_hash] = {
            "hash": source_wallet_tx_hash,
            "account": settlement.transfer.source_wallet,
            "description": {
                "aborted": False,
                "action": {"success": True},
                "compute_ph": {"success": True, "skipped": False},
            },
            "in_msg": {
                "hash": _hash_string(payer_out_hash),
                "hash_norm": _hash_string(payer_out_hash),
            },
        }

    return {
        "type": "trace",
        "trace_external_hash_norm": "trace-hash-1",
        "transactions": transactions,
        "actions": [action] if include_action else [],
    }


def _patch_scheme_verification(monkeypatch, scheme: ExactTvmScheme, settlements: dict[str, ParsedTvmSettlement]) -> None:
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: settlements[settlement_boc],
    )
    monkeypatch.setattr(
        scheme,
        "_verify",
        lambda payload, requirements, tvm_payload, settlement: (
            VerifyResponse(is_valid=True, payer=settlement.payer),
            TvmRelayRequest(destination=settlement.payer, body=None, state_init=None),  # type: ignore[arg-type]
        ),
    )


def test_settle_succeeds_when_finalized_trace_contains_matching_jetton_transfer(monkeypatch):
    settlement = _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100)
    signer = MockSigner(_make_finalized_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_scheme_verification(monkeypatch, scheme, {"boc-1": settlement})

    response = scheme.settle(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.success is True
    assert response.transaction == "trace-hash-1"
    assert response.error_reason is None


def test_settle_succeeds_when_finalized_trace_has_no_actions_but_transaction_chain_matches(monkeypatch):
    settlement = _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100)
    signer = MockSigner(_make_finalized_trace(settlement=settlement, include_action=False))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_scheme_verification(monkeypatch, scheme, {"boc-1": settlement})

    response = scheme.settle(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.success is True
    assert response.transaction == "trace-hash-1"
    assert response.error_reason is None


def test_settle_fails_when_finalized_trace_has_no_matching_source_wallet_transaction(monkeypatch):
    settlement = _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100)
    signer = MockSigner(_make_finalized_trace(settlement=settlement, include_source_wallet_tx=False))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_scheme_verification(monkeypatch, scheme, {"boc-1": settlement})

    response = scheme.settle(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.success is False
    assert response.transaction == "trace-hash-1"
    assert response.error_reason == "transaction_failed"
    assert "source jetton wallet transaction" in (response.error_message or "")


def test_settle_batch_marks_each_settlement_individually(monkeypatch):
    settlement_1 = _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100)
    settlement_2 = _make_settlement(settlement_hash="settlement-2", source_wallet=SOURCE_WALLET_2, amount=200)
    signer = MockSigner(_make_finalized_trace(settlement=settlement_1))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=1.0, batch_max_size=2)
    _patch_scheme_verification(
        monkeypatch,
        scheme,
        {
            "boc-1": settlement_1,
            "boc-2": settlement_2,
        },
    )

    results: dict[str, object] = {}

    def settle(name: str, settlement_boc: str, amount: str) -> None:
        results[name] = scheme.settle(_make_payload(settlement_boc, amount=amount), _make_requirements(amount=amount))

    thread_1 = threading.Thread(target=settle, args=("first", "boc-1", "100"))
    thread_2 = threading.Thread(target=settle, args=("second", "boc-2", "200"))
    thread_1.start()
    thread_2.start()
    thread_1.join(timeout=2.0)
    thread_2.join(timeout=2.0)

    assert thread_1.is_alive() is False
    assert thread_2.is_alive() is False

    first = results["first"]
    second = results["second"]
    assert first.success is True
    assert first.transaction == "trace-hash-1"
    assert second.success is False
    assert second.transaction == "trace-hash-1"
    assert second.error_reason == "transaction_failed"


def test_settle_batch_matches_exact_settlement_transaction_chain(monkeypatch):
    settlement_1 = _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100)
    settlement_2 = _make_settlement(settlement_hash="settlement-2", source_wallet=SOURCE_WALLET_1, amount=100)
    signer = MockSigner(_make_finalized_trace(settlement=settlement_1, source_wallet_tx_hash="source-wallet-tx-1"))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=1.0, batch_max_size=2)
    _patch_scheme_verification(
        monkeypatch,
        scheme,
        {
            "boc-1": settlement_1,
            "boc-2": settlement_2,
        },
    )

    results: dict[str, object] = {}

    def settle(name: str, settlement_boc: str) -> None:
        results[name] = scheme.settle(_make_payload(settlement_boc, amount="100"), _make_requirements(amount="100"))

    thread_1 = threading.Thread(target=settle, args=("first", "boc-1"))
    thread_2 = threading.Thread(target=settle, args=("second", "boc-2"))
    thread_1.start()
    thread_2.start()
    thread_1.join(timeout=2.0)
    thread_2.join(timeout=2.0)

    assert thread_1.is_alive() is False
    assert thread_2.is_alive() is False

    first = results["first"]
    second = results["second"]
    assert first.success is True
    assert first.transaction == "trace-hash-1"
    assert second.success is False
    assert second.transaction == "trace-hash-1"
    assert second.error_reason == "transaction_failed"
    assert "payer wallet transaction" in (second.error_message or "")


def test_settle_returns_structured_error_for_invalid_payload(monkeypatch):
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: (_ for _ in ()).throw(ValueError(ERR_INVALID_SETTLEMENT_BOC)),
    )

    response = scheme.settle(_make_payload("bad-boc", amount="100"), _make_requirements(amount="100"))

    assert response.success is False
    assert response.error_reason == ERR_INVALID_SETTLEMENT_BOC
    assert response.transaction == ""
    assert response.payer == ""


def test_verify_rejects_forward_ton_amount_above_one(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100),
        transfer=replace(
            _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100).transfer,
            forward_ton_amount=2,
        ),
    )
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: settlement,
    )

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is False
    assert response.invalid_reason == ERR_INVALID_JETTON_TRANSFER


def test_verify_rejects_mismatched_response_destination(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100),
        transfer=replace(
            _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100).transfer,
            response_destination=PAYER,
        ),
    )
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: settlement,
    )

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is False
    assert response.invalid_reason == ERR_INVALID_JETTON_TRANSFER


def test_verify_rejects_noncanonical_source_wallet(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_2, amount=100),
        valid_until=int(time.time()) + 60,
    )
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)
    scheme._signer = type(
        "CanonicalMismatchSigner",
        (),
        {
            "get_addresses": lambda self: ["0:" + "f" * 64],
            "get_account_state": lambda self, address, network: TvmAccountState(
                address=address,
                balance=0,
                is_active=True,
                is_uninitialized=False,
                state_init=None,
            ),
            "get_jetton_wallet": lambda self, asset, owner, network: SOURCE_WALLET_1,
        },
    )()
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: settlement,
    )
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_active_w5_account_state",
        lambda account: W5InitData(
            signature_allowed=True,
            seqno=settlement.seqno,
            wallet_id=settlement.wallet_id,
            public_key=b"\x01" * 32,
            extensions_dict=None,
        ),
    )
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.verify_w5_signature",
        lambda public_key, signed_slice_hash, signature: True,
    )

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is False
    assert response.invalid_reason == ERR_INVALID_JETTON_TRANSFER
