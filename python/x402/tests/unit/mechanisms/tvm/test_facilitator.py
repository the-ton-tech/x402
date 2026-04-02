"""Tests for the exact TVM facilitator scheme."""

from __future__ import annotations

import base64
import time

import pytest

pytest.importorskip("pytoniq_core")

from pytoniq_core import begin_cell

import x402.mechanisms.tvm.exact.facilitator as facilitator_module
from x402.mechanisms.tvm import (
    ERR_DUPLICATE_SETTLEMENT,
    ERR_INVALID_AMOUNT,
    ERR_INVALID_ASSET,
    ERR_INVALID_JETTON_TRANSFER,
    ERR_INVALID_RECIPIENT,
    ERR_INVALID_SIGNATURE,
    ERR_INVALID_UNTIL_EXPIRED,
    ERR_NETWORK_MISMATCH,
    ERR_SIMULATION_FAILED,
    ERR_TRANSACTION_FAILED,
    ERR_UNSUPPORTED_NETWORK,
    ERR_UNSUPPORTED_SCHEME,
    ERR_VALID_UNTIL_TOO_FAR,
    TVM_TESTNET,
    ParsedJettonTransfer,
    ParsedTvmSettlement,
    SettlementCache,
    TvmAccountState,
    TvmJettonWalletData,
    TvmRelayRequest,
)
from x402.mechanisms.tvm.constants import DEFAULT_TVM_OUTER_GAS_BUFFER
from x402.mechanisms.tvm.exact import ExactTvmFacilitatorScheme
from x402.mechanisms.tvm.trace_utils import body_hash_to_base64
from x402.schemas import PaymentPayload, PaymentRequirements, ResourceInfo

PAYER = "0:" + "1" * 64
MERCHANT = "0:" + "2" * 64
ASSET = "0:" + "3" * 64
SOURCE_WALLET = "0:" + "4" * 64
FACILITATOR = "0:" + "f" * 64
EMPTY_FORWARD_PAYLOAD = begin_cell().store_bit(0).end_cell()
EMPTY_FORWARD_PAYLOAD_B64 = base64.b64encode(EMPTY_FORWARD_PAYLOAD.to_boc()).decode("ascii")


class _FakeCell:
    def __init__(self, raw_hash: bytes) -> None:
        self.hash = raw_hash


class _FakeBatcher:
    def __init__(
        self,
        signer,
        settlement_cache,
        *,
        flush_interval_seconds: float,
        batch_flush_size: int,
        confirmation_timeout_seconds: float,
    ) -> None:
        _ = signer, settlement_cache, flush_interval_seconds, batch_flush_size
        _ = confirmation_timeout_seconds
        self.enqueued: list[object] = []
        self.result = facilitator_module._BatchResult(success=True, transaction="trace-tx-hash")
        self.error: Exception | None = None

    def enqueue(self, queued_settlement):
        self.enqueued.append(queued_settlement)
        if self.error is not None:
            raise self.error
        return self.result


class _SignerStub:
    def __init__(self) -> None:
        self.account_state = TvmAccountState(
            address=PAYER,
            balance=0,
            is_active=True,
            is_uninitialized=False,
            state_init=None,
        )
        self.jetton_wallet_data = TvmJettonWalletData(
            address=SOURCE_WALLET,
            balance=1_000_000,
            owner=PAYER,
            jetton_minter=ASSET,
        )
        self.last_relay_request: TvmRelayRequest | None = None

    def get_addresses(self) -> list[str]:
        return [FACILITATOR]

    def get_addresses_for_network(self, network: str) -> list[str]:
        assert network == TVM_TESTNET
        return [FACILITATOR]

    def get_account_state(self, address: str, network: str) -> TvmAccountState:
        assert address == PAYER
        assert network == TVM_TESTNET
        return self.account_state

    def get_jetton_wallet(self, asset: str, owner: str, network: str) -> str:
        assert asset == ASSET
        assert owner == PAYER
        assert network == TVM_TESTNET
        return SOURCE_WALLET

    def get_jetton_wallet_data(self, address: str, network: str) -> TvmJettonWalletData:
        assert address == SOURCE_WALLET
        assert network == TVM_TESTNET
        return self.jetton_wallet_data

    def build_relay_external_boc(
        self, network: str, relay_request: TvmRelayRequest, *, for_emulation: bool = False
    ) -> bytes:
        assert network == TVM_TESTNET
        assert for_emulation is True
        self.last_relay_request = relay_request
        return b"external-boc"

    def emulate_external_message(self, network: str, external_boc: bytes) -> dict[str, object]:
        assert network == TVM_TESTNET
        assert external_boc == b"external-boc"
        return {"transactions": {}}


def _make_settlement(**overrides) -> ParsedTvmSettlement:
    transfer = ParsedJettonTransfer(
        source_wallet=overrides.pop("source_wallet", SOURCE_WALLET),
        destination=overrides.pop("destination", MERCHANT),
        response_destination=overrides.pop("response_destination", None),
        jetton_amount=overrides.pop("jetton_amount", 100),
        attached_ton_amount=overrides.pop("attached_ton_amount", 500_000),
        forward_ton_amount=overrides.pop("forward_ton_amount", 0),
        forward_payload=overrides.pop("forward_payload", EMPTY_FORWARD_PAYLOAD),
        body_hash=overrides.pop("body_hash", b"transfer-body-hash"),
    )
    return ParsedTvmSettlement(
        payer=overrides.pop("payer", PAYER),
        wallet_id=overrides.pop("wallet_id", 777),
        valid_until=overrides.pop("valid_until", int(time.time()) + 120),
        seqno=overrides.pop("seqno", 12),
        settlement_hash=overrides.pop("settlement_hash", "settlement-hash-1"),
        body=overrides.pop("body", _FakeCell(b"body-hash")),
        signed_slice_hash=overrides.pop("signed_slice_hash", b"signed-slice"),
        signature=overrides.pop("signature", b"signature"),
        state_init=overrides.pop("state_init", None),
        transfer=transfer,
        **overrides,
    )


def _make_requirements(**overrides) -> PaymentRequirements:
    extra = {
        "areFeesSponsored": True,
        "forwardPayload": EMPTY_FORWARD_PAYLOAD_B64,
        "forwardTonAmount": "0",
    }
    extra.update(overrides.pop("extra", {}))
    return PaymentRequirements(
        scheme="exact",
        network=overrides.pop("network", TVM_TESTNET),
        asset=overrides.pop("asset", ASSET),
        amount=overrides.pop("amount", "100"),
        pay_to=overrides.pop("pay_to", MERCHANT),
        max_timeout_seconds=overrides.pop("max_timeout_seconds", 300),
        extra=extra,
        **overrides,
    )


def _make_payload(**overrides) -> PaymentPayload:
    accepted_extra = {
        "areFeesSponsored": True,
        "forwardPayload": EMPTY_FORWARD_PAYLOAD_B64,
        "forwardTonAmount": "0",
    }
    accepted_extra.update(overrides.pop("accepted_extra", {}))
    return PaymentPayload(
        x402_version=overrides.pop("x402_version", 2),
        resource=ResourceInfo(
            url="http://example.com/protected",
            description="Test resource",
            mime_type="application/json",
        ),
        accepted=PaymentRequirements(
            scheme=overrides.pop("accepted_scheme", "exact"),
            network=overrides.pop("accepted_network", TVM_TESTNET),
            asset=overrides.pop("accepted_asset", ASSET),
            amount=overrides.pop("accepted_amount", "100"),
            pay_to=overrides.pop("accepted_pay_to", MERCHANT),
            max_timeout_seconds=overrides.pop("accepted_max_timeout_seconds", 300),
            extra=accepted_extra,
        ),
        payload={
            "settlementBoc": overrides.pop("settlement_boc", "base64-boc=="),
            "asset": overrides.pop("payload_asset", ASSET),
        },
        **overrides,
    )


@pytest.fixture
def facilitator_env(monkeypatch):
    batchers: list[_FakeBatcher] = []

    def _batcher_factory(*args, **kwargs):
        batcher = _FakeBatcher(*args, **kwargs)
        batchers.append(batcher)
        return batcher

    signer = _SignerStub()
    settlement = _make_settlement()
    monkeypatch.setattr(facilitator_module, "_SettlementBatcher", _batcher_factory)
    monkeypatch.setattr(facilitator_module, "parse_exact_tvm_payload", lambda boc: settlement)
    monkeypatch.setattr(
        facilitator_module,
        "parse_active_w5_account_state",
        lambda account: facilitator_module.W5InitData(
            signature_allowed=True,
            seqno=settlement.seqno,
            wallet_id=settlement.wallet_id,
            public_key=b"\x01" * 32,
            extensions_dict=None,
        ),
    )
    monkeypatch.setattr(facilitator_module, "verify_w5_signature", lambda *args: True)
    monkeypatch.setattr(
        facilitator_module,
        "trace_transaction_storage_fees",
        lambda tx: 10_000,
    )
    monkeypatch.setattr(
        facilitator_module,
        "trace_transaction_compute_fees",
        lambda tx: 20_000,
    )
    monkeypatch.setattr(
        facilitator_module,
        "trace_transaction_fwd_fees",
        lambda tx: 30_000,
    )
    monkeypatch.setattr(
        ExactTvmFacilitatorScheme,
        "_verify_finalized_trace_settlement",
        staticmethod(lambda *args, **kwargs: {"hash": "payer-tx"}),
    )

    facilitator = ExactTvmFacilitatorScheme(signer, SettlementCache())
    return {
        "facilitator": facilitator,
        "signer": signer,
        "settlement": settlement,
        "batcher": lambda: batchers[-1],
    }


class TestExactTvmFacilitatorSchemeConstructor:
    def test_should_create_instance_with_correct_scheme(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        assert facilitator.scheme == "exact"
        assert facilitator.caip_family == "tvm:*"

    def test_should_return_supported_extra_and_signers(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        assert facilitator.get_extra(TVM_TESTNET) == {"areFeesSponsored": True}
        assert facilitator.get_extra("tvm:123") is None
        assert facilitator.get_signers(TVM_TESTNET) == [FACILITATOR]


class TestVerify:
    def test_should_reject_wrong_scheme(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(accepted_scheme="wrong"),
            _make_requirements(),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_UNSUPPORTED_SCHEME

    def test_should_reject_unsupported_network(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(accepted_network="tvm:123"),
            _make_requirements(network="tvm:123"),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_UNSUPPORTED_NETWORK

    def test_should_reject_network_mismatch(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(accepted_network="tvm:-239"),
            _make_requirements(network=TVM_TESTNET),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_NETWORK_MISMATCH

    def test_should_reject_amount_mismatch(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(accepted_amount="101"),
            _make_requirements(amount="100"),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_INVALID_AMOUNT

    def test_should_reject_asset_mismatch(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(payload_asset="0:" + "9" * 64),
            _make_requirements(),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_INVALID_ASSET

    def test_should_reject_payee_mismatch(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(accepted_pay_to="0:" + "8" * 64),
            _make_requirements(),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_INVALID_RECIPIENT

    def test_should_reject_forward_amount_mismatch(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(
            _make_payload(accepted_extra={"forwardTonAmount": "1"}),
            _make_requirements(),
        )

        assert result.is_valid is False
        assert result.invalid_reason == ERR_INVALID_JETTON_TRANSFER

    def test_should_reject_expired_settlement(self, facilitator_env, monkeypatch):
        facilitator = facilitator_env["facilitator"]
        settlement = facilitator_env["settlement"]
        monkeypatch.setattr(
            facilitator_module,
            "parse_exact_tvm_payload",
            lambda boc: _make_settlement(valid_until=int(time.time()) - 1, seqno=settlement.seqno),
        )

        result = facilitator.verify(_make_payload(), _make_requirements())

        assert result.is_valid is False
        assert result.invalid_reason == ERR_INVALID_UNTIL_EXPIRED

    def test_should_reject_valid_until_beyond_timeout(self, facilitator_env, monkeypatch):
        facilitator = facilitator_env["facilitator"]
        monkeypatch.setattr(
            facilitator_module,
            "parse_exact_tvm_payload",
            lambda boc: _make_settlement(valid_until=int(time.time()) + 600),
        )

        result = facilitator.verify(_make_payload(), _make_requirements(max_timeout_seconds=300))

        assert result.is_valid is False
        assert result.invalid_reason == ERR_VALID_UNTIL_TOO_FAR

    def test_should_reject_invalid_signature(self, facilitator_env, monkeypatch):
        facilitator = facilitator_env["facilitator"]
        monkeypatch.setattr(facilitator_module, "verify_w5_signature", lambda *args: False)

        result = facilitator.verify(_make_payload(), _make_requirements())

        assert result.is_valid is False
        assert result.invalid_reason == ERR_INVALID_SIGNATURE

    def test_should_return_valid_response_for_matching_payload(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.verify(_make_payload(), _make_requirements())

        assert result.is_valid is True
        assert result.payer == PAYER


class TestSettle:
    def test_should_fail_settlement_if_verification_fails(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        result = facilitator.settle(
            _make_payload(accepted_scheme="wrong"),
            _make_requirements(),
        )

        assert result.success is False
        assert result.error_reason == ERR_UNSUPPORTED_SCHEME
        assert result.transaction == ""
        assert result.network == TVM_TESTNET

    def test_should_reject_duplicate_settlement(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]

        first = facilitator.settle(_make_payload(), _make_requirements())
        second = facilitator.settle(_make_payload(), _make_requirements())

        assert first.success is True
        assert second.success is False
        assert second.error_reason == ERR_DUPLICATE_SETTLEMENT
        assert second.payer == PAYER

    def test_should_return_successful_settlement_response(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]
        batcher = facilitator_env["batcher"]()

        result = facilitator.settle(_make_payload(), _make_requirements())

        assert result.success is True
        assert result.transaction == "trace-tx-hash"
        assert result.payer == PAYER
        assert result.network == TVM_TESTNET
        assert len(batcher.enqueued) == 1
        queued = batcher.enqueued[0]
        assert queued.network == TVM_TESTNET
        assert queued.settlement_hash == "settlement-hash-1"
        assert queued.relay_request.destination == PAYER
        assert queued.relay_request.relay_amount == (
            500_000 + 10_000 + 20_000 + 30_000 + DEFAULT_TVM_OUTER_GAS_BUFFER
        )

    def test_should_convert_batcher_exceptions_into_transaction_failed(self, facilitator_env):
        facilitator = facilitator_env["facilitator"]
        batcher = facilitator_env["batcher"]()
        batcher.error = RuntimeError("boom")

        result = facilitator.settle(_make_payload(), _make_requirements())

        assert result.success is False
        assert result.error_reason == ERR_TRANSACTION_FAILED
        assert result.error_message == "boom"

    def test_should_map_unexpected_verification_exception_to_simulation_failed(
        self, facilitator_env, monkeypatch
    ):
        facilitator = facilitator_env["facilitator"]
        monkeypatch.setattr(
            facilitator_module,
            "parse_exact_tvm_payload",
            lambda boc: (_ for _ in ()).throw(RuntimeError("decode crashed")),
        )

        result = facilitator.settle(_make_payload(), _make_requirements())

        assert result.success is False
        assert result.error_reason == ERR_SIMULATION_FAILED
        assert result.error_message == "decode crashed"


def _make_trace(
    *,
    include_payer_tx: bool = True,
    payer_tx_success: bool = True,
    include_matching_payer_out_msg: bool = True,
    include_source_wallet_tx: bool = True,
    payer_hash: str | None = "payer-tx-hash",
):
    settlement = _make_settlement()
    transactions: dict[str, object] = {}
    if include_payer_tx:
        transactions["payer"] = {
            "hash": payer_hash,
            "account": PAYER,
            "description": {
                "aborted": not payer_tx_success,
                "compute_ph": {"success": payer_tx_success, "skipped": False},
                "action": {"success": payer_tx_success},
            },
            "in_msg": {
                "message_content": {"hash": body_hash_to_base64(settlement.body.hash)},
            },
            "out_msgs": (
                [
                    {
                        "hash": "payer-out-hash",
                        "destination": SOURCE_WALLET,
                        "message_content": {
                            "hash": body_hash_to_base64(settlement.transfer.body_hash or b""),
                        },
                    }
                ]
                if include_matching_payer_out_msg
                else []
            ),
        }
    if include_source_wallet_tx:
        transactions["source"] = {
            "hash": "source-tx-hash",
            "account": SOURCE_WALLET,
            "description": {
                "aborted": False,
                "compute_ph": {"success": True, "skipped": False},
                "action": {"success": True},
            },
            "in_msg": {
                "hash": "payer-out-hash",
            },
        }
    return settlement, {"transactions": transactions}


class TestVerifyFinalizedTraceSettlement:
    def test_should_fail_when_trace_has_no_matching_payer_wallet_transaction(self):
        settlement, trace = _make_trace(include_payer_tx=False)

        with pytest.raises(ValueError, match="expected payer wallet transaction"):
            ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
                trace,
                settlement=settlement,
            )

    def test_should_ignore_failed_payer_wallet_transactions(self):
        settlement, trace = _make_trace(payer_tx_success=False)

        with pytest.raises(ValueError, match="expected payer wallet transaction"):
            ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
                trace,
                settlement=settlement,
            )

    def test_should_fail_when_payer_wallet_transaction_has_no_matching_out_message(self):
        settlement, trace = _make_trace(include_matching_payer_out_msg=False)

        with pytest.raises(ValueError, match="missing out message hash"):
            ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
                trace,
                settlement=settlement,
            )

    def test_should_fail_when_trace_has_no_matching_source_wallet_transaction(self):
        settlement, trace = _make_trace(include_source_wallet_tx=False)

        with pytest.raises(ValueError, match="expected source jetton wallet transaction"):
            ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
                trace,
                settlement=settlement,
            )

    def test_should_fail_when_payer_wallet_transaction_has_no_hash(self):
        settlement, trace = _make_trace(payer_hash="")

        with pytest.raises(ValueError, match="missing transaction hash"):
            ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
                trace,
                settlement=settlement,
            )

    def test_should_return_payer_transaction_hash_for_valid_trace(self):
        settlement, trace = _make_trace()

        result = ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
            trace,
            settlement=settlement,
        )

        assert result == "payer-tx-hash"

    def test_should_return_payer_transaction_object_when_requested(self):
        settlement, trace = _make_trace()

        result = ExactTvmFacilitatorScheme._verify_finalized_trace_settlement(
            trace,
            settlement=settlement,
            return_transaction=True,
        )

        assert result["hash"] == "payer-tx-hash"
