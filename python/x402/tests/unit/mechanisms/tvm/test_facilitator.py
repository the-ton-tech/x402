"""Tests for TVM exact facilitator settlement confirmation."""

from __future__ import annotations

import base64
import threading
import time
from dataclasses import replace

import pytest

pytest.importorskip("pytoniq_core")

from pytoniq.contract.contract import Contract
from pytoniq_core import Address, Cell, begin_cell
from pytoniq_core.tlb.transaction import MessageAny

from x402.mechanisms.tvm import (
    ERR_INVALID_JETTON_TRANSFER,
    ERR_INVALID_SETTLEMENT_BOC,
    ERR_INVALID_W5_ACTIONS,
    TVM_TESTNET,
    address_from_state_init,
    build_w5r1_state_init,
)
from x402.mechanisms.tvm.codecs.w5 import (
    parse_out_list,
    serialize_out_list,
    serialize_send_msg_action,
)
from x402.mechanisms.tvm.constants import W5_INTERNAL_SIGNED_OPCODE
from x402.mechanisms.tvm.exact.client import ExactTvmScheme as ExactTvmClientScheme
from x402.mechanisms.tvm.exact.facilitator import ExactTvmScheme
from x402.mechanisms.tvm.types import (
    ParsedJettonTransfer,
    ParsedTvmSettlement,
    TvmAccountState,
    TvmJettonWalletData,
    TvmRelayRequest,
    W5InitData,
)
from x402.schemas import (
    PaymentPayload,
    PaymentRequirements,
    ResourceInfo,
    VerifyResponse,
)

PAYER = "0:" + "1" * 64
MERCHANT = "0:" + "2" * 64
ASSET = "0:" + "3" * 64
SOURCE_WALLET_1 = "0:" + "4" * 64
SOURCE_WALLET_2 = "0:" + "5" * 64
RECEIVER_WALLET = "0:" + "6" * 64
RESPONSE_DESTINATION = "0:" + "7" * 64
EMPTY_FORWARD_PAYLOAD = begin_cell().store_bit(0).end_cell()
EMPTY_FORWARD_PAYLOAD_B64 = base64.b64encode(EMPTY_FORWARD_PAYLOAD.to_boc()).decode("ascii")
PAYER_TX_HASH_1 = "a" * 64
PAYER_TX_HASH_2 = "b" * 64


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


class _VerificationSigner:
    def __init__(self, emulation_trace: dict[str, object]) -> None:
        self.emulation_trace = emulation_trace

    def get_addresses(self) -> list[str]:
        return ["0:" + "f" * 64]

    def get_account_state(self, address: str, network: str) -> TvmAccountState:
        _ = network
        return TvmAccountState(
            address=address,
            balance=0,
            is_active=True,
            is_uninitialized=False,
            state_init=None,
        )

    def get_jetton_wallet(self, asset: str, owner: str, network: str) -> str:
        _ = asset, network
        if owner == PAYER:
            return SOURCE_WALLET_1
        if owner == MERCHANT:
            return RECEIVER_WALLET
        raise AssertionError(f"Unexpected owner {owner}")

    def get_jetton_wallet_data(self, address: str, network: str) -> TvmJettonWalletData:
        _ = network
        return TvmJettonWalletData(
            address=address,
            balance=1_000_000_000,
            owner=PAYER,
            jetton_minter=ASSET,
        )

    def build_relay_external_boc(
        self,
        network: str,
        relay_request: TvmRelayRequest,
        *,
        for_emulation: bool = False,
    ) -> bytes:
        _ = network, relay_request, for_emulation
        return b"external-boc"

    def emulate_external_message(self, network: str, external_boc: bytes) -> dict[str, object]:
        _ = network, external_boc
        return self.emulation_trace


class _PayloadSignerStub:
    def __init__(self) -> None:
        self._wallet_id = 1
        self._state_init = build_w5r1_state_init(b"\x11" * 32, self._wallet_id)
        self._address = address_from_state_init(self._state_init, 0)

    @property
    def address(self) -> str:
        return self._address

    @property
    def network(self) -> str:
        return TVM_TESTNET

    @property
    def wallet_id(self) -> int:
        return self._wallet_id

    @property
    def state_init(self):
        return self._state_init

    def sign_message(self, message: bytes) -> bytes:
        _ = message
        return b"\x00" * 64


class _PayloadClientStub:
    def get_account_state(self, address: str) -> TvmAccountState:
        return TvmAccountState(
            address=address,
            balance=0,
            is_active=False,
            is_uninitialized=True,
            state_init=None,
        )

    def get_jetton_wallet(self, asset: str, owner: str) -> str:
        _ = asset
        return SOURCE_WALLET_1 if owner == _PayloadSignerStub().address else RECEIVER_WALLET

    def get_jetton_wallet_data(self, address: str) -> TvmJettonWalletData:
        return TvmJettonWalletData(
            address=address,
            balance=0,
            owner=_PayloadSignerStub().address if address == SOURCE_WALLET_1 else MERCHANT,
            jetton_minter=ASSET,
        )

    def emulate_trace(self, boc: bytes) -> dict[str, object]:
        _ = boc
        return {
            "transactions": {
                "source": {
                    "account": SOURCE_WALLET_1,
                    "account_state_before": {"balance": "1000000"},
                    "description": {
                        "aborted": False,
                        "action": {"success": True},
                        "compute_ph": {
                            "success": True,
                            "skipped": False,
                            "gas_fees": "300000",
                        },
                        "storage_ph": {
                            "storage_fees_collected": "500000",
                        },
                    },
                    "in_msg": {
                        "hash": "payer-out-hash",
                        "hash_norm": "payer-out-hash",
                        "source": _PayloadSignerStub().address,
                        "destination": SOURCE_WALLET_1,
                        "decoded_opcode": "jetton_transfer",
                    },
                    "out_msgs": [
                        {
                            "hash": "source-out-hash",
                            "hash_norm": "source-out-hash",
                            "fwd_fee": "200000",
                            "source": SOURCE_WALLET_1,
                            "destination": RECEIVER_WALLET,
                            "decoded_opcode": "jetton_internal_transfer",
                            "message_content": {
                                "decoded": {
                                    "@type": "jetton_internal_transfer",
                                }
                            },
                        }
                    ],
                },
                "receiver": {
                    "account": RECEIVER_WALLET,
                    "description": {
                        "aborted": False,
                        "action": {"success": True},
                        "compute_ph": {
                            "success": True,
                            "skipped": False,
                            "gas_fees": "400000",
                        },
                    },
                    "in_msg": {
                        "hash": "source-out-hash",
                        "hash_norm": "source-out-hash",
                        "source": SOURCE_WALLET_1,
                        "destination": RECEIVER_WALLET,
                        "decoded_opcode": "jetton_internal_transfer",
                    },
                },
            }
        }


def _make_emulation_trace(
    *,
    settlement: ParsedTvmSettlement,
    receiver_wallet: str = RECEIVER_WALLET,
    payer_compute_fee: int = 700_000,
    payer_storage_fee: int = 600_000,
    payer_fwd_fees: list[int] | None = None,
    source_wallet_balance: int = 1_000_000,
    source_wallet_fwd_fees: list[int] | None = None,
    source_wallet_compute_fee: int = 300_000,
    source_wallet_storage_fee: int = 500_000,
    receiver_wallet_compute_fee: int = 400_000,
) -> dict[str, object]:
    payer_out_hash = "payer-out-hash"
    source_out_hashes = [f"source-out-hash-{idx}" for idx in range(3)]
    payer_fees = payer_fwd_fees or [800_000]
    source_fees = source_wallet_fwd_fees or [200_000]
    out_msgs = [
        {
            "hash": payer_out_hash,
            "hash_norm": payer_out_hash,
            "destination": settlement.transfer.source_wallet,
            "message_content": {
                "hash": _hash_string(settlement.transfer.body_hash or b""),
            },
            "fwd_fee": str(fee),
        }
        for fee in payer_fees
    ]

    source_out_msgs = [
        {
            "hash": source_out_hashes[idx],
            "hash_norm": source_out_hashes[idx],
            "fwd_fee": str(fee),
        }
        for idx, fee in enumerate(source_fees)
    ]
    return {
        "transactions": {
            "payer-wallet-tx": {
                "hash": PAYER_TX_HASH_1,
                "account": PAYER,
                "description": {
                    "aborted": False,
                    "action": {"success": True},
                    "compute_ph": {
                        "success": True,
                        "skipped": False,
                        "gas_fees": str(payer_compute_fee),
                    },
                    "storage_ph": {
                        "storage_fees_collected": str(payer_storage_fee),
                    },
                },
                "in_msg": {
                    "message_content": {
                        "hash": _hash_string(settlement.body.hash),
                    },
                },
                "out_msgs": out_msgs,
            },
            "source-wallet-tx": {
                "hash": "source-wallet-tx",
                "account": settlement.transfer.source_wallet,
                "account_state_before": {"balance": str(source_wallet_balance)},
                "description": {
                    "aborted": False,
                    "action": {"success": True},
                    "compute_ph": {
                        "success": True,
                        "skipped": False,
                        "gas_fees": str(source_wallet_compute_fee),
                    },
                    "storage_ph": {
                        "storage_fees_collected": str(source_wallet_storage_fee),
                    },
                },
                "in_msg": {"hash": payer_out_hash, "hash_norm": payer_out_hash},
                "out_msgs": source_out_msgs,
            },
            "receiver-wallet-tx": {
                "hash": "receiver-wallet-tx",
                "account": receiver_wallet,
                "description": {
                    "aborted": False,
                    "action": {"success": True},
                    "compute_ph": {
                        "success": True,
                        "skipped": False,
                        "gas_fees": str(receiver_wallet_compute_fee),
                    },
                },
                "in_msg": {
                    "hash": source_out_hashes[0],
                    "hash_norm": source_out_hashes[0],
                },
            },
        }
    }


def _make_real_settlement_boc_with_mode(mode: int) -> str:
    client_scheme = ExactTvmClientScheme(_PayloadSignerStub())
    client_scheme._get_client = lambda network: _PayloadClientStub()  # type: ignore[method-assign]

    payload = client_scheme.create_payment_payload(
        PaymentRequirements(
            scheme="exact",
            network=TVM_TESTNET,
            asset=ASSET,
            amount="100",
            pay_to=MERCHANT,
            max_timeout_seconds=300,
            extra={"areFeesSponsored": True},
        )
    )

    message = MessageAny.deserialize(
        Cell.one_from_boc(base64.b64decode(payload["settlementBoc"])).begin_parse()
    )
    body_slice = message.body.begin_parse()
    opcode = body_slice.load_uint(32)
    wallet_id = body_slice.load_uint(32)
    valid_until = body_slice.load_uint(32)
    seqno = body_slice.load_uint(32)
    has_actions = body_slice.load_bit()
    actions = parse_out_list(body_slice.load_ref()) if has_actions else []
    has_extra_actions = body_slice.load_bit()
    signature = body_slice.load_bytes(64)

    assert opcode == W5_INTERNAL_SIGNED_OPCODE
    assert len(actions) == 1

    mutated_actions = serialize_out_list(
        [serialize_send_msg_action(actions[0].out_msg.serialize(), mode=mode)]
    )
    mutated_body = (
        begin_cell()
        .store_uint(opcode, 32)
        .store_uint(wallet_id, 32)
        .store_uint(valid_until, 32)
        .store_uint(seqno, 32)
        .store_maybe_ref(mutated_actions)
        .store_bit(has_extra_actions)
        .store_bytes(signature)
        .end_cell()
    )
    mutated_message = Contract.create_internal_msg(
        src=None,
        dest=Address(_PayloadSignerStub().address),
        bounce=True,
        value=0,
        state_init=message.init,
        body=mutated_body,
    )
    return base64.b64encode(mutated_message.serialize().to_boc()).decode("utf-8")


def _make_requirements(
    *, amount: str, response_destination: str | None = None
) -> PaymentRequirements:
    extra = {
        "areFeesSponsored": True,
        "forwardPayload": EMPTY_FORWARD_PAYLOAD_B64,
        "forwardTonAmount": "0",
    }
    if response_destination is not None:
        extra["responseDestination"] = response_destination

    return PaymentRequirements(
        scheme="exact",
        network=TVM_TESTNET,
        asset=ASSET,
        amount=amount,
        pay_to=MERCHANT,
        max_timeout_seconds=300,
        extra=extra,
    )


def _make_payload(
    settlement_boc: str, *, amount: str, response_destination: str | None = None
) -> PaymentPayload:
    return PaymentPayload(
        x402_version=2,
        resource=ResourceInfo(
            url="https://example.com/protected",
            description="test",
            mime_type="application/json",
        ),
        accepted=_make_requirements(amount=amount, response_destination=response_destination),
        payload={
            "settlementBoc": settlement_boc,
            "asset": ASSET,
        },
    )


def _make_settlement(
    *, settlement_hash: str, source_wallet: str, amount: int, attached_ton_amount: int = 0
) -> ParsedTvmSettlement:
    body_hash = f"{settlement_hash}-body".encode("ascii")
    transfer_body_hash = f"{settlement_hash}-transfer".encode("ascii")
    return ParsedTvmSettlement(
        payer=PAYER,
        wallet_id=1,
        valid_until=int(time.time()) + 60,
        seqno=1,
        settlement_hash=settlement_hash,
        body=FakeCell(body_hash),  # type: ignore[arg-type]
        signed_slice_hash=b"",
        signature=b"",
        state_init=None,
        transfer=ParsedJettonTransfer(
            source_wallet=source_wallet,
            destination=MERCHANT,
            response_destination=None,
            jetton_amount=amount,
            attached_ton_amount=attached_ton_amount,
            forward_ton_amount=0,
            forward_payload=EMPTY_FORWARD_PAYLOAD,
            body_hash=transfer_body_hash,
        ),
    )


def _hash_string(raw_hash: bytes) -> str:
    return base64.b64encode(raw_hash).decode("ascii")


def _make_finalized_trace(
    *,
    settlement: ParsedTvmSettlement,
    payer_tx_hash: str = PAYER_TX_HASH_1,
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
            "hash": payer_tx_hash,
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


def _patch_scheme_verification(
    monkeypatch, scheme: ExactTvmScheme, settlements: dict[str, ParsedTvmSettlement]
) -> None:
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


def _patch_live_verification_dependencies(
    monkeypatch,
    settlement: ParsedTvmSettlement,
) -> None:
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


def test_settle_succeeds_when_finalized_trace_contains_matching_jetton_transfer(
    monkeypatch,
):
    settlement = _make_settlement(
        settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100
    )
    signer = MockSigner(_make_finalized_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_scheme_verification(monkeypatch, scheme, {"boc-1": settlement})

    response = scheme.settle(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.success is True
    assert response.transaction == PAYER_TX_HASH_1
    assert response.error_reason is None


def test_settle_succeeds_when_finalized_trace_has_no_actions_but_transaction_chain_matches(
    monkeypatch,
):
    settlement = _make_settlement(
        settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100
    )
    signer = MockSigner(_make_finalized_trace(settlement=settlement, include_action=False))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_scheme_verification(monkeypatch, scheme, {"boc-1": settlement})

    response = scheme.settle(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.success is True
    assert response.transaction == PAYER_TX_HASH_1
    assert response.error_reason is None


def test_settle_fails_when_finalized_trace_has_no_matching_source_wallet_transaction(
    monkeypatch,
):
    settlement = _make_settlement(
        settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100
    )
    signer = MockSigner(
        _make_finalized_trace(settlement=settlement, include_source_wallet_tx=False)
    )
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_scheme_verification(monkeypatch, scheme, {"boc-1": settlement})

    response = scheme.settle(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.success is False
    assert response.transaction == ""
    assert response.error_reason == "transaction_failed"
    assert "source jetton wallet transaction" in (response.error_message or "")


def test_settle_batch_marks_each_settlement_individually(monkeypatch):
    settlement_1 = _make_settlement(
        settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100
    )
    settlement_2 = _make_settlement(
        settlement_hash="settlement-2", source_wallet=SOURCE_WALLET_2, amount=200
    )
    finalized_trace = _make_finalized_trace(settlement=settlement_1, payer_tx_hash=PAYER_TX_HASH_1)
    finalized_trace["transactions"]["payer-wallet-tx-2"] = {
        **finalized_trace["transactions"]["payer-wallet-tx"],
        "hash": PAYER_TX_HASH_2,
        "out_msgs": [
            {
                **finalized_trace["transactions"]["payer-wallet-tx"]["out_msgs"][0],
                "destination": settlement_2.transfer.source_wallet,
                "message_content": {
                    "hash": _hash_string(settlement_2.transfer.body_hash or b""),
                },
            }
        ],
        "in_msg": {
            "message_content": {
                "hash": _hash_string(settlement_2.body.hash),
            },
        },
    }
    finalized_trace["transactions"]["source-wallet-tx-2"] = {
        "hash": "source-wallet-tx-2",
        "account": settlement_2.transfer.source_wallet,
        "description": {
            "aborted": False,
            "action": {"success": True},
            "compute_ph": {"success": True, "skipped": False},
        },
        "in_msg": {
            "hash": _hash_string(b"source-wallet-tx-2-in"),
            "hash_norm": _hash_string(b"source-wallet-tx-2-in"),
        },
    }
    finalized_trace["transactions"]["payer-wallet-tx-2"]["out_msgs"][0]["hash"] = _hash_string(
        b"source-wallet-tx-2-in"
    )
    finalized_trace["transactions"]["payer-wallet-tx-2"]["out_msgs"][0]["hash_norm"] = _hash_string(
        b"source-wallet-tx-2-in"
    )
    signer = MockSigner(finalized_trace)
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
        results[name] = scheme.settle(
            _make_payload(settlement_boc, amount=amount),
            _make_requirements(amount=amount),
        )

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
    assert first.transaction == PAYER_TX_HASH_1
    assert second.success is True
    assert second.transaction == PAYER_TX_HASH_2
    assert second.error_reason is None


def test_settle_batch_matches_exact_settlement_transaction_chain(monkeypatch):
    settlement_1 = _make_settlement(
        settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100
    )
    settlement_2 = _make_settlement(
        settlement_hash="settlement-2", source_wallet=SOURCE_WALLET_1, amount=100
    )
    signer = MockSigner(
        _make_finalized_trace(settlement=settlement_1, source_wallet_tx_hash="source-wallet-tx-1")
    )
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
        results[name] = scheme.settle(
            _make_payload(settlement_boc, amount="100"),
            _make_requirements(amount="100"),
        )

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
    assert first.transaction == PAYER_TX_HASH_1
    assert second.success is False
    assert second.transaction == ""
    assert second.error_reason == "transaction_failed"
    assert "payer wallet transaction" in (second.error_message or "")


def test_verify_accepts_exact_dynamic_inner_value(monkeypatch):
    settlement = _make_settlement(
        settlement_hash="settlement-dynamic",
        source_wallet=SOURCE_WALLET_1,
        amount=100,
        attached_ton_amount=7_500_000,
    )
    signer = _VerificationSigner(_make_emulation_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_live_verification_dependencies(monkeypatch, settlement)

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is True


def test_verify_uses_signed_inner_value_when_computing_outer_amount(monkeypatch):
    settlement = _make_settlement(
        settlement_hash="settlement-tolerance",
        source_wallet=SOURCE_WALLET_1,
        amount=100,
        attached_ton_amount=8_500_000,
    )
    signer = _VerificationSigner(_make_emulation_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_live_verification_dependencies(monkeypatch, settlement)

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is True


def test_verify_does_not_reject_lower_signed_inner_value_when_emulation_succeeds(monkeypatch):
    settlement = _make_settlement(
        settlement_hash="settlement-underfunded",
        source_wallet=SOURCE_WALLET_1,
        amount=100,
        attached_ton_amount=7_499_999,
    )
    signer = _VerificationSigner(_make_emulation_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_live_verification_dependencies(monkeypatch, settlement)

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is True


def test_verify_does_not_reject_higher_signed_inner_value_when_emulation_succeeds(monkeypatch):
    settlement = _make_settlement(
        settlement_hash="settlement-overpay",
        source_wallet=SOURCE_WALLET_1,
        amount=100,
        attached_ton_amount=8_500_001,
    )
    signer = _VerificationSigner(_make_emulation_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_live_verification_dependencies(monkeypatch, settlement)

    response = scheme.verify(_make_payload("boc-1", amount="100"), _make_requirements(amount="100"))

    assert response.is_valid is True


def test_settle_recomputes_relay_request_on_each_call(monkeypatch):
    settlement = _make_settlement(
        settlement_hash="settlement-reverify",
        source_wallet=SOURCE_WALLET_1,
        amount=100,
    )
    signer = MockSigner(_make_finalized_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: settlement,
    )

    verify_calls = {"count": 0}

    def _fake_verify(payload, requirements, tvm_payload, parsed_settlement):
        verify_calls["count"] += 1
        return (
            VerifyResponse(is_valid=True, payer=parsed_settlement.payer),
            TvmRelayRequest(
                destination=parsed_settlement.payer,
                body=None,  # type: ignore[arg-type]
                state_init=None,
                relay_amount=222_222_222,
            ),
        )

    monkeypatch.setattr(scheme, "_verify", _fake_verify)
    assert scheme.verify(
        _make_payload("boc-1", amount="100"), _make_requirements(amount="100")
    ).is_valid

    settle_response = scheme.settle(
        _make_payload("boc-1", amount="100"),
        _make_requirements(amount="100"),
    )

    assert settle_response.success is True
    assert verify_calls["count"] == 2


def test_settle_batch_uses_cached_exact_outer_values(monkeypatch):
    settlement_1 = _make_settlement(
        settlement_hash="settlement-exact-1",
        source_wallet=SOURCE_WALLET_1,
        amount=100,
    )
    settlement_2 = _make_settlement(
        settlement_hash="settlement-exact-2",
        source_wallet=SOURCE_WALLET_2,
        amount=200,
    )
    finalized_trace = _make_finalized_trace(settlement=settlement_1, payer_tx_hash=PAYER_TX_HASH_1)
    finalized_trace["transactions"]["payer-wallet-tx-2"] = {
        **finalized_trace["transactions"]["payer-wallet-tx"],
        "hash": PAYER_TX_HASH_2,
        "out_msgs": [
            {
                **finalized_trace["transactions"]["payer-wallet-tx"]["out_msgs"][0],
                "destination": settlement_2.transfer.source_wallet,
                "message_content": {
                    "hash": _hash_string(settlement_2.transfer.body_hash or b""),
                },
            }
        ],
        "in_msg": {
            "message_content": {
                "hash": _hash_string(settlement_2.body.hash),
            },
        },
    }
    finalized_trace["transactions"]["source-wallet-tx-2"] = {
        "hash": "source-wallet-tx-2",
        "account": settlement_2.transfer.source_wallet,
        "description": {
            "aborted": False,
            "action": {"success": True},
            "compute_ph": {"success": True, "skipped": False},
        },
        "in_msg": {
            "hash": _hash_string(b"source-wallet-tx-2-in"),
            "hash_norm": _hash_string(b"source-wallet-tx-2-in"),
        },
    }
    finalized_trace["transactions"]["payer-wallet-tx-2"]["out_msgs"][0]["hash"] = _hash_string(
        b"source-wallet-tx-2-in"
    )
    finalized_trace["transactions"]["payer-wallet-tx-2"]["out_msgs"][0]["hash_norm"] = _hash_string(
        b"source-wallet-tx-2-in"
    )
    signer = MockSigner(finalized_trace)
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=1.0, batch_max_size=2)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: {"boc-1": settlement_1, "boc-2": settlement_2}[settlement_boc],
    )

    relay_requests = {
        "boc-1": TvmRelayRequest(
            destination=settlement_1.payer,
            body=None,  # type: ignore[arg-type]
            state_init=None,
            relay_amount=111_111_111,
        ),
        "boc-2": TvmRelayRequest(
            destination=settlement_2.payer,
            body=None,  # type: ignore[arg-type]
            state_init=None,
            relay_amount=222_222_222,
        ),
    }

    monkeypatch.setattr(
        scheme,
        "_verify",
        lambda payload, requirements, tvm_payload, settlement: (
            VerifyResponse(is_valid=True, payer=settlement.payer),
            relay_requests[tvm_payload.settlement_boc],
        ),
    )

    results: dict[str, object] = {}

    def settle(name: str, settlement_boc: str, amount: str) -> None:
        results[name] = scheme.settle(
            _make_payload(settlement_boc, amount=amount),
            _make_requirements(amount=amount),
        )

    thread_1 = threading.Thread(target=settle, args=("first", "boc-1", "100"))
    thread_2 = threading.Thread(target=settle, args=("second", "boc-2", "200"))
    thread_1.start()
    thread_2.start()
    thread_1.join(timeout=2.0)
    thread_2.join(timeout=2.0)

    assert results["first"].success is True
    assert results["second"].success is True
    assert sorted(request.relay_amount for request in signer.sent_batches[0]) == [
        111_111_111,
        222_222_222,
    ]


def test_settle_returns_structured_error_for_invalid_payload(monkeypatch):
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: (_ for _ in ()).throw(ValueError(ERR_INVALID_SETTLEMENT_BOC)),
    )

    response = scheme.settle(
        _make_payload("bad-boc", amount="100"), _make_requirements(amount="100")
    )

    assert response.success is False
    assert response.error_reason == ERR_INVALID_SETTLEMENT_BOC
    assert response.transaction == ""
    assert response.payer == ""


def test_verify_rejects_internal_signed_message_with_non_fee_separate_mode():
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)

    response = scheme.verify(
        _make_payload(_make_real_settlement_boc_with_mode(0), amount="100"),
        _make_requirements(amount="100"),
    )

    assert response.is_valid is False
    assert response.invalid_reason == ERR_INVALID_W5_ACTIONS


def test_verify_rejects_forward_ton_amount_above_one(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100),
        transfer=replace(
            _make_settlement(
                settlement_hash="settlement-1",
                source_wallet=SOURCE_WALLET_1,
                amount=100,
            ).transfer,
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
            _make_settlement(
                settlement_hash="settlement-1",
                source_wallet=SOURCE_WALLET_1,
                amount=100,
            ).transfer,
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


def test_verify_accepts_matching_response_destination(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100),
        transfer=replace(
            _make_settlement(
                settlement_hash="settlement-1",
                source_wallet=SOURCE_WALLET_1,
                amount=100,
            ).transfer,
            response_destination=RESPONSE_DESTINATION,
        ),
    )
    signer = _VerificationSigner(_make_emulation_trace(settlement=settlement))
    scheme = ExactTvmScheme(signer, batch_flush_interval_seconds=0.0, batch_max_size=1)
    _patch_live_verification_dependencies(monkeypatch, settlement)

    response = scheme.verify(
        _make_payload("boc-1", amount="100", response_destination=RESPONSE_DESTINATION),
        _make_requirements(amount="100", response_destination=RESPONSE_DESTINATION),
    )

    assert response.is_valid is True


def test_verify_rejects_mismatched_payload_response_destination(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100),
        transfer=replace(
            _make_settlement(
                settlement_hash="settlement-1",
                source_wallet=SOURCE_WALLET_1,
                amount=100,
            ).transfer,
            response_destination=RESPONSE_DESTINATION,
        ),
    )
    scheme = ExactTvmScheme(MockSigner({}), batch_flush_interval_seconds=0.0, batch_max_size=1)
    monkeypatch.setattr(
        "x402.mechanisms.tvm.exact.facilitator.parse_exact_tvm_payload",
        lambda settlement_boc: settlement,
    )

    response = scheme.verify(
        _make_payload("boc-1", amount="100", response_destination=RESPONSE_DESTINATION),
        _make_requirements(amount="100"),
    )

    assert response.is_valid is False
    assert response.invalid_reason == ERR_INVALID_JETTON_TRANSFER


def test_verify_rejects_mismatched_forward_ton_amount(monkeypatch):
    settlement = replace(
        _make_settlement(settlement_hash="settlement-1", source_wallet=SOURCE_WALLET_1, amount=100),
        transfer=replace(
            _make_settlement(
                settlement_hash="settlement-1",
                source_wallet=SOURCE_WALLET_1,
                amount=100,
            ).transfer,
            forward_ton_amount=1,
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
