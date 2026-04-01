"""Tests for TVM exact client payload construction."""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("pytoniq_core")

from pytoniq_core import Cell, begin_cell
from pytoniq_core.tlb.transaction import MessageAny

from x402.mechanisms.tvm import (
    TVM_TESTNET,
    address_from_state_init,
    build_w5r1_state_init,
    normalize_address,
    parse_exact_tvm_payload,
)
from x402.mechanisms.tvm.codecs.w5 import parse_out_list
from x402.mechanisms.tvm.constants import (
    SEND_MODE_PAY_FEES_SEPARATELY,
    W5_INTERNAL_SIGNED_OPCODE,
)
from x402.mechanisms.tvm.exact.client import ExactTvmScheme
from x402.mechanisms.tvm.types import TvmAccountState, TvmJettonWalletData
from x402.schemas import PaymentRequirements

MERCHANT = "0:" + "2" * 64
ASSET = "0:" + "3" * 64
SOURCE_WALLET = "0:" + "4" * 64
RECEIVER_WALLET = "0:" + "5" * 64
RESPONSE_DESTINATION = "0:" + "6" * 64
EMPTY_FORWARD_PAYLOAD = begin_cell().store_bit(0).end_cell()


class _SignerStub:
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


class _ClientStub:
    def __init__(
        self,
        *,
        source_wallet_balance: int = 0,
        source_wallet_fwd_fees: list[int] | None = None,
        source_wallet_compute_fee: int = 0,
        receiver_wallet_compute_fee: int = 0,
        source_wallet_storage_fee: int = 0,
        emulate_error: Exception | None = None,
    ) -> None:
        self._source_wallet_balance = source_wallet_balance
        self._source_wallet_fwd_fees = source_wallet_fwd_fees or [0]
        self._source_wallet_compute_fee = source_wallet_compute_fee
        self._receiver_wallet_compute_fee = receiver_wallet_compute_fee
        self._source_wallet_storage_fee = source_wallet_storage_fee
        self._emulate_error = emulate_error

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
        return SOURCE_WALLET if owner == _SignerStub().address else RECEIVER_WALLET

    def get_jetton_wallet_data(self, address: str) -> TvmJettonWalletData:
        return TvmJettonWalletData(
            address=address,
            balance=0,
            owner=_SignerStub().address if address == SOURCE_WALLET else MERCHANT,
            jetton_minter=ASSET,
        )

    def emulate_trace(self, boc: bytes) -> dict[str, object]:
        if self._emulate_error is not None:
            raise self._emulate_error

        _ = boc
        payer_out_hash = "payer-out-hash"
        source_out_hash = "source-out-hash"
        out_msgs = [
            {
                "hash": source_out_hash,
                "hash_norm": source_out_hash,
                "fwd_fee": str(fee),
                "source": SOURCE_WALLET,
                "destination": RECEIVER_WALLET,
                "decoded_opcode": "jetton_internal_transfer",
                "message_content": {
                    "decoded": {
                        "@type": "jetton_internal_transfer",
                    }
                },
            }
            for fee in self._source_wallet_fwd_fees
        ]
        return {
            "transactions": {
                "payer": {
                    "account": _SignerStub().address,
                    "description": {
                        "aborted": False,
                        "action": {"success": True},
                        "compute_ph": {"success": True, "skipped": False},
                    },
                    "in_msg": {"decoded_opcode": "w5_external_signed_request"},
                    "out_msgs": [
                        {
                            "hash": payer_out_hash,
                            "hash_norm": payer_out_hash,
                        }
                    ],
                },
                "source": {
                    "account": SOURCE_WALLET,
                    "account_state_before": {"balance": str(self._source_wallet_balance)},
                    "description": {
                        "aborted": False,
                        "action": {"success": True},
                        "compute_ph": {
                            "success": True,
                            "skipped": False,
                            "gas_fees": str(self._source_wallet_compute_fee),
                        },
                        "storage_ph": {
                            "storage_fees_collected": str(self._source_wallet_storage_fee)
                        },
                    },
                    "in_msg": {
                        "hash": payer_out_hash,
                        "hash_norm": payer_out_hash,
                        "source": _SignerStub().address,
                        "destination": SOURCE_WALLET,
                        "decoded_opcode": "jetton_transfer",
                    },
                    "out_msgs": out_msgs,
                },
                "receiver": {
                    "account": RECEIVER_WALLET,
                    "description": {
                        "aborted": False,
                        "action": {"success": True},
                        "compute_ph": {
                            "success": True,
                            "skipped": False,
                            "gas_fees": str(self._receiver_wallet_compute_fee),
                        },
                    },
                    "in_msg": {
                        "hash": source_out_hash,
                        "hash_norm": source_out_hash,
                        "source": SOURCE_WALLET,
                        "destination": RECEIVER_WALLET,
                        "decoded_opcode": "jetton_internal_transfer",
                    },
                },
            }
        }


def _extract_single_w5_send_action(settlement_boc: str):
    message = MessageAny.deserialize(
        Cell.one_from_boc(base64.b64decode(settlement_boc)).begin_parse()
    )
    body_slice = message.body.begin_parse()
    assert body_slice.load_uint(32) == W5_INTERNAL_SIGNED_OPCODE
    body_slice.load_uint(32)
    body_slice.load_uint(32)
    body_slice.load_uint(32)
    assert body_slice.load_bit() == 1
    actions = parse_out_list(body_slice.load_ref())
    assert len(actions) == 1
    return actions[0]


def test_create_payment_payload_uses_requirements_forward_settings(monkeypatch):
    scheme = ExactTvmScheme(_SignerStub())
    monkeypatch.setattr(
        scheme,
        "_get_client",
        lambda network: _ClientStub(
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[200_000, 250_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        ),
    )
    forward_payload = begin_cell().store_uint(0xABCD, 16).end_cell()

    payload = scheme.create_payment_payload(
        PaymentRequirements(
            scheme="exact",
            network=TVM_TESTNET,
            asset=ASSET,
            amount="100",
            pay_to=MERCHANT,
            max_timeout_seconds=300,
            extra={
                "areFeesSponsored": True,
                "responseDestination": RESPONSE_DESTINATION,
                "forwardTonAmount": "50000000",
                "forwardPayload": base64.b64encode(forward_payload.to_boc()).decode("ascii"),
            },
        )
    )
    settlement = parse_exact_tvm_payload(payload["settlementBoc"])

    assert settlement.transfer.response_destination == RESPONSE_DESTINATION
    assert settlement.transfer.attached_ton_amount == 57_750_000
    assert settlement.transfer.forward_ton_amount == 50_000_000
    assert settlement.transfer.forward_payload.hash == forward_payload.hash


def test_create_payment_payload_uses_empty_forward_payload_defaults(monkeypatch):
    scheme = ExactTvmScheme(_SignerStub())
    monkeypatch.setattr(
        scheme,
        "_get_client",
        lambda network: _ClientStub(
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[200_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        ),
    )

    payload = scheme.create_payment_payload(
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
    settlement = parse_exact_tvm_payload(payload["settlementBoc"])

    assert settlement.transfer.response_destination is None
    assert settlement.transfer.attached_ton_amount == 7_500_000
    assert settlement.transfer.forward_ton_amount == 0
    assert settlement.transfer.forward_payload.hash == EMPTY_FORWARD_PAYLOAD.hash


def test_create_payment_payload_clamps_required_inner_value_to_forward_fee_floor(monkeypatch):
    scheme = ExactTvmScheme(_SignerStub())
    monkeypatch.setattr(
        scheme,
        "_get_client",
        lambda network: _ClientStub(
            source_wallet_balance=50_000_000,
            source_wallet_fwd_fees=[200_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        ),
    )

    payload = scheme.create_payment_payload(
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
    settlement = parse_exact_tvm_payload(payload["settlementBoc"])

    assert settlement.transfer.attached_ton_amount == 400_000


def test_create_payment_payload_sets_send_mode_1_for_w5_to_jetton_wallet_message(monkeypatch):
    scheme = ExactTvmScheme(_SignerStub())
    monkeypatch.setattr(
        scheme,
        "_get_client",
        lambda network: _ClientStub(
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[200_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        ),
    )

    payload = scheme.create_payment_payload(
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
    action = _extract_single_w5_send_action(payload["settlementBoc"])

    assert action.mode == SEND_MODE_PAY_FEES_SEPARATELY
    assert normalize_address(action.out_msg.info.dest) == SOURCE_WALLET


def test_create_payment_payload_propagates_emulation_failure(monkeypatch):
    scheme = ExactTvmScheme(_SignerStub())
    monkeypatch.setattr(
        scheme,
        "_get_client",
        lambda network: _ClientStub(emulate_error=RuntimeError("emulation exploded")),
    )

    with pytest.raises(RuntimeError, match="emulation exploded"):
        scheme.create_payment_payload(
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
