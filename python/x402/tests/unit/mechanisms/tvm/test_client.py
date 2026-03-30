"""Tests for TVM exact client payload construction."""

from __future__ import annotations

import pytest

pytest.importorskip("pytoniq_core")

from x402.mechanisms.tvm import (
    TVM_TESTNET,
    address_from_state_init,
    build_w5r1_state_init,
    parse_exact_tvm_payload,
)
from x402.mechanisms.tvm.exact.client import ExactTvmScheme
from x402.mechanisms.tvm.types import TvmAccountState
from x402.schemas import PaymentRequirements

MERCHANT = "0:" + "2" * 64
ASSET = "0:" + "3" * 64
SOURCE_WALLET = "0:" + "4" * 64


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
    def get_account_state(self, address: str) -> TvmAccountState:
        return TvmAccountState(
            address=address,
            balance=0,
            is_active=False,
            is_uninitialized=True,
            state_init=None,
        )

    def get_jetton_wallet(self, asset: str, owner: str) -> str:
        _ = asset, owner
        return SOURCE_WALLET


def test_create_payment_payload_uses_zero_forward_ton_amount(monkeypatch):
    scheme = ExactTvmScheme(_SignerStub())
    monkeypatch.setattr(scheme, "_get_client", lambda network: _ClientStub())

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

    assert settlement.transfer.response_destination == MERCHANT
    assert settlement.transfer.forward_ton_amount == 1
