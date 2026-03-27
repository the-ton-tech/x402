"""Unit tests for the TVM exact facilitator."""

from __future__ import annotations

import base64
import time
from types import SimpleNamespace

from nacl.bindings import crypto_sign_seed_keypair
from pytoniq.contract.contract import Contract
from pytoniq_core import Address, Cell, begin_cell
from pytoniq_core.crypto.signature import sign_message
from pytoniq_core.tlb.account import StateInit

from x402.mechanisms.tvm.constants import (
    ERR_DUPLICATE_SETTLEMENT,
    ERR_INVALID_RECIPIENT,
    ERR_SIMULATION_FAILED,
    ERR_STATE_INIT_NOT_SUPPORTED,
    JETTON_TRANSFER_OPCODE,
    TVM_MAINNET,
    W5_INTERNAL_SIGNED_OPCODE,
)
from x402.mechanisms.tvm.exact.facilitator import ExactTvmScheme
from x402.mechanisms.tvm.types import TvmJettonWalletData
from x402.mechanisms.tvm.utils import build_w5r1_state_init
from x402.schemas import PaymentPayload, PaymentRequirements

SOURCE_JETTON_WALLET = "0:" + "22" * 32
JETTON_MASTER = "0:" + "33" * 32
RECIPIENT = "0:" + "44" * 32
FACILITATOR = "0:" + "55" * 32
MERCHANT_JETTON_WALLET = "0:" + "66" * 32
TEST_PUBLIC_KEY, TEST_SECRET_KEY = crypto_sign_seed_keypair(b"\x01" * 32)
WALLET_PUBLIC_KEY = TEST_PUBLIC_KEY
WALLET_ID = 77


class FakeSigner:
    def __init__(
        self,
        *,
        is_active: bool = True,
        merchant_wallet_tx_success: bool = True,
        include_merchant_wallet_tx: bool = True,
    ) -> None:
        self._is_active = is_active
        self._merchant_wallet_tx_success = merchant_wallet_tx_success
        self._include_merchant_wallet_tx = include_merchant_wallet_tx
        self.built: list[tuple[str, str, StateInit | None]] = []
        self.sent: list[tuple[str, bytes]] = []

    def get_addresses(self) -> list[str]:
        return [FACILITATOR]

    def get_account_state(self, address: str, network: str):
        _ = address, network
        return SimpleNamespace(
            address=PAYER,
            is_active=self._is_active,
            is_uninitialized=not self._is_active,
            state_init=_wallet_state_init() if self._is_active else None,
        )

    def get_jetton_wallet_data(self, address: str, network: str) -> TvmJettonWalletData:
        _ = network
        return TvmJettonWalletData(
            address=address,
            balance=2_000_000,
            owner=PAYER,
            jetton_minter=JETTON_MASTER,
            wallet_code=Cell.empty(),
        )

    def build_relay_external_boc(
        self,
        network: str,
        destination: str,
        body: Cell,
        state_init: StateInit | None,
    ) -> bytes:
        _ = body
        self.built.append((network, destination, state_init))
        if state_init is not None:
            raise RuntimeError("state_init is not supported")
        return b"external-boc"

    def emulate_external_message(self, network: str, external_boc: bytes):
        _ = network, external_boc
        return _emulate_trace(
            merchant_wallet_tx_success=self._merchant_wallet_tx_success,
            include_merchant_wallet_tx=self._include_merchant_wallet_tx,
        )

    def send_external_message(self, network: str, external_boc: bytes) -> str:
        self.sent.append((network, external_boc))
        return "external-hash"


def test_verify_accepts_valid_payment() -> None:
    signer = FakeSigner()
    scheme = ExactTvmScheme(signer)

    payload = _payment_payload(_settlement_boc(TEST_SECRET_KEY))
    requirements = _requirements()

    result = scheme.verify(payload, requirements)

    assert result.is_valid is True
    assert result.payer == PAYER


def test_verify_rejects_when_emulation_has_no_successful_recipient_wallet_transaction() -> None:
    signer = FakeSigner(merchant_wallet_tx_success=False)
    scheme = ExactTvmScheme(signer)

    payload = _payment_payload(_settlement_boc(TEST_SECRET_KEY))
    requirements = _requirements()

    result = scheme.verify(payload, requirements)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_SIMULATION_FAILED
    assert "recipient jetton wallet transaction failed" in (result.invalid_message or "")


def test_verify_rejects_wrong_recipient() -> None:
    signer = FakeSigner()
    scheme = ExactTvmScheme(signer)

    payload = _payment_payload(_settlement_boc(TEST_SECRET_KEY, recipient="0:" + "66" * 32))
    requirements = _requirements()

    result = scheme.verify(payload, requirements)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_INVALID_RECIPIENT


def test_verify_accepts_undeployed_wallet_with_state_init() -> None:
    signer = FakeSigner(is_active=False)
    scheme = ExactTvmScheme(signer)

    payload = _payment_payload(_settlement_boc(TEST_SECRET_KEY, include_state_init=True))
    requirements = _requirements()

    result = scheme.verify(payload, requirements)

    assert result.is_valid is False
    assert result.invalid_reason == ERR_STATE_INIT_NOT_SUPPORTED


def test_settle_rejects_duplicates() -> None:
    signer = FakeSigner()
    scheme = ExactTvmScheme(signer)

    payload = _payment_payload(_settlement_boc(TEST_SECRET_KEY))
    requirements = _requirements()

    first = scheme.settle(payload, requirements)
    second = scheme.settle(payload, requirements)

    assert first.success is True
    assert second.success is False
    assert second.error_reason == ERR_DUPLICATE_SETTLEMENT
    assert signer.built == [(TVM_MAINNET, PAYER, None), (TVM_MAINNET, PAYER, None)]
    assert signer.sent == [(TVM_MAINNET, b"external-boc")]


def test_settle_accepts_state_init_for_undeployed_wallet() -> None:
    signer = FakeSigner(is_active=False)
    scheme = ExactTvmScheme(signer)

    payload = _payment_payload(_settlement_boc(TEST_SECRET_KEY, include_state_init=True))
    requirements = _requirements()

    result = scheme.settle(payload, requirements)

    assert result.success is False
    assert result.error_reason == ERR_STATE_INIT_NOT_SUPPORTED
    assert signer.sent == []


def _payment_payload(settlement_boc: str) -> PaymentPayload:
    requirements = _requirements()
    return PaymentPayload(
        x402_version=2,
        payload={
            "settlementBoc": settlement_boc,
            "asset": JETTON_MASTER,
        },
        accepted=requirements,
    )


def _requirements() -> PaymentRequirements:
    return PaymentRequirements(
        scheme="exact",
        network=TVM_MAINNET,
        asset=JETTON_MASTER,
        amount="1000000",
        pay_to=RECIPIENT,
        max_timeout_seconds=300,
        extra={"areFeesSponsored": True},
    )


def _settlement_boc(
    secret_key: bytes,
    *,
    recipient: str = RECIPIENT,
    include_state_init: bool = False,
) -> str:
    body = _w5_body(secret_key, recipient=recipient)
    state_init = _wallet_state_init() if include_state_init else None

    message = Contract.create_internal_msg(
        src=None,
        dest=Address(PAYER),
        value=0,
        state_init=state_init,
        body=body,
    )
    return base64.b64encode(message.serialize().to_boc()).decode("utf-8")


def _w5_body(secret_key: bytes, *, recipient: str) -> Cell:
    out_msg = Contract.create_internal_msg(
        src=None,
        dest=Address(SOURCE_JETTON_WALLET),
        value=1,
        body=_jetton_transfer_body(recipient),
    ).serialize()

    action = (
        begin_cell()
        .store_uint(0x0EC3C86D, 32)
        .store_uint(3, 8)
        .store_ref(out_msg)
        .end_cell()
    )
    out_list = begin_cell().store_ref(Cell.empty()).store_cell(action).end_cell()

    unsigned_body = (
        begin_cell()
        .store_uint(W5_INTERNAL_SIGNED_OPCODE, 32)
        .store_uint(WALLET_ID, 32)
        .store_uint(int(time.time()) + 120, 32)
        .store_uint(0, 32)
        .store_bit(1)
        .store_ref(out_list)
        .store_bit(0)
        .end_cell()
    )
    signature = sign_message(unsigned_body.hash, secret_key)
    return begin_cell().store_slice(unsigned_body.begin_parse()).store_bytes(signature).end_cell()


def _wallet_state_init() -> StateInit:
    return build_w5r1_state_init(WALLET_PUBLIC_KEY, WALLET_ID)


PAYER = Address((0, _wallet_state_init().serialize().hash)).to_str(is_user_friendly=False)


def _jetton_transfer_body(recipient: str) -> Cell:
    return (
        begin_cell()
        .store_uint(JETTON_TRANSFER_OPCODE, 32)
        .store_uint(0, 64)
        .store_coins(1_000_000)
        .store_address(Address(recipient))
        .store_address(Address(PAYER))
        .store_bit(0)
        .store_coins(1)
        .store_bit(0)
        .store_uint(0, 1)
        .end_cell()
    )


def _emulate_trace(*, merchant_wallet_tx_success: bool, include_merchant_wallet_tx: bool) -> dict[str, object]:
    transactions: dict[str, object] = {}
    if include_merchant_wallet_tx:
        transactions["merchant-wallet-tx"] = {
            "account": MERCHANT_JETTON_WALLET,
            "description": {
                "aborted": not merchant_wallet_tx_success,
                "compute_ph": {"success": merchant_wallet_tx_success},
                "action": {"success": merchant_wallet_tx_success},
            },
        }

    return {
        "actions": [
            {
                "type": "jetton_transfer",
                "success": True,
                "details": {
                    "asset": JETTON_MASTER,
                    "sender": PAYER,
                    "receiver": RECIPIENT,
                    "sender_jetton_wallet": SOURCE_JETTON_WALLET,
                    "receiver_jetton_wallet": MERCHANT_JETTON_WALLET,
                    "amount": "1000000",
                },
            }
        ],
        "transactions": transactions,
    }
