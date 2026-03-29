"""Unit tests for the TVM exact client and server schemes."""

from __future__ import annotations

from nacl.bindings import crypto_sign_seed_keypair
from pytoniq_core import Address, begin_cell
from pytoniq_core.crypto.signature import sign_message
from pytoniq_core.tlb.account import StateInit

from x402.mechanisms.tvm import (
    TVM_MAINNET,
    USDT_MAINNET_MINTER,
    build_w5r1_state_init,
    make_w5r1_wallet_id,
    parse_exact_tvm_payload,
)
from x402.mechanisms.tvm.exact.client import ExactTvmScheme as ExactTvmClientScheme
from x402.mechanisms.tvm.exact.server import ExactTvmScheme as ExactTvmServerScheme
from x402.mechanisms.tvm.types import TvmAccountState
from x402.mechanisms.tvm.utils import parse_w5_init_data
from x402.schemas import PaymentRequirements, SupportedKind

SOURCE_JETTON_WALLET = "0:" + "22" * 32
RECIPIENT = "0:" + "44" * 32


class FakeClientSigner:
    def __init__(self) -> None:
        _, self._secret_key = crypto_sign_seed_keypair(b"\x02" * 32)
        self._public_key = self._secret_key[32:]
        self._wallet_id = make_w5r1_wallet_id(TVM_MAINNET)
        self._state_init = build_w5r1_state_init(self._public_key, self._wallet_id)
        self._address = Address((0, self._state_init.serialize().hash)).to_str(is_user_friendly=False)

    @property
    def address(self) -> str:
        return self._address

    @property
    def network(self) -> str:
        return TVM_MAINNET

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @property
    def wallet_id(self) -> int:
        return self._wallet_id

    @property
    def state_init(self):
        return self._state_init

    def sign_message(self, message: bytes) -> bytes:
        return sign_message(message, self._secret_key)


class FakeToncenterClient:
    def __init__(self, *, active: bool, seqno: int = 7) -> None:
        self._active = active
        self._seqno = seqno

    def get_account_state(self, address: str) -> TvmAccountState:
        return TvmAccountState(
            address=address,
            balance=0,
            is_active=self._active,
            is_uninitialized=not self._active,
            state_init=_wallet_state_init(seqno=self._seqno) if self._active else None,
            last_transaction_lt=None,
        )

    def get_jetton_wallet(self, asset: str, owner: str) -> str:
        _ = asset, owner
        return SOURCE_JETTON_WALLET


def test_client_creates_settlement_boc_for_undeployed_wallet() -> None:
    signer = FakeClientSigner()
    scheme = ExactTvmClientScheme(signer)
    scheme._get_client = lambda network: FakeToncenterClient(active=False)  # type: ignore[method-assign]

    payload = scheme.create_payment_payload(_requirements())
    settlement = parse_exact_tvm_payload(payload["settlementBoc"])

    assert payload["asset"] == USDT_MAINNET_MINTER
    assert settlement.payer == signer.address
    assert settlement.wallet_id == signer.wallet_id
    assert settlement.transfer.source_wallet == SOURCE_JETTON_WALLET
    assert settlement.transfer.destination == RECIPIENT
    assert settlement.transfer.jetton_amount == 1_500_000
    assert settlement.state_init is not None
    assert settlement.state_init.serialize().hash.hex() == signer.state_init.serialize().hash.hex()


def test_client_omits_state_init_for_active_wallet() -> None:
    signer = FakeClientSigner()
    scheme = ExactTvmClientScheme(signer)
    scheme._get_client = lambda network: FakeToncenterClient(active=True, seqno=9)  # type: ignore[method-assign]

    payload = scheme.create_payment_payload(_requirements())
    settlement = parse_exact_tvm_payload(payload["settlementBoc"])

    assert settlement.seqno == 9
    assert settlement.state_init is None


def test_server_defaults_to_mainnet_usdt_and_sponsored_fees() -> None:
    scheme = ExactTvmServerScheme()

    parsed = scheme.parse_price("$1.50", TVM_MAINNET)
    requirements = PaymentRequirements(
        scheme="exact",
        network=TVM_MAINNET,
        asset="",
        amount="1.50",
        pay_to=RECIPIENT,
        max_timeout_seconds=300,
        extra={},
    )
    supported_kind = SupportedKind(
        x402_version=2,
        scheme="exact",
        network=TVM_MAINNET,
        extra={"areFeesSponsored": True},
    )

    enhanced = scheme.enhance_payment_requirements(requirements, supported_kind, [])

    assert parsed.amount == "1500000"
    assert parsed.asset == USDT_MAINNET_MINTER
    assert parsed.extra == {"areFeesSponsored": True}
    assert enhanced.asset == USDT_MAINNET_MINTER
    assert enhanced.amount == "1500000"
    assert enhanced.extra == {"areFeesSponsored": True}


def _requirements() -> PaymentRequirements:
    return PaymentRequirements(
        scheme="exact",
        network=TVM_MAINNET,
        asset=USDT_MAINNET_MINTER,
        amount="1500000",
        pay_to=RECIPIENT,
        max_timeout_seconds=300,
        extra={"areFeesSponsored": True},
    )


def _wallet_state_init(*, seqno: int) -> StateInit:
    _, secret_key = crypto_sign_seed_keypair(b"\x02" * 32)
    state_init = build_w5r1_state_init(secret_key[32:], make_w5r1_wallet_id(TVM_MAINNET))
    parsed = parse_w5_init_data(state_init)
    updated_data = (
        begin_cell()
        .store_uint(parsed.signature_allowed, 1)
        .store_uint(seqno, 32)
        .store_uint(parsed.wallet_id, 32)
        .store_bytes(parsed.public_key)
        .store_maybe_ref(parsed.extensions_dict)
        .end_cell()
    )
    return StateInit(code=state_init.code, data=updated_data)
