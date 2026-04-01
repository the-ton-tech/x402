"""TVM integration tests for x402ClientSync, x402ResourceServerSync, and x402FacilitatorSync.

These tests perform REAL blockchain transactions on TON testnet using sync classes.

Required environment variables:
- TVM_PRIVATE_KEY: TON private key used for both the payer W5 wallet and facilitator highload wallet
- TONCENTER_API_KEY: Toncenter API key for TON

These must correspond to a wallet that has TON and USDT.
"""

from __future__ import annotations

import os
import time

import pytest

pytest.importorskip("pytoniq_core")

from pytoniq_core import Cell

from x402 import x402ClientSync, x402FacilitatorSync, x402ResourceServerSync
from x402.mechanisms.tvm import (
    EMPTY_FORWARD_PAYLOAD_BOC,
    ERR_DUPLICATE_SETTLEMENT,
    ERR_INVALID_SEQNO,
    SCHEME_EXACT,
    TVM_TESTNET,
    USDT_TESTNET_MINTER,
    ExactTvmPayload,
    FacilitatorHighloadV3Signer,
    HighloadV3Config,
    ToncenterV3Client,
    WalletV5R1Config,
    WalletV5R1MnemonicSigner,
    parse_exact_tvm_payload,
)
from x402.mechanisms.tvm.exact import (
    ExactTvmClientScheme,
    ExactTvmFacilitatorScheme,
    ExactTvmServerScheme,
)
from x402.schemas import (
    PaymentPayload,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
    SupportedResponse,
    VerifyResponse,
)

TVM_PRIVATE_KEY = os.environ.get("TVM_PRIVATE_KEY")
TONCENTER_API_KEY = os.environ.get("TONCENTER_API_KEY")
TONCENTER_BASE_URL = os.environ.get("TONCENTER_BASE_URL")

TEST_PAYMENT_AMOUNT = "1000"  # 0.001 USDT with 6 decimals
MIN_CLIENT_TON_BALANCE = 100_000_000
MIN_FACILITATOR_TON_BALANCE = 1_000_000_000
MIN_CLIENT_USDT_BALANCE = int(TEST_PAYMENT_AMOUNT)

pytestmark = pytest.mark.skipif(
    not TVM_PRIVATE_KEY or not TONCENTER_API_KEY,
    reason="TVM_PRIVATE_KEY and TONCENTER_API_KEY are required for TVM integration tests",
)


class TvmFacilitatorClientSync:
    """Facilitator client wrapper for x402ResourceServerSync."""

    scheme = SCHEME_EXACT
    network = TVM_TESTNET
    x402_version = 2

    def __init__(self, facilitator: x402FacilitatorSync):
        self._facilitator = facilitator

    def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        return self._facilitator.verify(payload, requirements)

    def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse:
        return self._facilitator.settle(payload, requirements)

    def get_supported(self) -> SupportedResponse:
        return self._facilitator.get_supported()


def build_tvm_payment_requirements(
    pay_to: str,
    amount: str,
    network: str = TVM_TESTNET,
    asset: str = USDT_TESTNET_MINTER,
) -> PaymentRequirements:
    """Build TVM payment requirements for testing."""
    return PaymentRequirements(
        scheme=SCHEME_EXACT,
        network=network,
        asset=asset,
        amount=amount,
        pay_to=pay_to,
        max_timeout_seconds=300,
        extra={
            "decimals": 6,
            "areFeesSponsored": True,
        },
    )


def _wait_for_jetton_balance_at_least(
    provider: ToncenterV3Client,
    jetton_wallet: str,
    expected_balance: int,
    *,
    timeout_seconds: float = 20.0,
) -> int:
    """Wait until Toncenter reflects a target jetton balance."""
    deadline = time.monotonic() + timeout_seconds
    last_balance = 0
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            last_balance = provider.get_jetton_wallet_data(jetton_wallet).balance
            if last_balance >= expected_balance:
                return last_balance
        except Exception as exc:  # pragma: no cover - retry path for flaky RPC
            last_error = exc
        time.sleep(1.0)

    if last_error is not None:
        raise AssertionError(
            f"Timed out waiting for jetton balance update for {jetton_wallet}: {last_error}"
        ) from last_error
    raise AssertionError(
        f"Timed out waiting for jetton balance {expected_balance}, last balance {last_balance}"
    )


class TestTvmIntegrationV2:
    """Integration tests for TVM V2 payment flow with REAL blockchain transactions."""

    def setup_method(self) -> None:
        client_config = WalletV5R1Config.from_private_key(TVM_TESTNET, TVM_PRIVATE_KEY)
        client_config.api_key = TONCENTER_API_KEY
        client_config.base_url = TONCENTER_BASE_URL
        self.client_signer = WalletV5R1MnemonicSigner(client_config)

        facilitator_config = HighloadV3Config.from_private_key(TVM_PRIVATE_KEY)
        facilitator_config.api_key = TONCENTER_API_KEY
        facilitator_config.toncenter_base_url = TONCENTER_BASE_URL
        self.facilitator_signer = FacilitatorHighloadV3Signer({TVM_TESTNET: facilitator_config})

        self.provider = ToncenterV3Client(
            TVM_TESTNET,
            api_key=TONCENTER_API_KEY,
            base_url=TONCENTER_BASE_URL,
        )

        self.client_address = self.client_signer.address
        self.facilitator_address = self.facilitator_signer.get_addresses()[0]
        self.client_jetton_wallet = self.provider.get_jetton_wallet(
            USDT_TESTNET_MINTER,
            self.client_address,
        )
        self.facilitator_jetton_wallet = self.provider.get_jetton_wallet(
            USDT_TESTNET_MINTER,
            self.facilitator_address,
        )

        self.client = x402ClientSync().register(
            TVM_TESTNET,
            ExactTvmClientScheme(self.client_signer),
        )
        self.facilitator = x402FacilitatorSync().register(
            [TVM_TESTNET],
            ExactTvmFacilitatorScheme(
                self.facilitator_signer,
                batch_flush_interval_seconds=0.05,
                batch_max_size=1,
            ),
        )

        facilitator_client = TvmFacilitatorClientSync(self.facilitator)
        self.server = x402ResourceServerSync(facilitator_client)
        self.server.register(TVM_TESTNET, ExactTvmServerScheme())
        self.server.initialize()

    def teardown_method(self) -> None:
        self.facilitator_signer.close()
        self.provider.close()

    def _require_live_balances(self) -> None:
        client_state = self.provider.get_account_state(self.client_address)
        facilitator_state = self.provider.get_account_state(self.facilitator_address)
        client_jetton_balance = self.provider.get_jetton_wallet_data(
            self.client_jetton_wallet
        ).balance

        if client_state.balance < MIN_CLIENT_TON_BALANCE:
            pytest.skip(
                f"Client wallet {self.client_address} needs at least {MIN_CLIENT_TON_BALANCE} nanotons"
            )
        if facilitator_state.balance < MIN_FACILITATOR_TON_BALANCE:
            pytest.skip(
                "Facilitator wallet "
                f"{self.facilitator_address} needs at least {MIN_FACILITATOR_TON_BALANCE} nanotons"
            )
        if client_jetton_balance < MIN_CLIENT_USDT_BALANCE:
            pytest.skip(
                f"Client jetton wallet {self.client_jetton_wallet} needs at least {MIN_CLIENT_USDT_BALANCE} USDT units"
            )

    def test_server_should_successfully_verify_and_settle_tvm_payment_from_client(
        self,
    ) -> None:
        """Test the complete TVM V2 payment flow with REAL blockchain transactions."""
        self._require_live_balances()

        recipient_balance_before = self.provider.get_jetton_wallet_data(
            self.facilitator_jetton_wallet
        ).balance

        accepts = [
            build_tvm_payment_requirements(
                self.facilitator_address,
                TEST_PAYMENT_AMOUNT,
            )
        ]
        resource = ResourceInfo(
            url="https://api.example.com/premium",
            description="Premium API Access",
            mime_type="application/json",
        )
        payment_required = self.server.create_payment_required_response(accepts, resource)

        assert payment_required.x402_version == 2

        payment_payload = self.client.create_payment_payload(payment_required)

        assert payment_payload.x402_version == 2
        assert payment_payload.accepted.scheme == SCHEME_EXACT
        assert payment_payload.accepted.network == TVM_TESTNET
        assert "settlementBoc" in payment_payload.payload
        assert "asset" in payment_payload.payload

        accepted = self.server.find_matching_requirements(accepts, payment_payload)
        assert accepted is not None

        verify_response = self.server.verify_payment(payment_payload, accepted)
        if not verify_response.is_valid:
            print(f"❌ Verification failed: {verify_response.invalid_reason}")
            print(f"Payer: {verify_response.payer}")
            print(f"Client address: {self.client_address}")

        assert verify_response.is_valid is True
        assert verify_response.payer == self.client_address

        settle_response = self.server.settle_payment(payment_payload, accepted)
        if not settle_response.success:
            print(f"❌ Settlement failed: {settle_response.error_reason}")
            if settle_response.transaction:
                print(f"📋 Trace message hash: {settle_response.transaction}")

        assert settle_response.success is True
        assert settle_response.network == TVM_TESTNET
        assert settle_response.transaction != ""
        assert settle_response.payer == self.client_address

        recipient_balance_after = _wait_for_jetton_balance_at_least(
            self.provider,
            self.facilitator_jetton_wallet,
            recipient_balance_before + int(TEST_PAYMENT_AMOUNT),
        )
        assert recipient_balance_after >= recipient_balance_before + int(TEST_PAYMENT_AMOUNT)

    def test_client_creates_valid_tvm_payment_payload(self) -> None:
        """Test that client creates properly structured TVM payload."""
        accepts = [
            build_tvm_payment_requirements(
                self.facilitator_address,
                "5000000",
            )
        ]
        payment_required = self.server.create_payment_required_response(accepts)

        payload = self.client.create_payment_payload(payment_required)

        assert payload.x402_version == 2
        assert payload.accepted.scheme == SCHEME_EXACT
        assert payload.accepted.amount == "5000000"
        assert payload.accepted.network == TVM_TESTNET

        tvm_payload = ExactTvmPayload.from_dict(payload.payload)
        settlement = parse_exact_tvm_payload(tvm_payload.settlement_boc)

        assert tvm_payload.asset == USDT_TESTNET_MINTER
        assert settlement.payer == self.client_address
        assert settlement.state_init is None
        assert settlement.transfer.destination == self.facilitator_address
        assert settlement.transfer.response_destination is None
        assert settlement.transfer.jetton_amount == 5_000_000
        assert settlement.transfer.forward_ton_amount == 0
        assert settlement.transfer.source_wallet == self.client_jetton_wallet

    def test_invalid_recipient_fails_verification(self) -> None:
        """Test that mismatched recipient fails verification."""
        accepts = [
            build_tvm_payment_requirements(
                self.facilitator_address,
                TEST_PAYMENT_AMOUNT,
            )
        ]
        payment_required = self.server.create_payment_required_response(accepts)
        payload = self.client.create_payment_payload(payment_required)

        different_accepts = [
            build_tvm_payment_requirements(
                self.client_address,
                TEST_PAYMENT_AMOUNT,
            )
        ]

        verify_response = self.server.verify_payment(payload, different_accepts[0])
        assert verify_response.is_valid is False
        assert "recipient" in verify_response.invalid_reason.lower()

    def test_insufficient_amount_fails_verification(self) -> None:
        """Test that insufficient amount fails verification."""
        accepts = [
            build_tvm_payment_requirements(
                self.facilitator_address,
                TEST_PAYMENT_AMOUNT,
            )
        ]
        payment_required = self.server.create_payment_required_response(accepts)
        payload = self.client.create_payment_payload(payment_required)

        higher_accepts = [
            build_tvm_payment_requirements(
                self.facilitator_address,
                "2000",
            )
        ]

        verify_response = self.server.verify_payment(payload, higher_accepts[0])
        assert verify_response.is_valid is False
        assert "amount" in verify_response.invalid_reason.lower()

    def test_duplicate_settlement_fails_on_second_attempt(self) -> None:
        """Test that settling the same payload twice is rejected as duplicate."""
        self._require_live_balances()

        accepts = [
            build_tvm_payment_requirements(
                self.facilitator_address,
                TEST_PAYMENT_AMOUNT,
            )
        ]
        payment_required = self.server.create_payment_required_response(accepts)
        payload = self.client.create_payment_payload(payment_required)
        accepted = self.server.find_matching_requirements(accepts, payload)
        assert accepted is not None

        first_settle = self.server.settle_payment(payload, accepted)
        assert first_settle.success is True

        second_settle = self.server.settle_payment(payload, accepted)
        assert second_settle.success is False
        assert second_settle.error_reason in {
            ERR_DUPLICATE_SETTLEMENT,
            ERR_INVALID_SEQNO,
        }

    def test_facilitator_get_supported(self) -> None:
        """Test that facilitator returns supported kinds."""
        supported = self.facilitator.get_supported()

        tvm_support = None
        for kind in supported.kinds:
            if kind.network == TVM_TESTNET and kind.scheme == SCHEME_EXACT:
                tvm_support = kind
                break

        assert tvm_support is not None
        assert tvm_support.x402_version == 2
        assert tvm_support.extra is not None
        assert tvm_support.extra.get("areFeesSponsored") is True
