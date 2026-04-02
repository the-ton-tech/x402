"""Tests for the exact TVM client scheme."""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("pytoniq_core")

from pytoniq.contract.contract import Contract
from pytoniq_core import Address, begin_cell

from x402.mechanisms.tvm import (
    TVM_TESTNET,
    TvmAccountState,
    address_from_state_init,
    build_w5r1_state_init,
)
from x402.mechanisms.tvm.constants import (
    DEFAULT_TVM_EMULATION_ADDRESS,
    DEFAULT_TVM_INNER_GAS_BUFFER,
)
from x402.mechanisms.tvm.exact import ExactTvmClientScheme
from x402.mechanisms.tvm.exact.codec import parse_exact_tvm_payload
from x402.schemas import PaymentRequirements

MERCHANT = "0:" + "2" * 64
ASSET = "0:" + "3" * 64
SOURCE_WALLET = "0:" + "4" * 64
RECEIVER_WALLET = "0:" + "5" * 64
RESPONSE_DESTINATION = "0:" + "6" * 64
EMULATION_ADDRESS = DEFAULT_TVM_EMULATION_ADDRESS


class _SignerStub:
    def __init__(self) -> None:
        self._wallet_id = 7
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
        assert message
        return b"\x00" * 64


class _ToncenterStub:
    def __init__(
        self,
        *,
        is_active: bool = False,
        source_wallet_balance: int = 0,
        source_wallet_fwd_fees: list[int] | None = None,
        source_wallet_compute_fee: int = 0,
        receiver_wallet_compute_fee: int = 0,
        source_wallet_storage_fee: int = 0,
        omit_receiver_tx: bool = False,
        source_action_total_fwd_fees: int | None = None,
    ) -> None:
        self._is_active = is_active
        self._source_wallet_balance = source_wallet_balance
        self._source_wallet_fwd_fees = source_wallet_fwd_fees or [0]
        self._source_wallet_compute_fee = source_wallet_compute_fee
        self._receiver_wallet_compute_fee = receiver_wallet_compute_fee
        self._source_wallet_storage_fee = source_wallet_storage_fee
        self._omit_receiver_tx = omit_receiver_tx
        self._source_action_total_fwd_fees = source_action_total_fwd_fees
        self.get_account_state_calls = 0
        self.get_jetton_wallet_calls: list[tuple[str, str]] = []
        self.emulate_trace_calls: list[dict[str, object]] = []
        self._signer_state_init = _SignerStub().state_init

    def get_account_state(self, address: str) -> TvmAccountState:
        self.get_account_state_calls += 1
        return TvmAccountState(
            address=address,
            balance=0,
            is_active=self._is_active,
            is_uninitialized=not self._is_active,
            state_init=self._signer_state_init if self._is_active else None,
        )

    def get_jetton_wallet(self, asset: str, owner: str) -> str:
        self.get_jetton_wallet_calls.append((asset, owner))
        if owner == _SignerStub().address:
            return SOURCE_WALLET
        return RECEIVER_WALLET

    def emulate_trace(self, boc: bytes, *, ignore_chksig: bool = False) -> dict[str, object]:
        _ = boc
        self.emulate_trace_calls.append({"ignore_chksig": ignore_chksig})
        payer = _SignerStub().address
        source_wallet = SOURCE_WALLET
        relay_out_hash = "relay-out-hash"
        payer_out_hash = "payer-out-hash"
        source_out_hash = "source-out-hash"
        transactions = {
            "payer": {
                "account": payer,
                "description": {
                    "aborted": False,
                    "action": {"success": True},
                    "compute_ph": {"success": True, "skipped": False},
                },
                "in_msg": (
                    {
                        "hash": relay_out_hash,
                        "hash_norm": relay_out_hash,
                        "source": EMULATION_ADDRESS,
                        "destination": payer,
                        "decoded_opcode": "w5_internal_signed_request",
                    }
                    if ignore_chksig
                    else {"decoded_opcode": "w5_external_signed_request"}
                ),
                "out_msgs": [{"hash": payer_out_hash, "hash_norm": payer_out_hash}],
            },
            "source": {
                "account": source_wallet,
                "account_state_before": {"balance": str(self._source_wallet_balance)},
                "description": {
                    "aborted": False,
                    "action": {
                        "success": True,
                        **(
                            {"total_fwd_fees": str(self._source_action_total_fwd_fees)}
                            if self._source_action_total_fwd_fees is not None
                            else {}
                        ),
                    },
                    "compute_ph": {
                        "success": True,
                        "skipped": False,
                        "gas_fees": str(self._source_wallet_compute_fee),
                    },
                    "storage_ph": {"storage_fees_collected": str(self._source_wallet_storage_fee)},
                },
                "in_msg": {
                    "hash": payer_out_hash,
                    "hash_norm": payer_out_hash,
                    "source": payer,
                    "destination": source_wallet,
                    "decoded_opcode": "jetton_transfer",
                },
                "out_msgs": [
                    {
                        "hash": source_out_hash,
                        "hash_norm": source_out_hash,
                        "source": source_wallet,
                        "destination": RECEIVER_WALLET,
                        "decoded_opcode": "jetton_internal_transfer",
                        "message_content": {
                            "decoded": {
                                "@type": "jetton_internal_transfer",
                            }
                        },
                        **({"fwd_fee": str(fee)} if fee is not None else {}),
                    }
                    for fee in self._source_wallet_fwd_fees
                ],
            },
        }
        if not self._omit_receiver_tx:
            transactions["receiver"] = {
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
                    "source": source_wallet,
                    "destination": RECEIVER_WALLET,
                    "decoded_opcode": "jetton_internal_transfer",
                },
            }
        if ignore_chksig:
            transactions["emulation"] = {
                "account": EMULATION_ADDRESS,
                "description": {
                    "aborted": False,
                    "action": {"success": True},
                    "compute_ph": {"success": True, "skipped": False},
                },
                "in_msg": {"decoded_opcode": "w5_external_signed_request"},
                "out_msgs": [
                    {
                        "hash": relay_out_hash,
                        "hash_norm": relay_out_hash,
                        "source": EMULATION_ADDRESS,
                        "destination": payer,
                    }
                ],
            }
        return {"transactions": transactions}


def _make_requirements(**overrides) -> PaymentRequirements:
    extra = {
        "areFeesSponsored": True,
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


class TestExactTvmClientSchemeConstructor:
    def test_should_create_instance_with_correct_scheme(self):
        signer = _SignerStub()

        client = ExactTvmClientScheme(signer)

        assert client.scheme == "exact"

    def test_should_store_signer_reference(self):
        signer = _SignerStub()

        client = ExactTvmClientScheme(signer)

        assert client._signer is signer


class TestCreatePaymentPayload:
    def test_should_have_create_payment_payload_method(self):
        client = ExactTvmClientScheme(_SignerStub())

        assert hasattr(client, "create_payment_payload")
        assert callable(client.create_payment_payload)

    def test_should_reject_unsupported_network(self):
        client = ExactTvmClientScheme(_SignerStub())

        with pytest.raises(ValueError, match="Unsupported TVM network"):
            client.create_payment_payload(_make_requirements(network="tvm:999"))

    def test_should_reject_requirements_for_different_signer_network(self):
        client = ExactTvmClientScheme(_SignerStub())

        with pytest.raises(ValueError, match="Signer network .* does not match requirements"):
            client.create_payment_payload(_make_requirements(network="tvm:-239"))

    def test_should_require_fee_sponsorship(self):
        client = ExactTvmClientScheme(_SignerStub())

        with pytest.raises(ValueError, match="requires extra.areFeesSponsored to be true"):
            client.create_payment_payload(_make_requirements(extra={"areFeesSponsored": False}))

    def test_should_create_payload_with_forward_defaults(self, monkeypatch):
        client = ExactTvmClientScheme(_SignerStub())
        toncenter = _ToncenterStub(
            is_active=True,
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[200_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        )
        monkeypatch.setattr(client, "_get_client", lambda network: toncenter)

        payload = client.create_payment_payload(_make_requirements())
        settlement = parse_exact_tvm_payload(payload["settlementBoc"])

        assert payload["asset"] == ASSET
        assert settlement.transfer.destination == MERCHANT
        assert settlement.transfer.source_wallet == SOURCE_WALLET
        assert settlement.transfer.response_destination is None
        assert settlement.transfer.forward_ton_amount == 0
        assert settlement.transfer.forward_payload.hash == begin_cell().store_bit(0).end_cell().hash
        assert settlement.transfer.attached_ton_amount == (
            200_000 + 300_000 + 400_000 + 500_000 + DEFAULT_TVM_INNER_GAS_BUFFER
        )
        assert toncenter.get_account_state_calls == 1
        assert toncenter.get_jetton_wallet_calls == [(ASSET, _SignerStub().address)]
        assert toncenter.emulate_trace_calls == [{"ignore_chksig": True}]

    def test_should_use_default_emulation_wallet_to_relay_into_undeployed_payer(self, monkeypatch):
        client = ExactTvmClientScheme(_SignerStub())
        toncenter = _ToncenterStub(
            is_active=False,
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[200_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        )
        monkeypatch.setattr(client, "_get_client", lambda network: toncenter)

        payload = client.create_payment_payload(_make_requirements())
        settlement = parse_exact_tvm_payload(payload["settlementBoc"])

        assert settlement.transfer.source_wallet == SOURCE_WALLET
        assert toncenter.get_account_state_calls == 1
        assert toncenter.get_jetton_wallet_calls == [(ASSET, _SignerStub().address)]
        assert toncenter.emulate_trace_calls == [{"ignore_chksig": True}]

    def test_should_create_payload_with_custom_forward_settings(self, monkeypatch):
        client = ExactTvmClientScheme(_SignerStub())
        toncenter = _ToncenterStub(
            is_active=True,
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[200_000, 250_000],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
        )
        monkeypatch.setattr(client, "_get_client", lambda network: toncenter)
        forward_payload = begin_cell().store_uint(0xABCD, 16).end_cell()

        payload = client.create_payment_payload(
            _make_requirements(
                extra={
                    "areFeesSponsored": True,
                    "responseDestination": RESPONSE_DESTINATION,
                    "forwardTonAmount": "50000000",
                    "forwardPayload": base64.b64encode(forward_payload.to_boc()).decode("ascii"),
                }
            )
        )
        settlement = parse_exact_tvm_payload(payload["settlementBoc"])

        assert settlement.transfer.response_destination == RESPONSE_DESTINATION
        assert settlement.transfer.forward_ton_amount == 50_000_000
        assert settlement.transfer.forward_payload.hash == forward_payload.hash
        assert settlement.transfer.attached_ton_amount == 58_750_000

    def test_should_raise_when_trace_does_not_include_destination_wallet_transfer(
        self, monkeypatch
    ):
        client = ExactTvmClientScheme(_SignerStub())
        monkeypatch.setattr(
            client,
            "_get_client",
            lambda network: _ToncenterStub(
                is_active=True,
                source_wallet_balance=1_000_000,
                source_wallet_fwd_fees=[200_000],
                source_wallet_compute_fee=300_000,
                receiver_wallet_compute_fee=400_000,
                source_wallet_storage_fee=500_000,
                omit_receiver_tx=True,
            ),
        )

        with pytest.raises(
            ValueError,
            match="Trace does not contain the expected destination jetton wallet transaction",
        ):
            client.create_payment_payload(_make_requirements())

    def test_build_transfer_body_should_reject_negative_forward_ton_amount(self):
        client = ExactTvmClientScheme(_SignerStub())

        with pytest.raises(ValueError, match="Forward ton amount should be >= 0"):
            client._build_transfer_body(_make_requirements(extra={"forwardTonAmount": "-1"}))

    def test_build_transfer_body_should_store_explicit_forward_payload(self):
        client = ExactTvmClientScheme(_SignerStub())
        forward_payload = begin_cell().store_uint(0xABCD, 16).end_cell()

        transfer_body = client._build_transfer_body(
            _make_requirements(
                extra={
                    "forwardTonAmount": "777",
                    "forwardPayload": base64.b64encode(forward_payload.to_boc()).decode("ascii"),
                }
            )
        )
        transfer = parse_exact_tvm_payload(
            base64.b64encode(
                Contract.create_internal_msg(
                    src=None,
                    dest=Address(_SignerStub().address),
                    bounce=True,
                    value=0,
                    body=client._build_signed_body(
                        source_wallet=SOURCE_WALLET,
                        transfer_body=transfer_body,
                        seqno=1,
                        valid_until=2,
                        attached_amount=3,
                    ),
                )
                .serialize()
                .to_boc()
            ).decode("ascii")
        )

        assert transfer.transfer.forward_ton_amount == 777
        assert transfer.transfer.forward_payload.hash == forward_payload.hash

    def test_estimate_required_inner_value_should_fallback_to_action_phase_fees(self, monkeypatch):
        client = ExactTvmClientScheme(_SignerStub())
        toncenter = _ToncenterStub(
            is_active=True,
            source_wallet_balance=1_000_000,
            source_wallet_fwd_fees=[None],
            source_wallet_compute_fee=300_000,
            receiver_wallet_compute_fee=400_000,
            source_wallet_storage_fee=500_000,
            source_action_total_fwd_fees=200_000,
        )
        monkeypatch.setattr(client, "_get_client", lambda network: toncenter)

        payload = client.create_payment_payload(_make_requirements())
        settlement = parse_exact_tvm_payload(payload["settlementBoc"])

        assert settlement.transfer.attached_ton_amount == (
            200_000 + 300_000 + 400_000 + 500_000 + DEFAULT_TVM_INNER_GAS_BUFFER
        )
