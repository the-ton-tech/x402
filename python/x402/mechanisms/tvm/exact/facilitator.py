"""TVM facilitator implementation for the Exact payment scheme (V2)."""

from __future__ import annotations

import threading
import time
from typing import Any

from ....schemas import (
    Network,
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)
from ..codecs.common import normalize_address
from ..codecs.w5 import (
    address_from_state_init,
    parse_active_w5_account_state,
    parse_w5_init_data,
    verify_w5_signature,
)
from ..constants import (
    ERR_DUPLICATE_SETTLEMENT,
    ERR_INSUFFICIENT_BALANCE,
    ERR_INVALID_AMOUNT,
    ERR_INVALID_ASSET,
    ERR_INVALID_CODE_HASH,
    ERR_INVALID_EXTENSIONS_DICT,
    ERR_INVALID_RECIPIENT,
    ERR_INVALID_SEQNO,
    ERR_INVALID_SIGNATURE,
    ERR_INVALID_SIGNATURE_MODE,
    ERR_INVALID_W5_MESSAGE,
    ERR_INVALID_WALLET_ID,
    ERR_NETWORK_MISMATCH,
    ERR_SIMULATION_FAILED,
    ERR_STATE_INIT_NOT_SUPPORTED,
    ERR_TRANSACTION_FAILED,
    ERR_UNSUPPORTED_NETWORK,
    ERR_UNSUPPORTED_SCHEME,
    ERR_INVALID_UNTIL_EXPIRED,
    ERR_VALID_UNTIL_TOO_FAR,
    SCHEME_EXACT,
    SUPPORTED_NETWORKS,
    W5R1_CODE_HASH,
)
from .codec import parse_exact_tvm_payload
from ..signer import FacilitatorTvmSigner
from ..types import ExactTvmPayload, ParsedTvmSettlement, W5InitData


class ExactTvmScheme:
    """TVM facilitator implementation for the Exact payment scheme (V2)."""

    scheme = SCHEME_EXACT
    caip_family = "tvm:*"

    def __init__(self, signer: FacilitatorTvmSigner) -> None:
        self._signer = signer
        self._settlement_cache: dict[str, float] = {}
        self._lock = threading.Lock()

    def get_extra(self, network: Network) -> dict[str, Any] | None:
        """Get mechanism-specific extra data."""
        if str(network) not in SUPPORTED_NETWORKS:
            return None
        return {"areFeesSponsored": True}

    def get_signers(self, network: Network) -> list[str]:
        """Get facilitator wallet addresses."""
        _ = network
        return list(self._signer.get_addresses())

    def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        context=None,
    ) -> VerifyResponse:
        """Verify a TON exact payment payload."""
        try:
            tvm_payload = ExactTvmPayload.from_dict(payload.payload)
            settlement = parse_exact_tvm_payload(tvm_payload.settlement_boc)
            return self._verify(payload, requirements, tvm_payload, settlement)[0]
        except ValueError as e:
            return VerifyResponse(is_valid=False, invalid_reason=str(e), payer="")
        except Exception as e:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_SIMULATION_FAILED,
                invalid_message=str(e),
                payer="",
            )

    def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        context=None,
    ) -> SettleResponse:
        """Settle a TON exact payment payload."""
        tvm_payload = ExactTvmPayload.from_dict(payload.payload)
        settlement = parse_exact_tvm_payload(tvm_payload.settlement_boc)
        verification, external_boc = self._verify(payload, requirements, tvm_payload, settlement)
        if not verification.is_valid:
            return SettleResponse(
                success=False,
                error_reason=verification.invalid_reason,
                error_message=verification.invalid_message,
                payer=verification.payer,
                transaction="",
                network=requirements.network,
            )

        try:
            if self._reserve_settlement(settlement, requirements):
                return SettleResponse(
                    success=False,
                    error_reason=ERR_DUPLICATE_SETTLEMENT,
                    payer=settlement.payer,
                    transaction="",
                    network=requirements.network,
                )
            transaction = self._signer.send_external_message(str(requirements.network), external_boc)
        except Exception as e:
            self._delete_settlement(settlement)
            return SettleResponse(
                success=False,
                error_reason=ERR_SIMULATION_FAILED if isinstance(e, ValueError) else ERR_TRANSACTION_FAILED,
                error_message=str(e),
                payer=settlement.payer,
                transaction="",
                network=requirements.network,
            )

        return SettleResponse(
            success=True,
            payer=settlement.payer,
            transaction=transaction,
            network=requirements.network,
        )

    def _verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        tvm_payload: ExactTvmPayload,
        settlement: ParsedTvmSettlement
    ) -> tuple[VerifyResponse, bytes]:
        payer = settlement.payer
        if payload.x402_version != 2:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=settlement.payer)

        if payload.accepted.scheme != SCHEME_EXACT or requirements.scheme != SCHEME_EXACT:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=settlement.payer)

        if str(requirements.network) not in SUPPORTED_NETWORKS:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_NETWORK, payer=settlement.payer)

        if str(payload.accepted.network) != str(requirements.network):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_NETWORK_MISMATCH, payer=settlement.payer)

        if int(payload.accepted.amount) != int(requirements.amount):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_AMOUNT, payer=settlement.payer)
        
        if normalize_address(payload.accepted.asset) != normalize_address(requirements.asset):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_ASSET, payer=settlement.payer)

        if normalize_address(payload.accepted.pay_to) != normalize_address(requirements.pay_to):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_RECIPIENT, payer=settlement.payer)

        if payload.accepted.extra.get("areFeesSponsored") is not True or requirements.extra.get("areFeesSponsored") is not True:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=settlement.payer)

        if normalize_address(tvm_payload.asset) != normalize_address(requirements.asset):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_ASSET, payer=settlement.payer)

        # Up to this point, we've checked all fields in PaymentRequirements and PaymentPayload except for settlementBoc

        if settlement.transfer.destination != normalize_address(requirements.pay_to):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_RECIPIENT, payer=payer)

        if settlement.transfer.jetton_amount != int(requirements.amount):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_AMOUNT, payer=payer)

        now = int(time.time())
        if settlement.valid_until <= now:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_UNTIL_EXPIRED, payer=payer)
        if settlement.valid_until > now + requirements.max_timeout_seconds:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_VALID_UNTIL_TOO_FAR, payer=payer)

        account = self._signer.get_account_state(payer, str(requirements.network))
        init_data_parsed: W5InitData

        if settlement.state_init is not None and account.is_uninitialized:
            if settlement.state_init.code is None or settlement.state_init.code.hash.hex() != W5R1_CODE_HASH:
                return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_CODE_HASH, payer=payer)
            payer_workchain = int(payer.split(":", 1)[0])
            if address_from_state_init(settlement.state_init, payer_workchain) != payer:
                return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_W5_MESSAGE, payer=payer)
            init_data_parsed = parse_w5_init_data(settlement.state_init)
            if init_data_parsed.seqno != 0:
                return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SEQNO, payer=payer)
            if init_data_parsed.extensions_dict:
                return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_EXTENSIONS_DICT, payer=payer)
        else:
            try:
                init_data_parsed = parse_active_w5_account_state(account)
            except RuntimeError:
                return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_CODE_HASH, payer=payer)
            
        if not init_data_parsed.signature_allowed:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SIGNATURE_MODE, payer=payer)
        if init_data_parsed.seqno != settlement.seqno:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SEQNO, payer=payer)
        if init_data_parsed.wallet_id != settlement.wallet_id:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_WALLET_ID, payer=payer)

        if not verify_w5_signature(init_data_parsed.public_key, settlement.signed_slice_hash, settlement.signature):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SIGNATURE, payer=payer)

        jetton_wallet_data = self._signer.get_jetton_wallet_data(
            settlement.transfer.source_wallet,
            str(requirements.network),
        )
        if normalize_address(jetton_wallet_data.owner) != payer:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_RECIPIENT, payer=payer)
        if normalize_address(jetton_wallet_data.jetton_minter) != normalize_address(requirements.asset):
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_ASSET, payer=payer)
        if jetton_wallet_data.balance < settlement.transfer.jetton_amount:
            return VerifyResponse(is_valid=False, invalid_reason=ERR_INSUFFICIENT_BALANCE, payer=payer)

        try:
            external_boc = self._signer.build_relay_external_boc(
                str(requirements.network),
                settlement.payer,
                settlement.body,
                settlement.state_init,
            )
            self._verify_relay_emulation(
                self._signer.emulate_external_message(str(requirements.network), external_boc),
                settlement=settlement,
                requirements=requirements,
            )
        except Exception as e:
            return VerifyResponse(
                is_valid=False,
                invalid_reason=ERR_SIMULATION_FAILED,
                invalid_message=str(e),
                payer=payer,
            )

        return (VerifyResponse(is_valid=True, payer=payer), external_boc)

    def _reserve_settlement(
        self,
        settlement: ParsedTvmSettlement,
        requirements: PaymentRequirements,
    ) -> bool:
        with self._lock:
            self._cleanup_expired_settlements(requirements)
            if settlement.settlement_hash in self._settlement_cache:
                return True

            self._settlement_cache[settlement.settlement_hash] = time.monotonic()
            return False

    def _delete_settlement(self, settlement: ParsedTvmSettlement) -> None:
        with self._lock:
            self._settlement_cache.pop(settlement.settlement_hash, None)

    def _cleanup_expired_settlements(self, requirements: PaymentRequirements) -> None:
        cutoff = time.monotonic() - requirements.max_timeout_seconds
        expired = [key for key, ts in self._settlement_cache.items() if ts < cutoff]
        for key in expired:
            del self._settlement_cache[key]

    def _verify_relay_emulation(
        self,
        emulate_trace: dict[str, object],
        *,
        settlement: ParsedTvmSettlement,
        requirements: PaymentRequirements,
    ) -> None:
        actions = emulate_trace.get("actions")
        if not isinstance(actions, list):
            raise ValueError("Toncenter emulateTrace did not return actions")

        expected_asset = normalize_address(requirements.asset)
        expected_receiver = normalize_address(requirements.pay_to)
        expected_sender = settlement.payer
        expected_source_wallet = normalize_address(settlement.transfer.source_wallet)
        expected_amount = int(requirements.amount)

        for action in actions:
            if not isinstance(action, dict):
                continue
            if action.get("type") != "jetton_transfer" or action.get("success") is not True:
                continue
            details = action.get("details")
            if not isinstance(details, dict):
                continue
            try:
                asset = normalize_address(str(details["asset"]))
                receiver = normalize_address(str(details["receiver"]))
                sender = normalize_address(str(details["sender"]))
                sender_wallet = normalize_address(str(details["sender_jetton_wallet"]))
                amount = int(str(details["amount"]))
            except Exception:
                continue
            if (asset != expected_asset or receiver != expected_receiver or sender != expected_sender or 
                sender_wallet != expected_source_wallet or amount != expected_amount):
                continue
            return {"action": action, "details": details}

        raise ValueError("emulateTrace does not contain a successful jetton transfer to the merchant")
