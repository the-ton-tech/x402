"""TVM facilitator implementation for the Exact payment scheme (V2)."""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from pytoniq_core import begin_cell

from ....schemas import (
    Network,
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    VerifyResponse,
)
from ..codecs.common import decode_base64_boc, normalize_address
from ..codecs.w5 import (
    address_from_state_init,
    parse_active_w5_account_state,
    parse_w5_init_data,
    verify_w5_signature,
)
from ..constants import (
    DEFAULT_SETTLEMENT_BATCH_FLUSH_INTERVAL_SECONDS,
    DEFAULT_SETTLEMENT_BATCH_FLUSH_SIZE,
    DEFAULT_SETTLEMENT_BATCH_MAX_SIZE,
    DEFAULT_STREAMING_CONFIRMATION_TIMEOUT_SECONDS,
    DEFAULT_TVM_OUTER_GAS_BUFFER,
    ERR_DUPLICATE_SETTLEMENT,
    ERR_INSUFFICIENT_BALANCE,
    ERR_INVALID_AMOUNT,
    ERR_INVALID_ASSET,
    ERR_INVALID_CODE_HASH,
    ERR_INVALID_EXTENSIONS_DICT,
    ERR_INVALID_JETTON_TRANSFER,
    ERR_INVALID_RECIPIENT,
    ERR_INVALID_SEQNO,
    ERR_INVALID_SIGNATURE,
    ERR_INVALID_SIGNATURE_MODE,
    ERR_INVALID_UNTIL_EXPIRED,
    ERR_INVALID_W5_MESSAGE,
    ERR_INVALID_WALLET_ID,
    ERR_NETWORK_MISMATCH,
    ERR_SIMULATION_FAILED,
    ERR_TRANSACTION_FAILED,
    ERR_UNSUPPORTED_NETWORK,
    ERR_UNSUPPORTED_SCHEME,
    ERR_VALID_UNTIL_TOO_FAR,
    SCHEME_EXACT,
    SUPPORTED_NETWORKS,
    W5R1_CODE_HASH,
)
from ..trace_utils import (
    message_body_hash_matches,
    parse_trace_transactions,
    trace_transaction_compute_fees,
    trace_transaction_fwd_fees,
    trace_transaction_storage_fees,
    transaction_succeeded,
)
from ..settlement_cache import SettlementCache
from ..signer import FacilitatorTvmSigner
from ..types import ExactTvmPayload, ParsedTvmSettlement, TvmRelayRequest, W5InitData
from .codec import parse_exact_tvm_payload


@dataclass
class _BatchResult:
    success: bool
    transaction: str = ""
    error_reason: str | None = None
    error_message: str | None = None


@dataclass
class _QueuedSettlement:
    network: str
    settlement_hash: str
    settlement: ParsedTvmSettlement
    relay_request: TvmRelayRequest
    completed: threading.Event = field(default_factory=threading.Event)
    result: _BatchResult | None = None


@dataclass
class _PendingConfirmation:
    network: str
    batch: list[_QueuedSettlement]
    trace_external_hash_norm: str


def _effective_response_destination(extra: dict[str, Any]) -> str | None:
    response_destination = extra.get("responseDestination")
    if response_destination is None:
        return None
    return normalize_address(response_destination)


def _effective_forward_ton_amount(extra: dict[str, Any]) -> int:
    return int(extra.get("forwardTonAmount", 0))


def _effective_forward_payload(extra: dict[str, Any]):
    encoded_payload = extra.get("forwardPayload")
    if encoded_payload is None:
        return begin_cell().store_bit(0).end_cell()
    return decode_base64_boc(encoded_payload)


class _SettlementBatcher:
    def __init__(
        self,
        signer: FacilitatorTvmSigner,
        settlement_cache: SettlementCache,
        *,
        flush_interval_seconds: float,
        flush_batch_size: int,
        confirmation_timeout_seconds: float,
    ) -> None:
        self._signer = signer
        self._settlement_cache = settlement_cache
        self._flush_interval_seconds = flush_interval_seconds
        self._flush_batch_size = flush_batch_size
        self._max_batch_size = DEFAULT_SETTLEMENT_BATCH_MAX_SIZE
        self._confirmation_timeout_seconds = confirmation_timeout_seconds
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._confirmation_queue: queue.SimpleQueue[_PendingConfirmation] = queue.SimpleQueue()
        self._queues: dict[str, list[_QueuedSettlement]] = {}
        self._deadlines: dict[str, float] = {}
        self._worker = threading.Thread(
            target=self._run, name="tvm-settlement-batcher", daemon=True
        )
        self._worker.start()
        self._confirmation_workers = [
            threading.Thread(
                target=self._run_confirmation_worker,
                name=f"tvm-settlement-confirmation-{idx}",
                daemon=True,
            )
            for idx in range(4)
        ]
        for worker in self._confirmation_workers:
            worker.start()

    def enqueue(self, queued_settlement: _QueuedSettlement) -> _BatchResult:
        with self._condition:
            queue = self._queues.setdefault(queued_settlement.network, [])
            queue.append(queued_settlement)
            if len(queue) == 1:
                self._deadlines[queued_settlement.network] = (
                    time.monotonic() + self._flush_interval_seconds
                )
            elif len(queue) >= self._flush_batch_size:
                self._deadlines[queued_settlement.network] = time.monotonic()
            self._condition.notify_all()

        queued_settlement.completed.wait()
        assert queued_settlement.result is not None
        return queued_settlement.result

    def _run(self) -> None:
        while True:
            with self._condition:
                network, batch = self._wait_for_ready_batch_locked()
            self._flush_batch(network, batch)

    def _wait_for_ready_batch_locked(self) -> tuple[str, list[_QueuedSettlement]]:
        while True:
            now = time.monotonic()
            for network, deadline in list(self._deadlines.items()):
                queue = self._queues.get(network)
                if queue and deadline <= now:
                    batch_size = min(len(queue), self._max_batch_size)
                    batch = queue[:batch_size]
                    del queue[:batch_size]
                    if queue:
                        self._deadlines[network] = (
                            now
                            if len(queue) >= self._flush_batch_size
                            else now + self._flush_interval_seconds
                        )
                        self._condition.notify_all()
                    else:
                        self._queues.pop(network, None)
                        self._deadlines.pop(network, None)
                    return network, batch
            self._condition.wait(timeout=self._next_wait_timeout_locked())

    def _next_wait_timeout_locked(self) -> float | None:
        if not self._deadlines:
            return None
        return max(0.0, min(self._deadlines.values()) - time.monotonic())

    def _flush_batch(self, network: str, batch: list[_QueuedSettlement]) -> None:
        try:
            external_boc = self._signer.build_relay_external_boc_batch(
                network,
                [queued.relay_request for queued in batch],
            )
            trace_external_hash_norm = self._signer.send_external_message(network, external_boc)
        except Exception as exc:
            for queued in batch:
                self._settlement_cache.release(queued.settlement_hash)
            for queued in batch:
                queued.result = _BatchResult(
                    success=False,
                    transaction="",
                    error_reason=(
                        ERR_SIMULATION_FAILED
                        if isinstance(exc, ValueError)
                        else ERR_TRANSACTION_FAILED
                    ),
                    error_message=str(exc),
                )
                queued.completed.set()
            return

        self._confirmation_queue.put(
            _PendingConfirmation(
                network=network,
                batch=batch,
                trace_external_hash_norm=trace_external_hash_norm,
            )
        )

    def _run_confirmation_worker(self) -> None:
        while True:
            pending = self._confirmation_queue.get()
            try:
                finalized_trace = self._signer.wait_for_trace_confirmation(
                    pending.network,
                    pending.trace_external_hash_norm,
                    timeout_seconds=self._confirmation_timeout_seconds,
                )
            except Exception as exc:
                for queued in pending.batch:
                    self._settlement_cache.release(queued.settlement_hash)
                    queued.result = _BatchResult(
                        success=False,
                        transaction="",
                        error_reason=(
                            ERR_SIMULATION_FAILED
                            if isinstance(exc, ValueError)
                            else ERR_TRANSACTION_FAILED
                        ),
                        error_message=str(exc),
                    )
                    queued.completed.set()
                continue

            for queued in pending.batch:
                try:
                    transaction_hash = ExactTvmScheme._verify_finalized_trace_settlement(
                        finalized_trace,
                        settlement=queued.settlement,
                    )
                    queued.result = _BatchResult(
                        success=True,
                        transaction=transaction_hash,
                    )
                except Exception as exc:
                    self._settlement_cache.release(queued.settlement_hash)
                    queued.result = _BatchResult(
                        success=False,
                        transaction="",
                        error_reason=ERR_TRANSACTION_FAILED,
                        error_message=str(exc),
                    )
                queued.completed.set()


class ExactTvmScheme:
    """TVM facilitator implementation for the Exact payment scheme (V2)."""

    scheme = SCHEME_EXACT
    caip_family = "tvm:*"

    def __init__(
        self,
        signer: FacilitatorTvmSigner,
        settlement_cache: SettlementCache | None = None,
        *,
        batch_flush_interval_seconds: float = DEFAULT_SETTLEMENT_BATCH_FLUSH_INTERVAL_SECONDS,
        batch_max_size: int = DEFAULT_SETTLEMENT_BATCH_FLUSH_SIZE,
        streaming_confirmation_timeout_seconds: float = DEFAULT_STREAMING_CONFIRMATION_TIMEOUT_SECONDS,
    ) -> None:
        self._signer = signer
        self._settlement_cache = settlement_cache or SettlementCache()
        self._batcher = _SettlementBatcher(
            signer,
            self._settlement_cache,
            flush_interval_seconds=batch_flush_interval_seconds,
            flush_batch_size=batch_max_size,
            confirmation_timeout_seconds=streaming_confirmation_timeout_seconds,
        )

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
            verification, _ = self._verify(payload, requirements, tvm_payload, settlement)
            return verification
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
        try:
            tvm_payload = ExactTvmPayload.from_dict(payload.payload)
            settlement = parse_exact_tvm_payload(tvm_payload.settlement_boc)
            verification, relay_request = self._verify(
                payload, requirements, tvm_payload, settlement
            )
        except ValueError as e:
            return SettleResponse(
                success=False,
                error_reason=str(e),
                payer="",
                transaction="",
                network=requirements.network,
            )
        except Exception as e:
            return SettleResponse(
                success=False,
                error_reason=ERR_SIMULATION_FAILED,
                error_message=str(e),
                payer="",
                transaction="",
                network=requirements.network,
            )
        if not verification.is_valid:
            return SettleResponse(
                success=False,
                error_reason=verification.invalid_reason,
                error_message=verification.invalid_message,
                payer=verification.payer,
                transaction="",
                network=requirements.network,
            )

        if self._settlement_cache.reserve(
            settlement.settlement_hash, requirements.max_timeout_seconds
        ):
            return SettleResponse(
                success=False,
                error_reason=ERR_DUPLICATE_SETTLEMENT,
                payer=settlement.payer,
                transaction="",
                network=requirements.network,
            )

        try:
            batch_result = self._batcher.enqueue(
                _QueuedSettlement(
                    network=str(requirements.network),
                    settlement_hash=settlement.settlement_hash,
                    settlement=settlement,
                    relay_request=relay_request,
                )
            )
        except Exception as e:
            self._settlement_cache.release(settlement.settlement_hash)
            batch_result = _BatchResult(
                success=False,
                error_reason=ERR_TRANSACTION_FAILED,
                error_message=str(e),
            )

        return SettleResponse(
            success=batch_result.success,
            error_reason=batch_result.error_reason,
            error_message=batch_result.error_message,
            payer=settlement.payer,
            transaction=batch_result.transaction,
            network=requirements.network,
        )

    def _verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
        tvm_payload: ExactTvmPayload,
        settlement: ParsedTvmSettlement,
    ) -> tuple[VerifyResponse, TvmRelayRequest | None]:
        payer = settlement.payer

        def invalid_response(reason: str) -> tuple[VerifyResponse, TvmRelayRequest | None]:
            return (VerifyResponse(is_valid=False, invalid_reason=reason, payer=payer), None)

        if payload.x402_version != 2:
            return invalid_response(ERR_UNSUPPORTED_SCHEME)

        if payload.accepted.scheme != SCHEME_EXACT or requirements.scheme != SCHEME_EXACT:
            return invalid_response(ERR_UNSUPPORTED_SCHEME)

        if str(requirements.network) not in SUPPORTED_NETWORKS:
            return invalid_response(ERR_UNSUPPORTED_NETWORK)

        if str(payload.accepted.network) != str(requirements.network):
            return invalid_response(ERR_NETWORK_MISMATCH)

        if int(payload.accepted.amount) != int(requirements.amount):
            return invalid_response(ERR_INVALID_AMOUNT)

        if normalize_address(payload.accepted.asset) != normalize_address(requirements.asset):
            return invalid_response(ERR_INVALID_ASSET)

        if normalize_address(payload.accepted.pay_to) != normalize_address(requirements.pay_to):
            return invalid_response(ERR_INVALID_RECIPIENT)

        if (
            payload.accepted.extra.get("areFeesSponsored") is not True
            or requirements.extra.get("areFeesSponsored") is not True
        ):
            return invalid_response(ERR_UNSUPPORTED_SCHEME)

        if normalize_address(tvm_payload.asset) != normalize_address(requirements.asset):
            return invalid_response(ERR_INVALID_ASSET)

        expected_response_destination = _effective_response_destination(requirements.extra)
        if _effective_response_destination(payload.accepted.extra) != expected_response_destination:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)

        expected_forward_ton_amount = _effective_forward_ton_amount(requirements.extra)
        if _effective_forward_ton_amount(payload.accepted.extra) != expected_forward_ton_amount:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)

        expected_forward_payload = _effective_forward_payload(requirements.extra)
        if _effective_forward_payload(payload.accepted.extra).hash != expected_forward_payload.hash:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)

        # Up to this point, we've checked all fields in PaymentRequirements and PaymentPayload except for settlementBoc

        if settlement.transfer.destination != normalize_address(requirements.pay_to):
            return invalid_response(ERR_INVALID_RECIPIENT)

        if settlement.transfer.jetton_amount != int(requirements.amount):
            return invalid_response(ERR_INVALID_AMOUNT)

        if settlement.transfer.forward_ton_amount != expected_forward_ton_amount:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)
        if settlement.transfer.response_destination != expected_response_destination:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)
        if settlement.transfer.forward_payload.hash != expected_forward_payload.hash:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)

        now = int(time.time())
        if settlement.valid_until <= now:
            return invalid_response(ERR_INVALID_UNTIL_EXPIRED)
        if settlement.valid_until > now + requirements.max_timeout_seconds:
            return invalid_response(ERR_VALID_UNTIL_TOO_FAR)

        account = self._signer.get_account_state(payer, str(requirements.network))
        init_data_parsed: W5InitData

        if settlement.state_init is not None and account.is_uninitialized:
            if (
                settlement.state_init.code is None
                or settlement.state_init.code.hash.hex() != W5R1_CODE_HASH
            ):
                return invalid_response(ERR_INVALID_CODE_HASH)
            payer_workchain = int(payer.split(":", 1)[0])
            if address_from_state_init(settlement.state_init, payer_workchain) != payer:
                return invalid_response(ERR_INVALID_W5_MESSAGE)
            init_data_parsed = parse_w5_init_data(settlement.state_init)
            if init_data_parsed.seqno != 0:
                return invalid_response(ERR_INVALID_SEQNO)
            if init_data_parsed.extensions_dict:
                return invalid_response(ERR_INVALID_EXTENSIONS_DICT)
        else:
            try:
                init_data_parsed = parse_active_w5_account_state(account)
            except RuntimeError:
                return invalid_response(ERR_INVALID_CODE_HASH)

        if not init_data_parsed.signature_allowed:
            return invalid_response(ERR_INVALID_SIGNATURE_MODE)
        if init_data_parsed.seqno != settlement.seqno:
            return invalid_response(ERR_INVALID_SEQNO)
        if init_data_parsed.wallet_id != settlement.wallet_id:
            return invalid_response(ERR_INVALID_WALLET_ID)

        if not verify_w5_signature(
            init_data_parsed.public_key,
            settlement.signed_slice_hash,
            settlement.signature,
        ):
            return invalid_response(ERR_INVALID_SIGNATURE)

        canonical_source_wallet = normalize_address(
            self._signer.get_jetton_wallet(
                requirements.asset,
                payer,
                str(requirements.network),
            )
        )
        if normalize_address(settlement.transfer.source_wallet) != canonical_source_wallet:
            return invalid_response(ERR_INVALID_JETTON_TRANSFER)

        jetton_wallet_data = self._signer.get_jetton_wallet_data(
            settlement.transfer.source_wallet,
            str(requirements.network),
        )
        if normalize_address(jetton_wallet_data.owner) != payer:
            return invalid_response(ERR_INVALID_RECIPIENT)
        if normalize_address(jetton_wallet_data.jetton_minter) != normalize_address(
            requirements.asset
        ):
            return invalid_response(ERR_INVALID_ASSET)
        if jetton_wallet_data.balance < settlement.transfer.jetton_amount:
            return invalid_response(ERR_INSUFFICIENT_BALANCE)

        try:
            provisional_relay_request = TvmRelayRequest(
                destination=settlement.payer,
                body=settlement.body,
                state_init=settlement.state_init,
                forward_ton_amount=settlement.transfer.forward_ton_amount,
            )
            external_boc = self._signer.build_relay_external_boc(
                requirements.network,
                provisional_relay_request,
                for_emulation=True,
            )
            emulation = self._signer.emulate_external_message(requirements.network, external_boc)
            payer_transaction = self._verify_finalized_trace_settlement(
                emulation,
                settlement=settlement,
                return_transaction=True,
            )
            actual_inner = settlement.transfer.attached_ton_amount
            required_outer = (
                actual_inner
                + trace_transaction_storage_fees(payer_transaction)
                + trace_transaction_compute_fees(payer_transaction)
                + trace_transaction_fwd_fees(payer_transaction)
                + DEFAULT_TVM_OUTER_GAS_BUFFER
            )
            relay_request = TvmRelayRequest(
                destination=settlement.payer,
                body=settlement.body,
                state_init=settlement.state_init,
                forward_ton_amount=settlement.transfer.forward_ton_amount,
                relay_amount=required_outer,
            )
        except Exception as e:
            return (
                VerifyResponse(
                    is_valid=False,
                    invalid_reason=ERR_SIMULATION_FAILED,
                    invalid_message=str(e),
                    payer=payer,
                ),
                None,
            )

        return (VerifyResponse(is_valid=True, payer=payer), relay_request)

    @staticmethod
    def _verify_finalized_trace_settlement(
        trace_data: dict[str, object],
        *,
        settlement: ParsedTvmSettlement,
        return_transaction: bool = False,
    ) -> str | dict[str, object]:
        transactions = parse_trace_transactions(trace_data)
        expected_source_wallet = normalize_address(settlement.transfer.source_wallet)

        payer_transaction = None
        for transaction in transactions:
            if normalize_address(str(transaction.get("account"))) != settlement.payer:
                continue
            if not transaction_succeeded(transaction):
                continue
            in_msg: dict = transaction.get("in_msg")
            if not message_body_hash_matches(in_msg, settlement.body.hash):
                continue
            payer_transaction = transaction
            break
        if payer_transaction is None:
            raise ValueError("Trace does not contain the expected payer wallet transaction")

        out_msgs: list[dict] = payer_transaction.get("out_msgs")
        payer_out_hash = None
        for out_msg in out_msgs:
            if normalize_address(str(out_msg.get("destination"))) != expected_source_wallet:
                continue
            if not message_body_hash_matches(out_msg, settlement.transfer.body_hash):
                continue
            payer_out_hash = out_msg["hash"]
            break
        if payer_out_hash is None:
            raise ValueError("Trace payer wallet transaction is missing out message hash")

        # According to TEP-74, it is sufficient to check the success of the transaction on the payer's jetton wallet
        source_wallet_transaction = None
        for transaction in transactions:
            if normalize_address(str(transaction.get("account"))) != expected_source_wallet:
                continue
            if not transaction_succeeded(transaction):
                continue
            in_msg: dict = transaction.get("in_msg")
            if not in_msg:
                continue
            if in_msg.get("hash") == payer_out_hash:
                source_wallet_transaction = transaction
                break
        if source_wallet_transaction is None:
            raise ValueError("Trace does not contain the expected source jetton wallet transaction")

        transaction_hash = payer_transaction.get("hash")
        if not isinstance(transaction_hash, str) or not transaction_hash:
            raise ValueError("Trace payer wallet transaction is missing transaction hash")
        return payer_transaction if return_transaction else transaction_hash
