"""TVM facilitator implementation for the Exact payment scheme (V2)."""

from __future__ import annotations

import base64
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
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
    DEFAULT_SETTLEMENT_BATCH_FLUSH_INTERVAL_SECONDS,
    DEFAULT_SETTLEMENT_BATCH_FLUSH_SIZE,
    DEFAULT_SETTLEMENT_BATCH_MAX_SIZE,
    DEFAULT_STREAMING_CONFIRMATION_TIMEOUT_SECONDS,
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
    transaction: str


class _SettlementBatcher:
    def __init__(
        self,
        signer: FacilitatorTvmSigner,
        *,
        flush_interval_seconds: float,
        flush_batch_size: int,
        confirmation_timeout_seconds: float,
        _delete_settlement_cache: Callable[[str], None],
    ) -> None:
        self._signer = signer
        self._flush_interval_seconds = flush_interval_seconds
        self._flush_batch_size = flush_batch_size
        self._max_batch_size = DEFAULT_SETTLEMENT_BATCH_MAX_SIZE
        self._confirmation_timeout_seconds = confirmation_timeout_seconds
        self._delete_settlement_cache = _delete_settlement_cache
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._confirmation_queue: queue.SimpleQueue[_PendingConfirmation] = queue.SimpleQueue()
        self._queues: dict[str, list[_QueuedSettlement]] = {}
        self._deadlines: dict[str, float] = {}
        self._worker = threading.Thread(target=self._run, name="tvm-settlement-batcher", daemon=True)
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
                self._deadlines[queued_settlement.network] = time.monotonic() + self._flush_interval_seconds
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
                        self._deadlines[network] = now if len(queue) >= self._flush_batch_size else now + self._flush_interval_seconds
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
                self._delete_settlement_cache(queued.settlement_hash)
            for queued in batch:
                queued.result = _BatchResult(
                    success=False,
                    transaction="",
                    error_reason=ERR_SIMULATION_FAILED if isinstance(exc, ValueError) else ERR_TRANSACTION_FAILED,
                    error_message=str(exc),
                )
                queued.completed.set()
            return

        self._confirmation_queue.put(
            _PendingConfirmation(
                network=network,
                batch=batch,
                transaction=trace_external_hash_norm,
            )
        )

    def _run_confirmation_worker(self) -> None:
        while True:
            pending = self._confirmation_queue.get()
            try:
                finalized_trace = self._signer.wait_for_trace_confirmation(
                    pending.network,
                    pending.transaction,
                    timeout_seconds=self._confirmation_timeout_seconds,
                )
            except Exception as exc:
                for queued in pending.batch:
                    self._delete_settlement_cache(queued.settlement_hash)
                    queued.result = _BatchResult(
                        success=False,
                        transaction=pending.transaction,
                        error_reason=ERR_SIMULATION_FAILED if isinstance(exc, ValueError) else ERR_TRANSACTION_FAILED,
                        error_message=str(exc),
                    )
                    queued.completed.set()
                continue

            for queued in pending.batch:
                try:
                    ExactTvmScheme._verify_finalized_trace_settlement(
                        finalized_trace,
                        settlement=queued.settlement,
                    )
                    queued.result = _BatchResult(
                        success=True,
                        transaction=pending.transaction,
                    )
                except Exception as exc:
                    self._delete_settlement_cache(queued.settlement_hash)
                    queued.result = _BatchResult(
                        success=False,
                        transaction=pending.transaction,
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
        *,
        batch_flush_interval_seconds: float = DEFAULT_SETTLEMENT_BATCH_FLUSH_INTERVAL_SECONDS,
        batch_max_size: int = DEFAULT_SETTLEMENT_BATCH_FLUSH_SIZE,
        streaming_confirmation_timeout_seconds: float = DEFAULT_STREAMING_CONFIRMATION_TIMEOUT_SECONDS,
    ) -> None:
        self._signer = signer
        self._settlement_cache: dict[str, float] = {}
        self._lock = threading.Lock()
        self._batcher = _SettlementBatcher(
            signer,
            flush_interval_seconds=batch_flush_interval_seconds,
            flush_batch_size=batch_max_size,
            confirmation_timeout_seconds=streaming_confirmation_timeout_seconds,
            _delete_settlement_cache=self._delete_settlement_cache,
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
        try:
            tvm_payload = ExactTvmPayload.from_dict(payload.payload)
            settlement = parse_exact_tvm_payload(tvm_payload.settlement_boc)
            verification, relay_request = self._verify(payload, requirements, tvm_payload, settlement)
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

        if self._reserve_settlement_cache(settlement, requirements):
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
            self._delete_settlement_cache(settlement.settlement_hash)
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
        if payload.x402_version != 2:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=settlement.payer), None)

        if payload.accepted.scheme != SCHEME_EXACT or requirements.scheme != SCHEME_EXACT:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=settlement.payer), None)

        if str(requirements.network) not in SUPPORTED_NETWORKS:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_NETWORK, payer=settlement.payer), None)

        if str(payload.accepted.network) != str(requirements.network):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_NETWORK_MISMATCH, payer=settlement.payer), None)

        if int(payload.accepted.amount) != int(requirements.amount):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_AMOUNT, payer=settlement.payer), None)

        if normalize_address(payload.accepted.asset) != normalize_address(requirements.asset):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_ASSET, payer=settlement.payer), None)

        if normalize_address(payload.accepted.pay_to) != normalize_address(requirements.pay_to):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_RECIPIENT, payer=settlement.payer), None)

        if payload.accepted.extra.get("areFeesSponsored") is not True or requirements.extra.get("areFeesSponsored") is not True:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_UNSUPPORTED_SCHEME, payer=settlement.payer), None)

        if normalize_address(tvm_payload.asset) != normalize_address(requirements.asset):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_ASSET, payer=settlement.payer), None)

        # Up to this point, we've checked all fields in PaymentRequirements and PaymentPayload except for settlementBoc

        if settlement.transfer.destination != normalize_address(requirements.pay_to):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_RECIPIENT, payer=payer), None)

        if settlement.transfer.jetton_amount != int(requirements.amount):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_AMOUNT, payer=payer), None)
        
        if settlement.transfer.forward_ton_amount > 1 or settlement.transfer.response_destination != normalize_address(requirements.pay_to):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_JETTON_TRANSFER, payer=payer), None)

        now = int(time.time())
        if settlement.valid_until <= now:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_UNTIL_EXPIRED, payer=payer), None)
        if settlement.valid_until > now + requirements.max_timeout_seconds:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_VALID_UNTIL_TOO_FAR, payer=payer), None)

        account = self._signer.get_account_state(payer, str(requirements.network))
        init_data_parsed: W5InitData

        if settlement.state_init is not None and account.is_uninitialized:
            if settlement.state_init.code is None or settlement.state_init.code.hash.hex() != W5R1_CODE_HASH:
                return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_CODE_HASH, payer=payer), None)
            payer_workchain = int(payer.split(":", 1)[0])
            if address_from_state_init(settlement.state_init, payer_workchain) != payer:
                return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_W5_MESSAGE, payer=payer), None)
            init_data_parsed = parse_w5_init_data(settlement.state_init)
            if init_data_parsed.seqno != 0:
                return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SEQNO, payer=payer), None)
            if init_data_parsed.extensions_dict:
                return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_EXTENSIONS_DICT, payer=payer), None)
        else:
            try:
                init_data_parsed = parse_active_w5_account_state(account)
            except RuntimeError:
                return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_CODE_HASH, payer=payer), None)

        if not init_data_parsed.signature_allowed:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SIGNATURE_MODE, payer=payer), None)
        if init_data_parsed.seqno != settlement.seqno:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SEQNO, payer=payer), None)
        if init_data_parsed.wallet_id != settlement.wallet_id:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_WALLET_ID, payer=payer), None)

        if not verify_w5_signature(init_data_parsed.public_key, settlement.signed_slice_hash, settlement.signature):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_SIGNATURE, payer=payer), None)

        canonical_source_wallet = normalize_address(
            self._signer.get_jetton_wallet(
                requirements.asset,
                payer,
                str(requirements.network),
            )
        )
        if normalize_address(settlement.transfer.source_wallet) != canonical_source_wallet:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_JETTON_TRANSFER, payer=payer), None)

        jetton_wallet_data = self._signer.get_jetton_wallet_data(
            settlement.transfer.source_wallet,
            str(requirements.network),
        )
        if normalize_address(jetton_wallet_data.owner) != payer:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_RECIPIENT, payer=payer), None)
        if normalize_address(jetton_wallet_data.jetton_minter) != normalize_address(requirements.asset):
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INVALID_ASSET, payer=payer), None)
        if jetton_wallet_data.balance < settlement.transfer.jetton_amount:
            return (VerifyResponse(is_valid=False, invalid_reason=ERR_INSUFFICIENT_BALANCE, payer=payer), None)

        try:
            relay_request = TvmRelayRequest(
                destination=settlement.payer,
                body=settlement.body,
                state_init=settlement.state_init,
            )
            external_boc = self._signer.build_relay_external_boc(
                requirements.network,
                relay_request,
                for_emulation=True,
            )
            emulation = self._signer.emulate_external_message(requirements.network, external_boc)
            self._verify_finalized_trace_settlement(emulation, settlement=settlement)
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

    def _reserve_settlement_cache(
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

    def _delete_settlement_cache(self, settlement_hash: str) -> None:
        with self._lock:
            self._settlement_cache.pop(settlement_hash, None)

    def _cleanup_expired_settlements(self, requirements: PaymentRequirements) -> None:
        cutoff = time.monotonic() - requirements.max_timeout_seconds
        expired = [key for key, ts in self._settlement_cache.items() if ts < cutoff]
        for key in expired:
            del self._settlement_cache[key]

    @staticmethod
    def _iter_trace_transactions(trace_data: dict[str, object]) -> list[dict[str, object]]:
        transactions = trace_data.get("transactions")
        if not isinstance(transactions, dict):
            raise ValueError("Toncenter trace did not return transactions dict")
        return [tx for tx in transactions.values() if isinstance(tx, dict)]

    @staticmethod
    def _transaction_succeeded(transaction: dict[str, object]) -> bool:
        description = transaction.get("description")
        if not isinstance(description, dict) or description.get("aborted") is True:
            return False

        compute_phase = description.get("compute_ph")
        if not isinstance(compute_phase, dict) or compute_phase.get("skipped") is True or compute_phase.get("success") is not True:
            return False

        action_phase = description.get("action")
        if action_phase is not None and (not isinstance(action_phase, dict) or action_phase.get("success") is not True):
            return False

        return True

    @staticmethod
    def _body_hash(raw_hash: bytes) -> str:
        return base64.b64encode(raw_hash).decode("ascii")

    @staticmethod
    def _message_body_hash_matches(message: dict[str, object], expected_hash: bytes) -> bool:
        message_content = message.get("message_content")
        if not isinstance(message_content, dict):
            return False
        message_hash = message_content.get("hash")
        return isinstance(message_hash, str) and message_hash == ExactTvmScheme._body_hash(expected_hash)

    @staticmethod
    def _verify_finalized_trace_settlement(
        trace_data: dict[str, object],
        *,
        settlement: ParsedTvmSettlement,
    ) -> None:
        transactions = ExactTvmScheme._iter_trace_transactions(trace_data)
        expected_source_wallet = normalize_address(settlement.transfer.source_wallet)

        payer_transaction = None
        for transaction in transactions:
            if normalize_address(str(transaction.get("account"))) != settlement.payer:
                continue
            if not ExactTvmScheme._transaction_succeeded(transaction):
                continue
            in_msg: dict = transaction.get("in_msg")
            if not ExactTvmScheme._message_body_hash_matches(in_msg, settlement.body.hash):
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
            if not ExactTvmScheme._message_body_hash_matches(out_msg, settlement.transfer.body_hash):
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
            if not ExactTvmScheme._transaction_succeeded(transaction):
                continue
            in_msg: dict = transaction.get("in_msg")
            if not in_msg:
                continue
            if in_msg.get("hash") == payer_out_hash:
                source_wallet_transaction = transaction
                break
        if source_wallet_transaction is None:
            raise ValueError("Trace does not contain the expected source jetton wallet transaction")
