"""TVM client implementation for the Exact payment scheme (V2)."""

from __future__ import annotations

import base64
import time
from typing import Any

from ....schemas import PaymentRequirements
from ..codecs.common import decode_base64_boc, normalize_address
from ..codecs.w5 import get_w5_seqno, serialize_out_list, serialize_send_msg_action
from ..constants import (
    DEFAULT_JETTON_WALLET_MESSAGE_AMOUNT,
    DEFAULT_TONCENTER_TIMEOUT_SECONDS,
    DEFAULT_TVM_INNER_GAS_BUFFER,
    JETTON_TRANSFER_OPCODE,
    SCHEME_EXACT,
    SEND_MODE_PAY_FEES_SEPARATELY,
    SUPPORTED_NETWORKS,
    W5_EXTERNAL_SIGNED_OPCODE,
    W5_INTERNAL_SIGNED_OPCODE,
)
from ..provider import ToncenterV3Client
from ..signer import ClientTvmSigner
from ..trace_utils import (
    parse_trace_transactions,
    trace_transaction_balance_before,
    trace_transaction_compute_fees,
    trace_transaction_fwd_fees,
    trace_transaction_storage_fees,
    transaction_succeeded,
)
from ..types import ExactTvmPayload

try:
    from pytoniq.contract.contract import Contract
    from pytoniq_core import Address, Cell, begin_cell
except ImportError as e:
    raise ImportError(
        "TVM mechanism requires pytoniq packages. Install with: pip install x402[tvm]"
    ) from e


class ExactTvmScheme:
    """TVM client implementation for the Exact payment scheme (V2)."""

    scheme = SCHEME_EXACT

    def __init__(self, signer: ClientTvmSigner) -> None:
        self._signer = signer
        self._clients: dict[str, ToncenterV3Client] = {}

    def create_payment_payload(
        self,
        requirements: PaymentRequirements,
    ) -> dict[str, Any]:
        """Create a signed TON exact payment payload."""
        network = str(requirements.network)
        if network not in SUPPORTED_NETWORKS:
            raise ValueError(f"Unsupported TVM network: {network}")
        if network != self._signer.network:
            raise ValueError(
                f"Signer network {self._signer.network} does not match requirements network {network}"
            )
        if requirements.extra.get("areFeesSponsored") is not True:
            raise ValueError("Exact TVM scheme requires extra.areFeesSponsored to be true")

        client = self._get_client(network)
        payer = normalize_address(self._signer.address)
        asset = normalize_address(requirements.asset)
        source_wallet = self._get_jetton_wallet(client, asset, payer)

        account = client.get_account_state(payer)
        include_state_init = not account.is_active
        seqno = get_w5_seqno(account)
        valid_until = int(time.time()) + (
            requirements.max_timeout_seconds - 5
            if requirements.max_timeout_seconds > 10
            else requirements.max_timeout_seconds // 2
        )
        transfer_body = self._build_transfer_body(requirements)
        required_inner = self._estimate_required_inner_value(
            client=client,
            source_wallet=source_wallet,
            requirements=requirements,
            seqno=seqno,
            valid_until=valid_until,
            transfer_body=transfer_body,
            include_state_init=include_state_init,
        )

        signed_body = self._build_signed_body(
            source_wallet=source_wallet,
            transfer_body=transfer_body,
            seqno=seqno,
            valid_until=valid_until,
            attached_amount=required_inner,
        )
        settlement_boc = self._build_settlement_boc(payer, signed_body, include_state_init)

        return ExactTvmPayload(
            settlement_boc=settlement_boc,
            asset=asset,
        ).to_dict()

    def _get_client(self, network: str) -> ToncenterV3Client:
        if network not in self._clients:
            self._clients[network] = ToncenterV3Client(
                network,
                api_key=getattr(self._signer, "api_key", None),
                base_url=getattr(self._signer, "base_url", None),
                timeout=getattr(
                    self._signer,
                    "toncenter_timeout_seconds",
                    DEFAULT_TONCENTER_TIMEOUT_SECONDS,
                ),
            )
        return self._clients[network]

    def _get_jetton_wallet(self, client: ToncenterV3Client, asset: str, payer: str) -> str:
        return client.get_jetton_wallet(asset, payer)

    def _build_signed_body(
        self,
        *,
        source_wallet: str,
        transfer_body: Cell,
        seqno: int,
        valid_until: int,
        attached_amount: int,
        opcode: int = W5_INTERNAL_SIGNED_OPCODE,
    ) -> Cell:
        out_msg = Contract.create_internal_msg(
            src=None,
            dest=Address(source_wallet),
            bounce=True,
            value=attached_amount,
            body=transfer_body,
        ).serialize()

        actions = serialize_out_list(
            [serialize_send_msg_action(out_msg, SEND_MODE_PAY_FEES_SEPARATELY)]
        )
        unsigned_body = (
            begin_cell()
            .store_uint(opcode, 32)
            .store_uint(self._signer.wallet_id, 32)
            .store_uint(valid_until, 32)
            .store_uint(seqno, 32)
            .store_maybe_ref(actions)
            .store_bit(0)  # extra actions
            .end_cell()
        )
        signature = self._signer.sign_message(unsigned_body.hash)
        return (
            begin_cell().store_slice(unsigned_body.begin_parse()).store_bytes(signature).end_cell()
        )

    def _build_settlement_boc(self, payer: str, body: Cell, include_state_init: bool) -> str:
        message = Contract.create_internal_msg(
            src=None,
            dest=Address(payer),
            bounce=True,
            value=0,
            state_init=self._signer.state_init if include_state_init else None,
            body=body,
        )
        return base64.b64encode(message.serialize().to_boc()).decode("utf-8")

    def _build_transfer_body(self, requirements: PaymentRequirements) -> Cell:
        forward_ton_amount = int(requirements.extra.get("forwardTonAmount", 0))
        if forward_ton_amount < 0 or forward_ton_amount > 10**9:
            raise ValueError("Forward ton amount should be in range of [0, 1e9]")
        response_destination = requirements.extra.get("responseDestination")

        transfer_body = (
            begin_cell()
            .store_uint(JETTON_TRANSFER_OPCODE, 32)
            .store_uint(0, 64)
            .store_coins(int(requirements.amount))
            .store_address(Address(requirements.pay_to))
            .store_address(response_destination)
            .store_bit(0)
            .store_coins(forward_ton_amount)
        )
        encoded_forward_payload = requirements.extra.get("forwardPayload")
        if encoded_forward_payload is None:
            transfer_body = transfer_body.store_uint(0, 2)
        else:
            forward_payload = decode_base64_boc(encoded_forward_payload)
            transfer_body = transfer_body.store_maybe_ref(forward_payload)
        return transfer_body.end_cell()

    def _estimate_required_inner_value(
        self,
        *,
        client: ToncenterV3Client,
        source_wallet: str,
        requirements: PaymentRequirements,
        seqno: int,
        valid_until: int,
        transfer_body: Cell,
        include_state_init: bool,
    ) -> int:
        forward_ton_amount = int(requirements.extra.get("forwardTonAmount", 0))
        provisional_value = DEFAULT_JETTON_WALLET_MESSAGE_AMOUNT + forward_ton_amount
        external_body = self._build_signed_body(
            source_wallet=source_wallet,
            transfer_body=transfer_body,
            seqno=seqno,
            valid_until=valid_until,
            attached_amount=provisional_value,
            opcode=W5_EXTERNAL_SIGNED_OPCODE,
        )
        external_message = Contract.create_external_msg(
            dest=Address(self._signer.address),
            state_init=self._signer.state_init if include_state_init else None,
            body=external_body,
        )
        trace = client.emulate_trace(external_message.serialize().to_boc())
        transactions = parse_trace_transactions(trace)

        source_wallet_tx = None
        for transaction in transactions:
            if normalize_address(str(transaction.get("account"))) != normalize_address(
                source_wallet
            ):
                continue
            if not transaction_succeeded(transaction):
                continue
            in_msg = transaction.get("in_msg") or {}
            if in_msg.get("decoded_opcode") == "jetton_transfer" and normalize_address(
                str(in_msg.get("source"))
            ) == normalize_address(self._signer.address):
                source_wallet_tx = transaction
                break
        if source_wallet_tx is None:
            raise ValueError("Trace does not contain the expected source jetton wallet transaction")

        receiver_wallet_tx = None
        for transaction in transactions:
            if not transaction_succeeded(transaction):
                continue
            in_msg = transaction.get("in_msg") or {}
            if in_msg.get("decoded_opcode") == "jetton_internal_transfer" and normalize_address(
                str(in_msg.get("source"))
            ) == normalize_address(source_wallet):
                receiver_wallet_tx = transaction
                break
        if receiver_wallet_tx is None:
            raise ValueError(
                "Trace does not contain the expected destination jetton wallet transaction"
            )

        source_wallet_balance = trace_transaction_balance_before(source_wallet_tx)
        forward_fees = trace_transaction_fwd_fees(
            source_wallet_tx,
            expected_count=2 if forward_ton_amount > 0 else 1,
        )
        compute_fee_source = trace_transaction_compute_fees(source_wallet_tx)
        compute_fee_destination = trace_transaction_compute_fees(receiver_wallet_tx)
        storage_fees_source = trace_transaction_storage_fees(source_wallet_tx)

        return max(
            forward_fees * 2,
            DEFAULT_TVM_INNER_GAS_BUFFER
            + forward_fees
            + compute_fee_source
            + compute_fee_destination
            + forward_ton_amount
            + storage_fees_source
            - source_wallet_balance,
        )
