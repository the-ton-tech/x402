"""TVM client implementation for the Exact payment scheme (V2)."""

from __future__ import annotations

import base64
import time
from typing import Any

from ....schemas import PaymentRequirements
from ..codecs.common import normalize_address
from ..codecs.w5 import get_w5_seqno, serialize_out_list, serialize_send_msg_action
from ..constants import (
    DEFAULT_JETTON_TRANSFER_AMOUNT,
    DEFAULT_TONCENTER_TIMEOUT_SECONDS,
    JETTON_TRANSFER_OPCODE,
    SCHEME_EXACT,
    SUPPORTED_NETWORKS,
    W5_INTERNAL_SIGNED_OPCODE,
)
from ..provider import ToncenterV3Client
from ..signer import ClientTvmSigner
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

        client = self._get_client(network)
        payer = normalize_address(self._signer.address)
        asset = normalize_address(requirements.asset)
        source_wallet = self._get_jetton_wallet(client, asset, payer)

        account = client.get_account_state(payer)
        include_state_init = not account.is_active
        seqno = get_w5_seqno(account)

        signed_body = self._build_signed_body(
            payer=payer,
            source_wallet=source_wallet,
            requirements=requirements,
            seqno=seqno,
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
        payer: str,
        source_wallet: str,
        requirements: PaymentRequirements,
        seqno: int,
    ) -> Cell:
        transfer_body = (
            begin_cell()
            .store_uint(JETTON_TRANSFER_OPCODE, 32)
            .store_uint(0, 64)
            .store_coins(int(requirements.amount))
            .store_address(Address(normalize_address(requirements.pay_to)))
            .store_address(Address(payer))
            .store_bit(0)
            .store_coins(1)
            .store_bit(0)
            .end_cell()
        )

        out_msg = Contract.create_internal_msg(
            src=None,
            dest=Address(source_wallet),
            bounce=True,
            value=self._get_transfer_amount(requirements),
            body=transfer_body,
        ).serialize()

        actions = serialize_out_list([serialize_send_msg_action(out_msg)])
        unsigned_body = (
            begin_cell()
            .store_uint(W5_INTERNAL_SIGNED_OPCODE, 32)
            .store_uint(self._signer.wallet_id, 32)
            .store_uint(int(time.time()) + requirements.max_timeout_seconds, 32)
            .store_uint(seqno, 32)
            .store_bit(1)
            .store_ref(actions)
            .store_bit(0)
            .end_cell()
        )
        signature = self._signer.sign_message(unsigned_body.hash)
        return begin_cell().store_slice(unsigned_body.begin_parse()).store_bytes(signature).end_cell()

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

    def _get_transfer_amount(self, requirements: PaymentRequirements) -> int:
        extra = requirements.extra or {}
        transfer_amount = extra.get("jettonTransferTonAmount")
        if transfer_amount is None:
            return DEFAULT_JETTON_TRANSFER_AMOUNT
        return int(transfer_amount)
