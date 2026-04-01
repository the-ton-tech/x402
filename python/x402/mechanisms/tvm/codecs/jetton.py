"""Jetton-specific TVM payload decoding."""

from __future__ import annotations

from ..constants import ERR_INVALID_JETTON_TRANSFER, JETTON_TRANSFER_OPCODE
from ..types import ParsedJettonTransfer
from .common import normalize_address

try:
    from pytoniq_core import Cell
except ImportError as e:
    raise ImportError(
        "TVM mechanism requires pytoniq packages. Install with: pip install x402[tvm]"
    ) from e


def parse_jetton_transfer(jetton_wallet: str, body: Cell) -> ParsedJettonTransfer:
    """
    Parse a TEP-74 `transfer` body:
    transfer#0f8a7ea5 query_id:uint64 amount:(VarUInteger 16) destination:MsgAddress
                 response_destination:MsgAddress custom_payload:(Maybe ^Cell)
                 forward_ton_amount:(VarUInteger 16) forward_payload:(Either Cell ^Cell)
                 = InternalMsgBody;
    """
    body_slice = body.begin_parse()

    opcode = body_slice.load_uint(32)
    if opcode != JETTON_TRANSFER_OPCODE:
        raise ValueError(ERR_INVALID_JETTON_TRANSFER)

    body_slice.load_uint(64)
    amount = body_slice.load_coins()
    destination = body_slice.load_address()
    if destination is None:
        raise ValueError(ERR_INVALID_JETTON_TRANSFER)

    response_destination = body_slice.load_address()

    if body_slice.load_bit():
        raise ValueError(ERR_INVALID_JETTON_TRANSFER)
    forward_ton_amount = body_slice.load_coins()
    forward_payload = body_slice.load_ref() if body_slice.load_bit() else body_slice.to_cell()

    return ParsedJettonTransfer(
        source_wallet=jetton_wallet,
        destination=normalize_address(destination),
        response_destination=(
            normalize_address(response_destination) if response_destination else None
        ),
        jetton_amount=amount,
        attached_ton_amount=0,
        forward_ton_amount=forward_ton_amount,
        forward_payload=forward_payload,
        body_hash=body.hash,
    )
