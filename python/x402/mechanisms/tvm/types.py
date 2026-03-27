"""TVM-specific payload and parsed data types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from pytoniq_core import Cell
    from pytoniq_core.tlb.account import StateInit
except ImportError as e:
    raise ImportError(
        "TVM mechanism requires pytoniq packages. Install with: pip install x402[tvm]"
    ) from e


@dataclass
class ExactTvmPayload:
    """Exact payment payload for TVM networks."""

    settlement_boc: str
    asset: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "settlementBoc": self.settlement_boc,
            "asset": self.asset,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExactTvmPayload:
        """Create from dictionary."""
        return cls(
            settlement_boc=data.get("settlementBoc", ""),
            asset=data.get("asset", ""),
        )


@dataclass
class ParsedJettonTransfer:
    """Jetton transfer extracted from a W5 action."""

    source_wallet: str
    destination: str
    response_destination: str
    jetton_amount: int
    forward_ton_amount: int
    forward_payload: Cell


@dataclass
class ParsedTvmSettlement:
    """Parsed TON settlement payload."""

    payer: str
    wallet_id: int
    valid_until: int
    seqno: int
    settlement_hash: str
    body: Cell
    signed_slice_hash: bytes
    signature: bytes
    state_init: StateInit | None
    transfer: ParsedJettonTransfer


@dataclass
class TvmAccountState:
    """Subset of account state needed by the facilitator."""

    address: str
    balance: int
    is_active: bool
    is_uninitialized: bool
    state_init: StateInit | None
    last_transaction_lt: int | None


@dataclass
class TvmJettonWalletData:
    """Data returned by TEP-74 get_wallet_data()."""

    address: str
    balance: int
    owner: str
    jetton_minter: str
    wallet_code: Cell



@dataclass
class W5InitData:
    signature_allowed: bool
    seqno: int
    wallet_id: int
    public_key: bytes
    extensions_dict: Cell | None
