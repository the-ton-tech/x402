"""Shared TVM codec helpers that are not wallet-contract specific."""

from __future__ import annotations

import base64
import re
from decimal import Decimal

try:
    from pytoniq_core import Address, Builder
except ImportError as e:
    raise ImportError(
        "TVM mechanism requires pytoniq packages. Install with: pip install x402[tvm]"
    ) from e


def normalize_address(address: str | Address) -> str:
    """Normalize a TVM address to raw ``wc:hex`` form."""
    if isinstance(address, Address):
        return address.to_str(is_user_friendly=False)
    return Address(address).to_str(is_user_friendly=False)


def address_to_stack_item(address: str) -> object:
    """Serialize an address for the Toncenter getter stack."""
    cell = Builder().store_address(Address(address)).end_cell()
    return {
        "type": "slice",
        "value": base64.b64encode(cell.to_boc()).decode("utf-8"),
    }


def get_network_global_id(network: str) -> int:
    """Extract the TVM global network ID from a CAIP-2 network string."""
    if not network.startswith("tvm:"):
        raise ValueError(f"Unsupported TVM network: {network}")
    return int(network.split(":", 1)[1])


def parse_amount(amount: str, decimals: int) -> int:
    """Convert decimal string to smallest unit."""
    return int(Decimal(amount) * Decimal(10**decimals))


def parse_money_to_decimal(money: str | float | int) -> float:
    """Parse Money into a decimal float."""
    if isinstance(money, int | float):
        return float(money)

    clean = money.strip()
    clean = clean.lstrip("$")
    clean = re.sub(r"\s*(USD|USDT|usd|usdt)\s*$", "", clean)
    return float(clean.strip())
