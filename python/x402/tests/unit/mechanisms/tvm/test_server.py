"""Tests for TVM exact server price normalization."""

from __future__ import annotations

import base64

from pytoniq_core import begin_cell

from x402.mechanisms.tvm.constants import (
    TVM_MAINNET,
    TVM_TESTNET,
    USDT_MAINNET_MINTER,
    USDT_TESTNET_MINTER,
)
from x402.mechanisms.tvm.exact.server import ExactTvmScheme

EMPTY_FORWARD_PAYLOAD_BOC = base64.b64encode(begin_cell().store_bit(0).end_cell().to_boc()).decode(
    "ascii"
)


def test_parse_price_preserves_atomic_units_without_float_rounding_loss():
    scheme = ExactTvmScheme()

    result = scheme.parse_price("2.01", TVM_MAINNET)

    assert result.amount == "2010000"
    assert result.asset == USDT_MAINNET_MINTER
    assert result.extra == {
        "areFeesSponsored": True,
        "forwardPayload": EMPTY_FORWARD_PAYLOAD_BOC,
        "forwardTonAmount": "0",
    }


def test_parse_price_preserves_large_decimal_amount_without_float_rounding_loss():
    scheme = ExactTvmScheme()

    result = scheme.parse_price("9007199254740.993", TVM_MAINNET)

    assert result.amount == "9007199254740993000"
    assert result.asset == USDT_MAINNET_MINTER
    assert result.extra == {
        "areFeesSponsored": True,
        "forwardPayload": EMPTY_FORWARD_PAYLOAD_BOC,
        "forwardTonAmount": "0",
    }


def test_parse_price_uses_testnet_usdt_as_default_asset():
    scheme = ExactTvmScheme()

    result = scheme.parse_price("$0.001", TVM_TESTNET)

    assert result.amount == "1000"
    assert result.asset == USDT_TESTNET_MINTER
    assert result.extra == {
        "areFeesSponsored": True,
        "forwardPayload": EMPTY_FORWARD_PAYLOAD_BOC,
        "forwardTonAmount": "0",
    }
