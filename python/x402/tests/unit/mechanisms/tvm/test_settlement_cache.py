"""Tests for the TVM settlement cache."""

import pytest

pytest.importorskip("pytoniq_core")

from x402.mechanisms.tvm.settlement_cache import SettlementCache


def test_reserve_rejects_duplicate_until_released() -> None:
    cache = SettlementCache()

    assert cache.reserve("settlement-1", 300.0) is False
    assert cache.reserve("settlement-1", 300.0) is True

    cache.release("settlement-1")

    assert cache.reserve("settlement-1", 300.0) is False


def test_reserve_prunes_expired_entries() -> None:
    cache = SettlementCache()

    assert cache.reserve("settlement-1", 300.0) is False
    cache.entries["settlement-1"] -= 301.0

    assert cache.reserve("settlement-1", 300.0) is False
