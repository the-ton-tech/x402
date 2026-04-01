"""Tests for TVM mechanism exports and utility functions."""

import pytest

pytest.importorskip("pytoniq_core")

from x402.mechanisms.tvm import (
    SCHEME_EXACT,
    SUPPORTED_NETWORKS,
    TVM_MAINNET,
    TVM_TESTNET,
    ClientTvmSigner,
    ExactTvmPayload,
    FacilitatorHighloadV3Signer,
    FacilitatorTvmSigner,
    SettlementCache,
    ToncenterV3Client,
    WalletV5R1MnemonicSigner,
    get_network_global_id,
    normalize_address,
    parse_amount,
    parse_money_to_decimal,
)
from x402.mechanisms.tvm.exact import (
    ExactTvmClientScheme,
    ExactTvmFacilitatorScheme,
    ExactTvmScheme,
    ExactTvmServerScheme,
)


class TestExports:
    """Test that main classes and constants are exported."""

    def test_should_export_main_classes(self):
        """Should export main scheme classes."""
        assert ExactTvmScheme is not None
        assert ExactTvmClientScheme is not None
        assert ExactTvmServerScheme is not None
        assert ExactTvmFacilitatorScheme is not None

    def test_should_export_signer_protocols(self):
        """Should export signer protocol classes."""
        assert ClientTvmSigner is not None
        assert FacilitatorTvmSigner is not None

    def test_should_export_signer_implementations(self):
        """Should export signer implementation classes."""
        assert WalletV5R1MnemonicSigner is not None
        assert FacilitatorHighloadV3Signer is not None

    def test_should_export_provider_and_payload_types(self):
        """Should export provider and payload types."""
        assert ToncenterV3Client is not None
        assert ExactTvmPayload is not None
        assert SettlementCache is not None


class TestNormalizeAddress:
    """Test normalize_address function."""

    def test_should_preserve_raw_tvm_address(self):
        """Should keep already-normalized raw TVM addresses intact."""
        raw = "0:" + "1" * 64

        assert normalize_address(raw) == raw


class TestNetworkUtilities:
    """Test TVM network helper functions."""

    def test_should_export_supported_networks(self):
        """Should export the supported TVM CAIP-2 networks."""
        assert TVM_MAINNET in SUPPORTED_NETWORKS
        assert TVM_TESTNET in SUPPORTED_NETWORKS

    def test_should_extract_global_id_from_caip2_network(self):
        """Should extract the signed global network id from CAIP-2."""
        assert get_network_global_id(TVM_MAINNET) == -239
        assert get_network_global_id(TVM_TESTNET) == -3

    def test_should_export_scheme_exact(self):
        """Should export the exact scheme identifier."""
        assert SCHEME_EXACT == "exact"


class TestAmountUtilities:
    """Test TVM amount helpers."""

    def test_should_parse_amount_using_decimals(self):
        """Should convert decimal strings into atomic units."""
        assert parse_amount("0.001", 6) == 1000
        assert parse_amount("1", 6) == 1000000

    def test_should_parse_money_strings_without_currency_noise(self):
        """Should parse money-like strings into decimal floats."""
        assert parse_money_to_decimal("$0.10") == 0.1
        assert parse_money_to_decimal("2.5 USDT") == 2.5
