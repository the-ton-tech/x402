"""Tests for TVM signer implementations."""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("pytoniq_core")

from pytoniq_core.crypto.keys import mnemonic_to_wallet_key

from x402.mechanisms.tvm import TVM_MAINNET, TVM_TESTNET
from x402.mechanisms.tvm.signers import (
    FacilitatorHighloadV3Signer,
    HighloadV3Config,
    WalletV5R1Config,
    WalletV5R1MnemonicSigner,
)

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


class TestWalletV5R1Config:
    @pytest.mark.parametrize(
        ("private_key", "factory"),
        [
            pytest.param(
                lambda secret_key, seed: secret_key.hex(),
                lambda private_key: WalletV5R1Config.from_private_key(TVM_TESTNET, private_key),
                id="hex-64",
            ),
            pytest.param(
                lambda secret_key, seed: seed.hex(),
                lambda private_key: WalletV5R1Config.from_private_key(TVM_TESTNET, private_key),
                id="hex-32",
            ),
            pytest.param(
                lambda secret_key, seed: base64.b64encode(secret_key).decode(),
                lambda private_key: WalletV5R1Config.from_private_key(TVM_TESTNET, private_key),
                id="base64-64",
            ),
            pytest.param(
                lambda secret_key, seed: base64.b64encode(seed).decode(),
                lambda private_key: WalletV5R1Config.from_private_key(TVM_TESTNET, private_key),
                id="base64-32",
            ),
        ],
    )
    def test_from_private_key_should_accept_hex_and_base64_seed_or_secret_key(
        self, private_key, factory
    ):
        _, secret_key = mnemonic_to_wallet_key(MNEMONIC.split())
        seed = secret_key[:32]

        config = factory(private_key(secret_key, seed))

        assert config.secret_key == secret_key
        assert config.network == TVM_TESTNET

    def test_from_private_key_should_reject_invalid_input(self):
        with pytest.raises(ValueError, match="valid hex or base64"):
            WalletV5R1Config.from_private_key(TVM_TESTNET, "not-a-key")


class TestWalletV5R1MnemonicSigner:
    def test_should_expose_network_wallet_id_state_init_and_address(self):
        config = WalletV5R1Config.from_mnemonic(TVM_TESTNET, MNEMONIC)

        signer = WalletV5R1MnemonicSigner(config)

        assert signer.network == TVM_TESTNET
        assert signer.wallet_id > 0
        assert signer.state_init is not None
        assert signer.address.startswith("0:")
        assert len(signer.address) == 66

    def test_sign_message_should_return_ed25519_signature(self):
        config = WalletV5R1Config.from_mnemonic(TVM_TESTNET, MNEMONIC)
        signer = WalletV5R1MnemonicSigner(config)

        signature = signer.sign_message(b"message-hash")

        assert isinstance(signature, bytes)
        assert len(signature) == 64


class TestHighloadV3Config:
    @pytest.mark.parametrize(
        ("private_key", "factory"),
        [
            pytest.param(
                lambda secret_key, seed: secret_key.hex(),
                lambda private_key: HighloadV3Config.from_private_key(private_key),
                id="hex-64",
            ),
            pytest.param(
                lambda secret_key, seed: seed.hex(),
                lambda private_key: HighloadV3Config.from_private_key(private_key),
                id="hex-32",
            ),
        ],
    )
    def test_from_private_key_should_accept_hex_seed_or_secret_key(self, private_key, factory):
        _, secret_key = mnemonic_to_wallet_key(MNEMONIC.split())
        seed = secret_key[:32]

        config = factory(private_key(secret_key, seed))

        assert config.secret_key == secret_key


class TestFacilitatorHighloadV3Signer:
    def test_get_addresses_for_network_should_return_only_requested_wallet(self):
        _, secret_key = mnemonic_to_wallet_key(MNEMONIC.split())
        signer = FacilitatorHighloadV3Signer(
            {
                TVM_TESTNET: HighloadV3Config(secret_key=secret_key, subwallet_id=1),
                TVM_MAINNET: HighloadV3Config(secret_key=secret_key, subwallet_id=2),
            }
        )

        testnet_addresses = signer.get_addresses_for_network(TVM_TESTNET)
        mainnet_addresses = signer.get_addresses_for_network(TVM_MAINNET)

        assert len(testnet_addresses) == 1
        assert len(mainnet_addresses) == 1
        assert testnet_addresses != mainnet_addresses
        assert signer.get_addresses() == testnet_addresses + mainnet_addresses

    def test_wait_for_trace_confirmation_fetches_full_trace_after_stream_signal(self, monkeypatch):
        _, secret_key = mnemonic_to_wallet_key(MNEMONIC.split())
        signer = FacilitatorHighloadV3Signer(
            {
                TVM_TESTNET: HighloadV3Config(
                    secret_key=secret_key,
                )
            }
        )
        stream_calls: list[tuple[str, float]] = []
        trace_calls: list[str] = []
        expected_trace = {
            "trace_id": "trace-id-1",
            "transactions": {
                "tx-1": {
                    "account": "0:" + "1" * 64,
                }
            },
        }

        class _FakeStreamingClient:
            def wait_for_trace_confirmation(
                self, *, trace_external_hash_norm: str, timeout_seconds: float
            ):
                stream_calls.append((trace_external_hash_norm, timeout_seconds))
                return {
                    "type": "transactions",
                    "finality": "finalized",
                    "trace_external_hash_norm": trace_external_hash_norm,
                }

        class _FakeProviderClient:
            def get_trace_by_message_hash(self, trace_external_hash_norm: str):
                trace_calls.append(trace_external_hash_norm)
                return expected_trace

        monkeypatch.setattr(signer, "_ensure_streaming_watcher", lambda network: True)
        monkeypatch.setattr(signer, "_streaming_client", lambda network: _FakeStreamingClient())
        monkeypatch.setattr(signer, "_client", lambda network: _FakeProviderClient())

        result = signer.wait_for_trace_confirmation(
            TVM_TESTNET,
            "trace-hash-1",
            timeout_seconds=12.5,
        )

        assert len(stream_calls) == 1
        assert stream_calls[0][0] == "trace-hash-1"
        assert stream_calls[0][1] == pytest.approx(12.5, abs=0.1)
        assert trace_calls == ["trace-hash-1"]
        assert result == expected_trace
