"""Tests for TVM signer orchestration."""

from __future__ import annotations

import pytest

pytest.importorskip("pytoniq_core")

from x402.mechanisms.tvm.constants import TVM_TESTNET
from x402.mechanisms.tvm.signers import FacilitatorHighloadV3Signer, HighloadV3Config

from pytoniq_core.crypto.keys import mnemonic_to_wallet_key


def test_wait_for_trace_confirmation_fetches_full_trace_after_stream_signal(monkeypatch):
    _, secret_key = mnemonic_to_wallet_key(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
    )
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
        def wait_for_trace_confirmation(self, *, trace_external_hash_norm: str, timeout_seconds: float):
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

    monkeypatch.setattr(signer, "_ensure_streaming_watcher", lambda network: None)
    monkeypatch.setattr(signer, "_streaming_client", lambda network: _FakeStreamingClient())
    monkeypatch.setattr(signer, "_client", lambda network: _FakeProviderClient())

    result = signer.wait_for_trace_confirmation(
        TVM_TESTNET,
        "trace-hash-1",
        timeout_seconds=12.5,
    )

    assert stream_calls == [("trace-hash-1", 12.5)]
    assert trace_calls == ["trace-hash-1"]
    assert result == expected_trace
