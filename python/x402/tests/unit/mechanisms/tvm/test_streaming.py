"""Tests for TVM streaming trace confirmation."""

from __future__ import annotations

import threading

import pytest

pytest.importorskip("pytoniq_core")

from x402.mechanisms.tvm.streaming import ToncenterStreamingSseClient

TRACE_HASH = "trace-hash-1"
FACILITATOR_ADDRESS = "0:" + "1" * 64


def test_wait_for_trace_confirmation_returns_finalized_trace_payload():
    client = ToncenterStreamingSseClient(base_url="https://toncenter.example")
    client._watcher = object()  # type: ignore[assignment]

    result_holder: dict[str, object] = {}

    def wait_for_trace() -> None:
        result_holder["trace"] = client.wait_for_trace_confirmation(
            trace_external_hash_norm=TRACE_HASH,
            timeout_seconds=1.0,
        )

    waiter = threading.Thread(target=wait_for_trace)
    waiter.start()
    client._handle_stream_event(
        {
            "type": "trace",
            "finality": "finalized",
            "trace_external_hash_norm": TRACE_HASH,
            "actions": [],
        },
        normalized_address=FACILITATOR_ADDRESS,
        on_invalidate=lambda: None,
        on_subscribed=lambda: None,
    )
    waiter.join(timeout=1.0)

    assert waiter.is_alive() is False
    assert result_holder["trace"] == {
        "type": "trace",
        "finality": "finalized",
        "trace_external_hash_norm": TRACE_HASH,
        "actions": [],
    }


def test_wait_for_trace_confirmation_raises_for_invalidated_trace():
    client = ToncenterStreamingSseClient(base_url="https://toncenter.example")
    client._watcher = object()  # type: ignore[assignment]
    client._handle_stream_event(
        {
            "type": "trace_invalidated",
            "trace_external_hash_norm": TRACE_HASH,
        },
        normalized_address=FACILITATOR_ADDRESS,
        on_invalidate=lambda: None,
        on_subscribed=lambda: None,
    )

    with pytest.raises(RuntimeError, match="invalidated before confirmation"):
        client.wait_for_trace_confirmation(
            trace_external_hash_norm=TRACE_HASH,
            timeout_seconds=0.1,
        )
