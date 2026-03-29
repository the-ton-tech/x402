"""Tests for TVM streaming trace confirmation."""

from __future__ import annotations

import threading
import time

import pytest

pytest.importorskip("pytoniq_core")

import x402.mechanisms.tvm.streaming as streaming_module
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


def test_start_account_state_watcher_retries_after_failed_start(monkeypatch):
    client = ToncenterStreamingSseClient(base_url="https://toncenter.example")
    state = {"calls": 0}

    def fake_consume_stream(*, subscription, stop_event, on_event, resources=None):
        _ = subscription, on_event, resources
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("boom")
        on_event({"status": "subscribed"})
        while not stop_event.wait(0.01):
            pass

    monkeypatch.setattr(client, "_consume_stream", fake_consume_stream)

    with pytest.raises(RuntimeError, match="failed to start"):
        client.start_account_state_watcher(
            address=FACILITATOR_ADDRESS,
            on_invalidate=lambda: None,
        )

    watcher = client.start_account_state_watcher(
        address=FACILITATOR_ADDRESS,
        on_invalidate=lambda: None,
    )
    try:
        assert watcher.is_alive() is True
        assert state["calls"] == 2
    finally:
        watcher.close()


def test_wait_for_trace_confirmation_survives_stream_reconnect(monkeypatch):
    client = ToncenterStreamingSseClient(base_url="https://toncenter.example")
    state = {"calls": 0}
    monkeypatch.setattr(streaming_module, "DEFAULT_STREAMING_RECONNECT_BACKOFF_SECONDS", 0.01)

    def fake_consume_stream(*, subscription, stop_event, on_event, resources=None):
        _ = subscription, resources
        state["calls"] += 1
        if state["calls"] == 1:
            on_event({"status": "subscribed"})
            time.sleep(0.05)
            raise RuntimeError("disconnect")
        on_event(
            {
                "type": "trace",
                "finality": "finalized",
                "trace_external_hash_norm": TRACE_HASH,
                "actions": [],
            }
        )
        stop_event.set()

    monkeypatch.setattr(client, "_consume_stream", fake_consume_stream)
    watcher = client.start_account_state_watcher(
        address=FACILITATOR_ADDRESS,
        on_invalidate=lambda: None,
    )
    try:
        result_holder: dict[str, object] = {}

        def wait_for_trace() -> None:
            result_holder["trace"] = client.wait_for_trace_confirmation(
                trace_external_hash_norm=TRACE_HASH,
                timeout_seconds=1.0,
            )

        waiter = threading.Thread(target=wait_for_trace)
        waiter.start()
        waiter.join(timeout=1.0)

        assert waiter.is_alive() is False
        assert result_holder["trace"] == {
            "type": "trace",
            "finality": "finalized",
            "trace_external_hash_norm": TRACE_HASH,
            "actions": [],
        }
        assert state["calls"] >= 2
    finally:
        watcher.close()
