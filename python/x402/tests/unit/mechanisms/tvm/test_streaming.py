"""Tests for TVM streaming trace confirmation."""

from __future__ import annotations

import queue
import threading
import time

import pytest

pytest.importorskip("pytoniq_core")

import x402.mechanisms.tvm.streaming as streaming_module
from x402.mechanisms.tvm.streaming import ToncenterStreamingSseClient, _account_stream_subscription

TRACE_HASH = "trace-hash-1"
FACILITATOR_ADDRESS = "0:" + "1" * 64


def test_account_stream_subscription_uses_transactions_and_account_state_change():
    assert _account_stream_subscription(FACILITATOR_ADDRESS) == {
        "addresses": [FACILITATOR_ADDRESS],
        "types": ["account_state_change", "transactions"],
        "min_finality": "finalized",
    }


def test_wait_for_trace_confirmation_returns_finalized_trace_payload_from_transactions_event(
    monkeypatch,
):
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
            "type": "transactions",
            "finality": "finalized",
            "trace_external_hash_norm": TRACE_HASH,
            "transactions": [],
        },
        normalized_address=FACILITATOR_ADDRESS,
        on_invalidate=lambda: None,
        on_subscribed=lambda: None,
    )
    waiter.join(timeout=1.0)

    assert waiter.is_alive() is False
    assert result_holder["trace"] == {
        "type": "transactions",
        "finality": "finalized",
        "trace_external_hash_norm": TRACE_HASH,
        "transactions": [],
    }


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
        on_event({"status": "subscribed"})
        on_event(
            {
                "type": "transactions",
                "finality": "finalized",
                "trace_external_hash_norm": TRACE_HASH,
                "transactions": [],
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
            "type": "transactions",
            "finality": "finalized",
            "trace_external_hash_norm": TRACE_HASH,
            "transactions": [],
        }
        assert state["calls"] >= 2
    finally:
        watcher.close()


def test_wait_for_trace_confirmation_fails_after_max_consecutive_stream_failures(monkeypatch):
    client = ToncenterStreamingSseClient(base_url="https://toncenter.example")
    state = {"calls": 0, "invalidations": 0}
    release_first_failure = threading.Event()
    result_holder: dict[str, object] = {}

    monkeypatch.setattr(streaming_module, "DEFAULT_STREAMING_RECONNECT_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(streaming_module, "DEFAULT_STREAMING_MAX_CONSECUTIVE_FAILURES", 2)

    def fake_consume_stream(*, subscription, stop_event, on_event, resources=None):
        _ = subscription, stop_event, resources
        state["calls"] += 1
        if state["calls"] == 1:
            on_event({"status": "subscribed"})
            release_first_failure.wait(timeout=1.0)
            raise RuntimeError("disconnect-1")
        raise RuntimeError("disconnect-2")

    def wait_for_trace() -> None:
        try:
            client.wait_for_trace_confirmation(
                trace_external_hash_norm=TRACE_HASH,
                timeout_seconds=1.0,
            )
        except Exception as exc:  # pragma: no branch - test captures the first terminal result
            result_holder["error"] = exc

    monkeypatch.setattr(client, "_consume_stream", fake_consume_stream)
    watcher = client.start_account_state_watcher(
        address=FACILITATOR_ADDRESS,
        on_invalidate=lambda: state.__setitem__("invalidations", state["invalidations"] + 1),
    )
    try:
        waiter = threading.Thread(target=wait_for_trace)
        waiter.start()
        release_first_failure.set()
        waiter.join(timeout=0.5)

        assert waiter.is_alive() is False
        error = result_holder["error"]
        assert isinstance(error, RuntimeError)
        assert str(error) == (
            "Toncenter facilitator account stream failed before confirmation: disconnect-2"
        )
        assert state["calls"] == 2
        assert state["invalidations"] == 2
    finally:
        watcher.close()


def test_close_stops_watcher_and_fails_pending_waiters():
    client = ToncenterStreamingSseClient(base_url="https://toncenter.example")
    waiter: queue.Queue[dict[str, object] | Exception] = queue.Queue(maxsize=1)
    close_calls: list[str] = []

    class _Watcher:
        def close(self) -> None:
            close_calls.append("closed")

        def is_alive(self) -> bool:
            return True

    client._watcher = _Watcher()  # type: ignore[assignment]
    client._watched_address = FACILITATOR_ADDRESS
    client._pending_trace_waiters[TRACE_HASH] = [waiter]

    client.close()

    result = waiter.get_nowait()
    assert isinstance(result, RuntimeError)
    assert str(result) == "Toncenter facilitator account stream closed"
    assert close_calls == ["closed"]
    assert client._watcher is None
    assert client._watched_address is None
