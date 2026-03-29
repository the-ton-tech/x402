"""Unit tests for TVM signer implementations."""

from __future__ import annotations

import time
from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import patch

from nacl.bindings import crypto_sign_seed_keypair
from pytoniq_core import HashMap, begin_cell
from pytoniq_core.tlb.account import StateInit

from x402.mechanisms.tvm.constants import DEFAULT_RELAY_AMOUNT, TVM_MAINNET
from x402.mechanisms.tvm.signers import (
    FacilitatorHighloadV3Signer,
    HighloadV3Config,
    MAX_USABLE_QUERY_SEQNO,
    _seqno_to_query_id,
)
from x402.mechanisms.tvm.types import TvmAccountState, TvmRelayRequest


class FakeToncenterClient:
    def __init__(self) -> None:
        self.sent_messages: list[bytes] = []
        self.emulated_messages: list[bytes] = []

    def send_message(self, boc: bytes) -> str:
        self.sent_messages.append(boc)
        return "external-message-hash"

    def emulate_trace(self, boc: bytes) -> dict[str, object]:
        self.emulated_messages.append(boc)
        return {"ok": True}


def _make_signer(client: FakeToncenterClient) -> FacilitatorHighloadV3Signer:
    _, secret_key = crypto_sign_seed_keypair(b"\x03" * 32)
    signer = FacilitatorHighloadV3Signer(
        {
            TVM_MAINNET: HighloadV3Config(
                secret_key=secret_key,
            )
        }
    )
    signer._clients[TVM_MAINNET] = client  # type: ignore[attr-defined]
    return signer


def _make_highload_state_init(
    signer: FacilitatorHighloadV3Signer,
    *,
    old_processed: set[int] | None = None,
    processed: set[int] | None = None,
    last_clean_time: int | None = None,
) -> StateInit:
    wallet_context = signer._wallets[TVM_MAINNET]  # type: ignore[attr-defined]
    if last_clean_time is None:
        last_clean_time = int(time.time())

    def _serialize_query_dict(query_ids: set[int] | None):
        if not query_ids:
            return None

        grouped: dict[int, set[int]] = defaultdict(set)
        for query_id in query_ids:
            grouped[query_id >> 10].add(query_id & 1023)

        hashmap = HashMap(13, value_serializer=lambda src, dest: dest.store_ref(src))
        for shift, bit_numbers in grouped.items():
            bitmap = begin_cell()
            for bit_number in range(1023):
                bitmap.store_bit(bit_number in bit_numbers)
            hashmap.set_int_key(shift, bitmap.end_cell())
        return hashmap.serialize()

    data = (
        begin_cell()
        .store_bytes(wallet_context.public_key)
        .store_uint(wallet_context.config.subwallet_id, 32)
        .store_maybe_ref(_serialize_query_dict(old_processed))
        .store_maybe_ref(_serialize_query_dict(processed))
        .store_uint(last_clean_time, 64)
        .store_uint(wallet_context.config.timeout, 22)
        .end_cell()
    )
    return StateInit(code=wallet_context.state_init.code, data=data)


def test_build_relay_external_boc_builds_single_request() -> None:
    signer = _make_signer(FakeToncenterClient())
    facilitator_address = signer.get_addresses()[0]
    state_init = _make_highload_state_init(signer)
    signer.get_account_state = lambda address, network: TvmAccountState(  # type: ignore[method-assign]
        address=address,
        balance=0,
        is_active=True,
        is_uninitialized=False,
        state_init=state_init,
        last_transaction_lt=10 if address == facilitator_address else 0,
    )

    external_boc = signer.build_relay_external_boc(
        TVM_MAINNET,
        TvmRelayRequest(
            destination="0:" + "11" * 32,
            body=begin_cell().end_cell(),
            state_init=None,
        ),
    )

    assert isinstance(external_boc, bytes)


def test_build_relay_external_boc_skips_processed_query_ids() -> None:
    client = FakeToncenterClient()
    signer = _make_signer(client)
    facilitator_address = signer.get_addresses()[0]
    signer._query_ids[TVM_MAINNET] = 0  # type: ignore[attr-defined]
    state_init = _make_highload_state_init(signer, processed={0, 1})
    signer.get_account_state = lambda address, network: TvmAccountState(  # type: ignore[method-assign]
        address=address,
        balance=0,
        is_active=True,
        is_uninitialized=False,
        state_init=state_init,
        last_transaction_lt=10 if address == facilitator_address else 0,
    )

    external_boc = signer.build_relay_external_boc(
        TVM_MAINNET,
        TvmRelayRequest(
            destination="0:" + "22" * 32,
            body=begin_cell().end_cell(),
            state_init=None,
        ),
    )

    assert isinstance(external_boc, bytes)
    assert client.sent_messages == []
    assert signer._query_ids[TVM_MAINNET] == 3  # type: ignore[attr-defined]


def test_send_external_message_returns_toncenter_message_hash() -> None:
    client = FakeToncenterClient()
    signer = _make_signer(client)
    facilitator_address = signer.get_addresses()[0]
    state_init = _make_highload_state_init(signer)
    signer.get_account_state = lambda address, network: TvmAccountState(  # type: ignore[method-assign]
        address=address,
        balance=0,
        is_active=True,
        is_uninitialized=False,
        state_init=state_init,
        last_transaction_lt=10 if address == facilitator_address else 0,
    )

    external_boc = signer.build_relay_external_boc(
        TVM_MAINNET,
        TvmRelayRequest(
            destination="0:" + "22" * 32,
            body=begin_cell().end_cell(),
            state_init=None,
        ),
    )
    tx_hash = signer.send_external_message(TVM_MAINNET, external_boc)

    assert tx_hash == "external-message-hash"
    assert len(client.sent_messages) == 1


def test_build_relay_external_boc_batch_supports_255_messages() -> None:
    client = FakeToncenterClient()
    signer = _make_signer(client)
    facilitator_address = signer.get_addresses()[0]
    signer._query_ids[TVM_MAINNET] = 0  # type: ignore[attr-defined]
    state_init = _make_highload_state_init(signer)
    signer.get_account_state = lambda address, network: TvmAccountState(  # type: ignore[method-assign]
        address=address,
        balance=0,
        is_active=True,
        is_uninitialized=False,
        state_init=state_init,
        last_transaction_lt=10 if address == facilitator_address else 0,
    )

    external_boc = signer.build_relay_external_boc_batch(
        TVM_MAINNET,
        [
            TvmRelayRequest(
                destination=f"0:{(index + 1):064x}",
                body=begin_cell().store_uint(index, 16).end_cell(),
                state_init=None,
            )
            for index in range(255)
        ],
    )

    assert isinstance(external_boc, bytes)
    assert signer._query_ids[TVM_MAINNET] == 1  # type: ignore[attr-defined]


def test_build_relay_external_boc_uses_fixed_relay_amount() -> None:
    client = FakeToncenterClient()
    signer = _make_signer(client)
    facilitator_address = signer.get_addresses()[0]
    state_init = _make_highload_state_init(signer)
    signer.get_account_state = lambda address, network: TvmAccountState(  # type: ignore[method-assign]
        address=address,
        balance=0,
        is_active=True,
        is_uninitialized=False,
        state_init=state_init,
        last_transaction_lt=10 if address == facilitator_address else 0,
    )

    captured_values: list[int] = []

    def fake_create_internal_msg(*, src, dest, bounce, value, state_init=None, body):
        _ = src, dest, bounce, state_init, body
        captured_values.append(value)
        return SimpleNamespace(serialize=lambda: begin_cell().end_cell())

    with patch("x402.mechanisms.tvm.signers.Contract.create_internal_msg", side_effect=fake_create_internal_msg):
        signer.build_relay_external_boc(
            TVM_MAINNET,
            TvmRelayRequest(
                destination="0:" + "22" * 32,
                body=begin_cell().end_cell(),
                state_init=None,
            ),
        )

    assert DEFAULT_RELAY_AMOUNT in captured_values


def test_seqno_to_query_id_enforces_upstream_bounds() -> None:
    assert _seqno_to_query_id(0) == 0
    assert _seqno_to_query_id(MAX_USABLE_QUERY_SEQNO) == ((8191 << 10) + 1021)

    try:
        _seqno_to_query_id(MAX_USABLE_QUERY_SEQNO + 1)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")
