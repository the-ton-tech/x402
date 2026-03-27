"""Tests for TVM provider helpers."""

from __future__ import annotations

from pytoniq_core import Cell, begin_cell
from pytoniq_core.tlb.account import StateInit

from x402.mechanisms.tvm import TVM_MAINNET, build_w5r1_state_init, make_w5r1_wallet_id
from x402.mechanisms.tvm.provider import ToncenterV3Client
from x402.mechanisms.tvm.types import TvmAccountState
from x402.mechanisms.tvm.utils import parse_w5_init_data


def test_get_jetton_wallet_data_parses_teps_74_stack() -> None:
    client = ToncenterV3Client.__new__(ToncenterV3Client)
    client.run_get_method = lambda address, method, stack: [  # type: ignore[method-assign]
        {"value": "0xf4240"},
        {"value": "owner-cell"},
        {"value": "jetton-cell"},
        {"value": "wallet-code-cell"},
    ]
    client._parse_stack_num = lambda item: int(item["value"], 0)  # type: ignore[method-assign]
    client._parse_stack_address = lambda item: {  # type: ignore[method-assign]
        "owner-cell": "0:" + "11" * 32,
        "jetton-cell": "0:" + "22" * 32,
    }[str(item["value"])]
    client._parse_stack_cell = lambda item: Cell.empty()  # type: ignore[method-assign]

    result = client.get_jetton_wallet_data("0:" + "33" * 32)

    assert result.address == "0:" + "33" * 32
    assert result.balance == 1_000_000
    assert result.owner == "0:" + "11" * 32
    assert result.jetton_minter == "0:" + "22" * 32
    assert result.wallet_code == Cell.empty()


def test_get_seqno_from_account_state_parses_w5_data_without_get_method() -> None:
    client = ToncenterV3Client.__new__(ToncenterV3Client)
    account = TvmAccountState(
        address="0:" + "33" * 32,
        balance=0,
        is_active=True,
        is_uninitialized=False,
        state_init=_wallet_state_init(seqno=13),
        last_transaction_lt=None,
    )

    assert client.get_seqno_from_account_state(account) == 13


def _wallet_state_init(*, seqno: int) -> StateInit:
    state_init = build_w5r1_state_init(b"\x02" * 32, make_w5r1_wallet_id(TVM_MAINNET))
    parsed = parse_w5_init_data(state_init)
    updated_data = (
        begin_cell()
        .store_uint(parsed.signature_allowed, 1)
        .store_uint(seqno, 32)
        .store_uint(parsed.wallet_id, 32)
        .store_bytes(parsed.public_key)
        .store_maybe_ref(parsed.extensions_dict)
        .end_cell()
    )
    return StateInit(code=state_init.code, data=updated_data)
