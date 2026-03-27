"""Index exports for the TVM mechanism."""

from x402.mechanisms.tvm import (
    TVM_MAINNET,
    ExactTvmPayload,
    FacilitatorHighloadV3Signer,
    HighloadV3Config,
    WalletV5R1Config,
    WalletV5R1MnemonicSigner,
    build_w5r1_state_init,
    make_w5r1_wallet_id,
    parse_exact_tvm_payload,
)


def test_tvm_index_exports() -> None:
    assert TVM_MAINNET == "tvm:-239"
    assert ExactTvmPayload
    assert FacilitatorHighloadV3Signer
    assert HighloadV3Config
    assert WalletV5R1Config
    assert WalletV5R1MnemonicSigner
    assert build_w5r1_state_init
    assert make_w5r1_wallet_id
    assert parse_exact_tvm_payload
