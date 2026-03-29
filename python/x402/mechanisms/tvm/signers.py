"""Concrete TVM signer implementations."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from secrets import randbelow

from .codecs.common import normalize_address
from .codecs.highload_v3 import (
    MAX_USABLE_QUERY_SEQNO,
    load_highload_query_state,
    query_id_is_processed,
    seqno_to_query_id,
    serialize_internal_transfer,
)
from .codecs.w5 import (
    address_from_state_init,
    build_w5r1_state_init,
    make_w5r1_wallet_id,
    serialize_out_list,
    serialize_send_msg_action,
)
from .constants import (
    DEFAULT_HIGHLOAD_SUBWALLET_ID,
    DEFAULT_HIGHLOAD_TIMEOUT,
    DEFAULT_RELAY_AMOUNT,
    DEFAULT_TONCENTER_TIMEOUT_SECONDS,
    DEFAULT_W5R1_SUBWALLET_NUMBER,
    HIGHLOAD_V3_CODE_HASH,
    HIGHLOAD_V3_CODE_HEX,
)
from .provider import ToncenterV3Client
from .types import TvmAccountState, TvmJettonWalletData, TvmRelayRequest

try:
    from pytoniq.contract.contract import Contract
    from pytoniq_core import Address, Cell, begin_cell
    from pytoniq_core.crypto.keys import mnemonic_to_wallet_key, private_key_to_public_key
    from pytoniq_core.crypto.signature import sign_message
    from pytoniq_core.tlb.account import StateInit
except ImportError as e:
    raise ImportError(
        "TVM mechanism requires pytoniq packages. Install with: pip install x402[tvm]"
    ) from e


@dataclass
class HighloadV3Config:
    """Configuration for one facilitator wallet on a TVM network."""

    secret_key: bytes
    api_key: str | None = None
    base_url: str | None = None
    subwallet_id: int = DEFAULT_HIGHLOAD_SUBWALLET_ID
    timeout: int = DEFAULT_HIGHLOAD_TIMEOUT
    relay_amount: int = DEFAULT_RELAY_AMOUNT
    toncenter_timeout_seconds: float = DEFAULT_TONCENTER_TIMEOUT_SECONDS
    workchain: int = 0

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: str | list[str],
        *,
        subwallet_id: int = DEFAULT_HIGHLOAD_SUBWALLET_ID,
        timeout: int = DEFAULT_HIGHLOAD_TIMEOUT,
        relay_amount: int = DEFAULT_RELAY_AMOUNT,
        workchain: int = 0,
    ) -> HighloadV3Config:
        """Create config from a TON mnemonic."""
        if isinstance(mnemonic, str):
            mnemonic = mnemonic.split()
        _, secret_key = mnemonic_to_wallet_key(mnemonic)
        return cls(
            secret_key=secret_key,
            subwallet_id=subwallet_id,
            timeout=timeout,
            relay_amount=relay_amount,
            workchain=workchain,
        )


@dataclass
class WalletV5R1Config:
    """Configuration for one client-side W5R1 wallet."""

    network: str
    secret_key: bytes
    api_key: str | None = None
    base_url: str | None = None
    subwallet_number: int = DEFAULT_W5R1_SUBWALLET_NUMBER
    toncenter_timeout_seconds: float = DEFAULT_TONCENTER_TIMEOUT_SECONDS
    workchain: int = 0

    @classmethod
    def from_mnemonic(
        cls,
        network: str,
        mnemonic: str | list[str],
        *,
        subwallet_number: int = DEFAULT_W5R1_SUBWALLET_NUMBER,
        workchain: int = 0,
    ) -> WalletV5R1Config:
        """Create config from a TON mnemonic."""
        if isinstance(mnemonic, str):
            mnemonic = mnemonic.split()
        _, secret_key = mnemonic_to_wallet_key(mnemonic)
        return cls(
            network=network,
            secret_key=secret_key,
            subwallet_number=subwallet_number,
            workchain=workchain,
        )


class WalletV5R1MnemonicSigner:
    """Client signer backed by a mnemonic-derived W5R1 wallet."""

    def __init__(self, config: WalletV5R1Config) -> None:
        self._config = config
        self._public_key = private_key_to_public_key(config.secret_key)
        self._wallet_id = make_w5r1_wallet_id(
            config.network,
            workchain=config.workchain,
            subwallet_number=config.subwallet_number,
        )
        self._state_init = build_w5r1_state_init(self._public_key, self._wallet_id)
        self._address = address_from_state_init(self._state_init, config.workchain)

    @property
    def address(self) -> str:
        return self._address

    @property
    def network(self) -> str:
        return self._config.network

    @property
    def api_key(self) -> str | None:
        return self._config.api_key

    @property
    def base_url(self) -> str | None:
        return self._config.base_url

    @property
    def toncenter_timeout_seconds(self) -> float:
        return self._config.toncenter_timeout_seconds

    @property
    def wallet_id(self) -> int:
        return self._wallet_id

    @property
    def state_init(self) -> StateInit:
        return self._state_init

    def sign_message(self, message: bytes) -> bytes:
        return sign_message(message, self._config.secret_key)


class FacilitatorHighloadV3Signer:
    """Facilitator signer backed by a highload-wallet-contract-v3 wallet."""

    def __init__(self, configs: dict[str, HighloadV3Config]) -> None:
        self._configs = dict(configs)
        self._clients: dict[str, ToncenterV3Client] = {}
        self._wallets: dict[str, _WalletContext] = {}
        self._query_ids: dict[str, int] = {}
        self._lock = threading.Lock()

        for network, config in self._configs.items():
            context = _WalletContext.from_config(config)
            self._wallets[network] = context
            self._query_ids[network] = randbelow(MAX_USABLE_QUERY_SEQNO + 1)

    def get_addresses(self) -> list[str]:
        """Get all facilitator wallet addresses."""
        return [wallet.address for wallet in self._wallets.values()]

    def get_account_state(self, address: str, network: str) -> TvmAccountState:
        """Get current account state."""
        return self._client(network).get_account_state(address)

    def build_relay_external_boc(
        self,
        network: str,
        relay_request: TvmRelayRequest,
        *,
        for_emulation: bool = False,
    ) -> bytes:
        """Build a Highload V3 external message for relaying the pre-signed W5 request."""
        return self.build_relay_external_boc_batch(network, [relay_request], for_emulation=for_emulation)

    def build_relay_external_boc_batch(
        self,
        network: str,
        relay_requests: list[TvmRelayRequest],
        *,
        for_emulation: bool = False,
    ) -> bytes:
        """Build one Highload V3 external message for relaying multiple W5 requests."""
        if not relay_requests:
            raise ValueError("relay_requests must not be empty")

        wallet_context = self._wallets[network]
        query_id = self._select_query_id(network, for_emulation)
        created_at = int(time.time())
        external_state_init = None
        forward_actions: list[Cell] = []

        for relay_request in relay_requests:
            forward_message = Contract.create_internal_msg(
                src=None,
                dest=Address(relay_request.destination),
                bounce=True,
                value=wallet_context.config.relay_amount,
                state_init=relay_request.state_init,
                body=relay_request.body,
            )
            forward_actions.append(serialize_send_msg_action(forward_message.serialize(), mode=3))

        message_to_send = self._pack_actions_message(wallet_context, forward_actions, query_id)

        message_inner = (
            begin_cell()
            .store_uint(wallet_context.config.subwallet_id, 32)
            .store_ref(message_to_send)
            .store_uint(1, 8)
            .store_uint(query_id, 23)
            .store_uint(created_at, 64)
            .store_uint(wallet_context.config.timeout, 22)
            .end_cell()
        )

        external_body = (
            begin_cell()
            .store_bytes(sign_message(message_inner.hash, wallet_context.config.secret_key))
            .store_ref(message_inner)
            .end_cell()
        )

        if wallet_context.deployed is not True:
            facilitator_account = self.get_account_state(wallet_context.address, network)
            wallet_context.deployed = facilitator_account.is_active
            if facilitator_account.is_uninitialized:
                external_state_init = wallet_context.state_init

        external_message = Contract.create_external_msg(
            dest=Address(wallet_context.address),
            state_init=external_state_init,
            body=external_body,
        )
        return external_message.serialize().to_boc()

    def emulate_external_message(self, network: str, external_boc: bytes) -> dict[str, object]:
        """Emulate a prepared external message via Toncenter."""
        return self._client(network).emulate_trace(external_boc)

    def send_external_message(self, network: str, external_boc: bytes) -> str:
        """Broadcast a prepared external message via Toncenter."""
        return self._client(network).send_message(external_boc)

    def get_jetton_wallet_data(self, address: str, network: str) -> TvmJettonWalletData:
        """Read TEP-74 jetton wallet data."""
        return self._client(network).get_jetton_wallet_data(address)

    def _client(self, network: str) -> ToncenterV3Client:
        if network not in self._clients:
            config = self._configs[network]
            self._clients[network] = ToncenterV3Client(
                network,
                api_key=config.api_key,
                base_url=config.base_url,
                timeout=config.toncenter_timeout_seconds,
            )
        return self._clients[network]

    def _pack_actions_message(
        self,
        wallet_context: "_WalletContext",
        actions: list[Cell],
        query_id: int,
    ) -> Cell:
        batch_actions = list(actions)
        if len(batch_actions) > 254:
            nested_message = self._pack_actions_message(wallet_context, batch_actions[253:], query_id)
            batch_actions = batch_actions[:253] + [serialize_send_msg_action(nested_message, mode=3)]

        return Contract.create_internal_msg(
            src=None,
            dest=Address(wallet_context.address),
            bounce=True,
            value=10 ** 9,
            body=serialize_internal_transfer(serialize_out_list(batch_actions), query_id),
        ).serialize()

    def _select_query_id(self, network: str, for_emulation: bool) -> int:
        """Pick a free HighloadV3 QueryID from the local monotonic seqno cursor."""
        with self._lock:
            wallet_context = self._wallets[network]
            query_state = load_highload_query_state(
                self.get_account_state(wallet_context.address, network),
                expected_code_hash=HIGHLOAD_V3_CODE_HASH,
            )
            wallet_context.deployed = query_state is not None
            attempts = MAX_USABLE_QUERY_SEQNO + 1
            next_seqno = self._query_ids[network]
            for _ in range(attempts):
                seqno = next_seqno
                next_seqno = (next_seqno + 1) % (MAX_USABLE_QUERY_SEQNO + 1)
                query_id = seqno_to_query_id(seqno)
                if query_state is None or not query_id_is_processed(query_state, query_id):
                    if not for_emulation:
                        self._query_ids[network] = next_seqno
                    return query_id
        raise RuntimeError("No free Highload V3 query_id available")


@dataclass
class _WalletContext:
    config: HighloadV3Config
    public_key: bytes
    address: str
    state_init: StateInit
    deployed: bool | None = None

    @classmethod
    def from_config(cls, config: HighloadV3Config) -> _WalletContext:
        # TON-specific: highload v3 wallet address is derived from its fixed code and data layout.
        public_key = private_key_to_public_key(config.secret_key)
        code = Cell.one_from_boc(bytes.fromhex(HIGHLOAD_V3_CODE_HEX))
        if code.hash.hex() != HIGHLOAD_V3_CODE_HASH:
            raise ValueError("Unexpected highload-wallet-contract-v3 code hash")

        data = (
            begin_cell()
            .store_bytes(public_key)
            .store_uint(config.subwallet_id, 32)
            .store_uint(0, 66)
            .store_uint(config.timeout, 22)
            .end_cell()
        )
        state_init = StateInit(code=code, data=data)
        address = normalize_address(Address((config.workchain, state_init.serialize().hash)))
        return cls(
            config=config,
            public_key=public_key,
            address=address,
            state_init=state_init,
            deployed=None,
        )

_seqno_to_query_id = seqno_to_query_id


def _transaction_failed(tx: dict[str, object]) -> bool:
    description = tx.get("description")
    if not isinstance(description, dict):
        return False

    if description.get("aborted") is True:
        return True

    compute_phase = description.get("compute_ph")
    if isinstance(compute_phase, dict) and compute_phase.get("success") is False:
        return True

    action_phase = description.get("action")
    if isinstance(action_phase, dict) and action_phase.get("success") is False:
        return True

    return False


def _format_transaction_failure(tx: dict[str, object]) -> str:
    description = tx.get("description")
    if not isinstance(description, dict):
        return "Highload V3 transaction failed"

    compute_phase = description.get("compute_ph")
    if isinstance(compute_phase, dict) and compute_phase.get("exit_code") is not None:
        return f"Highload V3 transaction failed with compute exit code {compute_phase['exit_code']}"

    action_phase = description.get("action")
    if isinstance(action_phase, dict) and action_phase.get("result_code") is not None:
        return f"Highload V3 transaction failed with action result code {action_phase['result_code']}"

    return "Highload V3 transaction failed"
