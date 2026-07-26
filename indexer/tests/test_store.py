from __future__ import annotations

import hashlib
from pathlib import Path
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import pytest

from epdn_indexer.store import (
    IndexerError,
    IndexerStore,
    _canonical_block_hash,
    _parse_transaction,
    _transaction_merkle_root,
)


def bytes32(value: int) -> list[int]:
    return [value] * 32


def wallet(value: int) -> tuple[ec.EllipticCurvePrivateKey, list[int]]:
    private_key = ec.derive_private_key(value, ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    address = hashlib.sha256(b"EPDN_WALLET_ADDRESS_V1" + public_key).digest()
    return private_key, list(address)


def block(
    height: int,
    _block_hash_hint: int,
    previous_hash: int | list[int],
    reward_address: int | list[int],
    *,
    reward: int = 100,
    transactions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    chain_id = "epdn-local-testnet-v1"
    epoch = height
    winning_device = 40 + height
    block_transactions = (
        transactions
        if transactions is not None
        else [
            reward_transaction(
                reward_address,
                reward,
                winning_device=winning_device,
                epoch=epoch,
            )
        ]
    )
    parsed_transactions = [
        _parse_transaction(transaction, chain_id)
        for transaction in block_transactions
    ]
    header: dict[str, object] = {
        "protocol_version": 1,
        "chain_id": chain_id,
        "height": height,
        "previous_block_hash": (
            bytes32(previous_hash)
            if isinstance(previous_hash, int)
            else previous_hash
        ),
        "epoch_number": epoch,
        "epoch_randomness": bytes32(3),
        "winning_ticket": bytes32(4),
        "winning_submission_hash": bytes32(5),
        "winning_certificate_hash": bytes32(6),
        "winning_device_public_key_hash": bytes32(winning_device),
        "security_class": "L0_SOFTWARE_TEST",
        "firmware_id": bytes32(7),
        "attestation_hash": None,
        "transaction_merkle_root": list(
            _transaction_merkle_root(parsed_transactions)
        ),
        "device_registry_root": bytes32(8),
        "revocation_root": bytes32(9),
    }
    result: dict[str, object] = {
        "header": header,
        "reward": {
            "address": (
                bytes32(reward_address)
                if isinstance(reward_address, int)
                else reward_address
            ),
            "amount": reward,
            "winning_device_id": bytes32(winning_device),
        },
        "transactions": block_transactions,
        "validator_signatures": [
            {"validator_id": bytes32(10), "signature": [11] * 64}
        ],
        "block_hash": list(_canonical_block_hash(header)),
    }
    return result


def transfer(sender: int, recipient: int) -> dict[str, object]:
    chain_id = "epdn-local-testnet-v1"
    private_key, sender_address = wallet(sender)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    recipient_address = bytes(bytes32(recipient))
    unsigned = (
        b"EPDN"
        + bytes((6,))
        + struct.pack(">H", 1)
        + bytes((1,))
        + struct.pack(">H", len(chain_id))
        + chain_id.encode()
        + public_key
        + bytes(sender_address)
        + recipient_address
        + struct.pack(">QQQ", 25, 2, 0)
    )
    der_signature = private_key.sign(
        b"EPDN_TRANSFER_SIGNATURE_V1" + unsigned,
        ec.ECDSA(hashes.SHA256()),
    )
    raw_r, raw_s = utils.decode_dss_signature(der_signature)
    signature = raw_r.to_bytes(32, "big") + raw_s.to_bytes(32, "big")
    return {
        "kind": "transfer",
        "value": {
            "protocol_version": 1,
            "chain_id": chain_id,
            "sender_public_key": list(public_key),
            "sender_address": sender_address,
            "recipient_address": list(recipient_address),
            "amount": 25,
            "fee": 2,
            "nonce": 0,
            "signature": list(signature),
        },
    }


def reward_transaction(
    recipient: int | list[int],
    amount: int = 100,
    *,
    winning_device: int = 41,
    epoch: int = 1,
) -> dict[str, object]:
    return {
        "kind": "reward_distribution",
        "value": {
            "protocol_version": 1,
            "chain_id": "epdn-local-testnet-v1",
            "recipient_address": (
                bytes32(recipient) if isinstance(recipient, int) else recipient
            ),
            "amount": amount,
            "winning_device_id": bytes32(winning_device),
            "epoch_number": epoch,
        },
    }


def revocation_transaction(
    *,
    reason: str = "compromised",
    effective_height: int = 1,
) -> dict[str, object]:
    return {
        "kind": "device_revocation",
        "value": {
            "protocol_version": 1,
            "chain_id": "epdn-local-testnet-v1",
            "device_id": bytes32(55),
            "reason": reason,
            "effective_block_height": effective_height,
        },
    }


def revocation_only_block() -> dict[str, object]:
    result = block(
        1,
        11,
        0,
        0,
        reward=0,
        transactions=[revocation_transaction()],
    )
    header = result["header"]  # type: ignore[assignment]
    for field in (
        "winning_ticket",
        "winning_submission_hash",
        "winning_certificate_hash",
        "winning_device_public_key_hash",
        "firmware_id",
    ):
        header[field] = bytes32(0)
    header["security_class"] = "L0_SOFTWARE_TEST"
    header["attestation_hash"] = None
    result["reward"] = {
        "address": bytes32(0),
        "amount": 0,
        "winning_device_id": bytes32(0),
    }
    result["block_hash"] = list(_canonical_block_hash(header))
    return result


def test_snapshot_indexes_balances_and_privacy_safe_export(tmp_path: Path) -> None:
    database = tmp_path / "index.sqlite3"
    _, first_wallet_address = wallet(1)
    first = block(
        1,
        11,
        0,
        first_wallet_address,
        transactions=[
            reward_transaction(
                first_wallet_address,
                winning_device=41,
                epoch=1,
            )
        ],
    )
    second = block(
        2,
        12,
        first["block_hash"],  # type: ignore[arg-type]
        2,
        transactions=[
            transfer(1, 2),
            reward_transaction(2, winning_device=42, epoch=2),
        ],
    )
    with IndexerStore(database) as store:
        result = store.replace_snapshot(
            [first, second],
            expected_chain_id="epdn-local-testnet-v1",
        )
        assert result == {"blocks": 2, "tip": 2, "reorg_height": -1}
        assert store.summary() == {
            "chain_id": "epdn-local-testnet-v1",
            "blocks": 2,
            "tip": 2,
            "total_rewards": 200,
            "transactions": 3,
            "addresses": 2,
        }

        exported = store.public_export(genesis_unix=1_700_000_000)
        assert exported["balances"] == [
            {"address": "02" * 32, "amount": 125},
            {"address": bytes(first_wallet_address).hex(), "amount": 73},
        ]
        assert exported["blocks"][0]["estimated_unix"] == 1_700_000_030
        assert exported["hourly_stats"] == [
            {"epoch_hour_bucket": 0, "blocks": 2, "rewards": 200}
        ]
        assert exported["daily_stats"] == [
            {"epoch_day_bucket": 0, "blocks": 2, "rewards": 200}
        ]
        text = str(exported).lower()
        for forbidden in ("wifi", "ssid", "mac_address", "ip_address", "private_key"):
            assert forbidden not in text


def test_reorg_rolls_back_derived_state(tmp_path: Path) -> None:
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        _, first_wallet_address = wallet(1)
        first = block(1, 11, 0, first_wallet_address)
        store.replace_snapshot(
            [
                first,
                block(
                    2,
                    12,
                    first["block_hash"],  # type: ignore[arg-type]
                    2,
                    transactions=[
                        transfer(1, 2),
                        reward_transaction(2, winning_device=42, epoch=2),
                    ],
                ),
            ],
            expected_chain_id="epdn-local-testnet-v1",
        )
        result = store.replace_snapshot(
            [
                first,
                block(
                    2,
                    22,
                    first["block_hash"],  # type: ignore[arg-type]
                    3,
                    reward=50,
                    transactions=[
                        reward_transaction(
                            3, 50, winning_device=42, epoch=2
                        )
                    ],
                ),
            ],
            expected_chain_id="epdn-local-testnet-v1",
        )
        assert result["reorg_height"] == 2
        assert store.public_export()["balances"] == [
            {"address": "03" * 32, "amount": 50},
            {"address": bytes(first_wallet_address).hex(), "amount": 100},
        ]


def test_snapshot_rejects_gap_and_wrong_parent(tmp_path: Path) -> None:
    first = block(1, 11, 0, 1)
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        with pytest.raises(IndexerError, match="non-contiguous"):
            store.replace_snapshot(
                [
                    first,
                    block(
                        3,
                        13,
                        first["block_hash"],  # type: ignore[arg-type]
                        2,
                    ),
                ]
            )
        with pytest.raises(IndexerError, match="previous hash"):
            store.replace_snapshot([first, block(2, 12, 99, 2)])
        with pytest.raises(IndexerError, match="height 1"):
            store.replace_snapshot([block(2, 12, 11, 2)])
        with pytest.raises(IndexerError, match="zero genesis hash"):
            store.replace_snapshot([block(1, 11, 9, 1)])


def test_snapshot_rejects_values_outside_sqlite_integer_range(
    tmp_path: Path,
) -> None:
    oversized = block(1, 11, 0, 1)
    oversized["reward"]["amount"] = 1 << 63  # type: ignore[index]
    oversized["transactions"][0]["value"]["amount"] = 1 << 63  # type: ignore[index]
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        with pytest.raises(IndexerError, match="SQLite MVP integer limit"):
            store.replace_snapshot([oversized])


def test_snapshot_rejects_mismatched_reward_device(tmp_path: Path) -> None:
    mismatched = block(1, 11, 0, 1)
    mismatched["reward"]["winning_device_id"] = bytes32(99)  # type: ignore[index]
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        with pytest.raises(IndexerError, match="reward winning device"):
            store.replace_snapshot([mismatched])


def test_snapshot_rejects_unknown_transaction_kind_atomically(
    tmp_path: Path,
) -> None:
    unsupported = block(1, 11, 0, 1)
    transactions = unsupported["transactions"]  # type: ignore[assignment]
    transactions[0]["kind"] = "future_unreviewed_kind"
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        with pytest.raises(IndexerError, match="unsupported transaction kind"):
            store.replace_snapshot([unsupported])
        assert store.summary()["blocks"] == 0


def test_snapshot_rejects_header_and_transaction_integrity_mismatches(
    tmp_path: Path,
) -> None:
    tampered_header = block(1, 11, 0, 1)
    header = tampered_header["header"]  # type: ignore[assignment]
    header["winning_ticket"] = bytes32(99)
    tampered_transactions = block(
        1,
        11,
        0,
        1,
        transactions=[
            transfer(2, 1),
            reward_transaction(1, winning_device=41, epoch=1),
        ],
    )
    transactions = tampered_transactions["transactions"]  # type: ignore[assignment]
    transactions[0]["value"]["amount"] = 26  # type: ignore[index]
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        with pytest.raises(IndexerError, match="canonical header"):
            store.replace_snapshot([tampered_header])
        with pytest.raises(IndexerError, match="signature"):
            store.replace_snapshot([tampered_transactions])


def test_snapshot_accepts_rewardless_revocation_only_management_block(
    tmp_path: Path,
) -> None:
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        store.replace_snapshot([revocation_only_block()])
        exported = store.public_export()
        assert exported["summary"]["blocks"] == 1
        assert exported["summary"]["total_rewards"] == 0
        assert exported["rewards"] == []
        assert exported["balances"] == []
        assert exported["blocks"][0]["reward_address"] is None
        assert exported["hourly_stats"] == [
            {"epoch_hour_bucket": 0, "blocks": 1, "rewards": 0}
        ]


def test_snapshot_rejects_revocation_and_epoch_context_mismatches(
    tmp_path: Path,
) -> None:
    whitespace = block(
        1,
        11,
        0,
        1,
        transactions=[
            revocation_transaction(),
            reward_transaction(1, winning_device=41, epoch=1),
        ],
    )
    whitespace["transactions"][0]["value"]["reason"] = "  "  # type: ignore[index]
    wrong_effective_height = block(
        1,
        11,
        0,
        1,
        transactions=[
            revocation_transaction(),
            reward_transaction(1, winning_device=41, epoch=1),
        ],
    )
    wrong_effective_height["transactions"][0]["value"][  # type: ignore[index]
        "effective_block_height"
    ] = 2
    wrong_epoch = block(1, 11, 0, 1)
    wrong_epoch["header"]["epoch_number"] = 2  # type: ignore[index]
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        with pytest.raises(IndexerError, match="reason"):
            store.replace_snapshot([whitespace])
        with pytest.raises(IndexerError, match="effective height"):
            store.replace_snapshot([wrong_effective_height])
        with pytest.raises(IndexerError, match="epoch_number"):
            store.replace_snapshot([wrong_epoch])
