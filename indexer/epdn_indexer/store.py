"""SQLite projection of finalized public EPDN block data."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


class IndexerError(RuntimeError):
    """Finalized block data violated the indexer's deterministic contract."""


SQLITE_INTEGER_MAX = (1 << 63) - 1
PROTOCOL_VERSION = 1
MAX_CHAIN_ID_BYTES = 64
MAX_REVOCATION_REASON_BYTES = 128
SECURITY_CLASS_VALUES = {
    "L0_SOFTWARE_TEST": 0,
    "L1_PROTECTED_SOFTWARE_IDENTITY": 1,
    "L2_NATIVE_HARDWARE_IDENTITY": 2,
    "L3_EXTERNAL_SECURE_ELEMENT": 3,
    "L4_ATTESTED_PLATFORM": 4,
}
REVOCATION_ONLY_MARKER = bytes(32)


def _bytes_exact(value: object, field: str, length: int) -> bytes:
    if isinstance(value, str):
        if len(value) != length * 2 or any(
            character not in "0123456789abcdefABCDEF" for character in value
        ):
            raise IndexerError(f"{field} must contain exactly {length} bytes")
        try:
            decoded = bytes.fromhex(value)
        except ValueError as error:
            raise IndexerError(f"{field} is not hexadecimal") from error
        if len(decoded) == length:
            return decoded
    if (
        isinstance(value, list)
        and len(value) == length
        and all(isinstance(item, int) and 0 <= item <= 255 for item in value)
    ):
        return bytes(value)
    raise IndexerError(f"{field} must contain exactly {length} bytes")


def _hex32(value: object, field: str) -> str:
    return _bytes_exact(value, field, 32).hex()


def _uint(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IndexerError(f"{field} must be a non-negative integer")
    if value > SQLITE_INTEGER_MAX:
        raise IndexerError(f"{field} exceeds the SQLite MVP integer limit")
    return value


def _protocol_version(value: object, field: str) -> int:
    version = _uint(value, field)
    if version != PROTOCOL_VERSION:
        raise IndexerError(f"{field} must be EPDN protocol version 1")
    return version


def _chain_id(value: object, field: str = "chain_id") -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_CHAIN_ID_BYTES
    ):
        raise IndexerError(f"{field} is invalid")
    return value


def _sized(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def _hash_domain(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


@dataclass(frozen=True)
class ParsedTransaction:
    kind: str
    sender: str | None
    recipient: str | None
    amount: int | None
    fee: int | None
    nonce: int | None
    transaction_hash: bytes
    order_key: bytes
    reward_winning_device_id: str | None
    reward_epoch: int | None
    revocation_effective_height: int | None
    raw_json: str


def _parse_transaction(
    transaction: dict[str, Any], expected_chain_id: str
) -> ParsedTransaction:
    kind = transaction.get("kind")
    value = transaction.get("value")
    if not isinstance(kind, str) or not isinstance(value, dict):
        raise IndexerError("transaction must contain kind and value")
    version = _protocol_version(
        value.get("protocol_version"), f"{kind}.protocol_version"
    )
    chain_id = _chain_id(value.get("chain_id"), f"{kind}.chain_id")
    if chain_id != expected_chain_id:
        raise IndexerError("transaction chain_id does not match its block")

    sender = recipient = None
    amount = fee = nonce = None
    reward_winning_device_id = None
    reward_epoch = None
    revocation_effective_height = None
    prefix: bytes
    order_prefix: bytes
    if kind == "transfer":
        public_key = _bytes_exact(
            value.get("sender_public_key"), "transfer.sender_public_key", 33
        )
        sender_bytes = _bytes_exact(
            value.get("sender_address"), "transfer.sender", 32
        )
        recipient_bytes = _bytes_exact(
            value.get("recipient_address"), "transfer.recipient", 32
        )
        amount = _uint(value.get("amount"), "transfer.amount")
        if amount == 0:
            raise IndexerError("transfer.amount must be greater than zero")
        fee = _uint(value.get("fee"), "transfer.fee")
        nonce = _uint(value.get("nonce"), "transfer.nonce")
        unsigned_prefix = (
            b"EPDN"
            + bytes((6,))
            + struct.pack(">H", version)
            + bytes((1,))
            + _sized(chain_id)
            + public_key
            + sender_bytes
            + recipient_bytes
            + struct.pack(">QQQ", amount, fee, nonce)
        )
        signature = _bytes_exact(value.get("signature"), "transfer.signature", 64)
        prefix = (
            unsigned_prefix
            + struct.pack(">H", len(signature))
            + signature
        )
        if _hash_domain(b"EPDN_WALLET_ADDRESS_V1", public_key) != sender_bytes:
            raise IndexerError("transfer sender address does not match its public key")
        try:
            verifying_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key
            )
            raw_r = int.from_bytes(signature[:32], "big")
            raw_s = int.from_bytes(signature[32:], "big")
            verifying_key.verify(
                utils.encode_dss_signature(raw_r, raw_s),
                b"EPDN_TRANSFER_SIGNATURE_V1" + unsigned_prefix,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError) as error:
            raise IndexerError("transfer signature is invalid") from error
        sender = sender_bytes.hex()
        recipient = recipient_bytes.hex()
        order_prefix = bytes((1,)) + sender_bytes + struct.pack(">Q", nonce)
    elif kind == "device_revocation":
        device_id = _bytes_exact(
            value.get("device_id"), "device_revocation.device_id", 32
        )
        reason = value.get("reason")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason.encode("utf-8")) > MAX_REVOCATION_REASON_BYTES
        ):
            raise IndexerError("device_revocation.reason is invalid")
        revocation_effective_height = _uint(
            value.get("effective_block_height"),
            "device_revocation.effective_block_height",
        )
        prefix = (
            b"EPDN"
            + bytes((7,))
            + struct.pack(">H", version)
            + bytes((4,))
            + _sized(chain_id)
            + device_id
            + _sized(reason)
            + struct.pack(">Q", revocation_effective_height)
        )
        order_prefix = bytes((4,)) + device_id
    elif kind == "reward_distribution":
        recipient_bytes = _bytes_exact(
            value.get("recipient_address"), "reward.recipient", 32
        )
        amount = _uint(value.get("amount"), "reward.amount")
        winning_device = _bytes_exact(
            value.get("winning_device_id"), "reward.winning_device_id", 32
        )
        reward_epoch = _uint(value.get("epoch_number"), "reward.epoch_number")
        prefix = (
            b"EPDN"
            + bytes((8,))
            + struct.pack(">H", version)
            + bytes((7,))
            + _sized(chain_id)
            + recipient_bytes
            + struct.pack(">Q", amount)
            + winning_device
            + struct.pack(">Q", reward_epoch)
        )
        recipient = recipient_bytes.hex()
        reward_winning_device_id = winning_device.hex()
        order_prefix = (
            bytes((7,)) + struct.pack(">Q", reward_epoch) + recipient_bytes
        )
    else:
        raise IndexerError(f"unsupported transaction kind: {kind}")

    transaction_hash = _hash_domain(b"EPDN_TRANSACTION_V1", prefix)
    return ParsedTransaction(
        kind=kind,
        sender=sender,
        recipient=recipient,
        amount=amount,
        fee=fee,
        nonce=nonce,
        transaction_hash=transaction_hash,
        order_key=order_prefix + transaction_hash,
        reward_winning_device_id=reward_winning_device_id,
        reward_epoch=reward_epoch,
        revocation_effective_height=revocation_effective_height,
        raw_json=json.dumps(transaction, sort_keys=True, separators=(",", ":")),
    )


def _transaction_merkle_root(transactions: list[ParsedTransaction]) -> bytes:
    if not transactions:
        return _hash_domain(b"EPDN_EMPTY_TRANSACTION_ROOT_V1")
    level = [transaction.transaction_hash for transaction in transactions]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(
                _hash_domain(b"EPDN_TRANSACTION_MERKLE_NODE_V1", left, right)
            )
        level = next_level
    return level[0]


def _canonical_block_hash(header: dict[str, Any]) -> bytes:
    version = _protocol_version(header.get("protocol_version"), "protocol_version")
    chain_id = _chain_id(header.get("chain_id"))
    security_class = header.get("security_class")
    if security_class not in SECURITY_CLASS_VALUES:
        raise IndexerError("security_class is invalid")
    attestation = header.get("attestation_hash")
    attestation_bytes = (
        b"\x00"
        if attestation is None
        else b"\x01" + _bytes_exact(attestation, "attestation_hash", 32)
    )
    canonical = (
        b"EPDN"
        + bytes((5,))
        + struct.pack(">H", version)
        + _sized(chain_id)
        + struct.pack(">Q", _uint(header.get("height"), "height"))
        + _bytes_exact(header.get("previous_block_hash"), "previous_block_hash", 32)
        + struct.pack(">Q", _uint(header.get("epoch_number"), "epoch_number"))
        + _bytes_exact(header.get("epoch_randomness"), "epoch_randomness", 32)
        + _bytes_exact(header.get("winning_ticket"), "winning_ticket", 32)
        + _bytes_exact(
            header.get("winning_submission_hash"), "winning_submission_hash", 32
        )
        + _bytes_exact(
            header.get("winning_certificate_hash"), "winning_certificate_hash", 32
        )
        + _bytes_exact(
            header.get("winning_device_public_key_hash"),
            "winning_device_public_key_hash",
            32,
        )
        + bytes((SECURITY_CLASS_VALUES[security_class],))
        + _bytes_exact(header.get("firmware_id"), "firmware_id", 32)
        + attestation_bytes
        + _bytes_exact(
            header.get("transaction_merkle_root"), "transaction_merkle_root", 32
        )
        + _bytes_exact(header.get("device_registry_root"), "device_registry_root", 32)
        + _bytes_exact(header.get("revocation_root"), "revocation_root", 32)
    )
    return _hash_domain(b"EPDN_BLOCK_V1", canonical)


@dataclass(frozen=True)
class ParsedBlock:
    height: int
    block_hash: str
    previous_hash: str
    chain_id: str
    epoch: int
    winning_device_id: str
    reward_address: str | None
    reward_amount: int | None
    transactions: list[ParsedTransaction]
    raw_json: str


def parse_block(block: dict[str, Any]) -> ParsedBlock:
    header = block.get("header")
    reward = block.get("reward")
    transactions = block.get("transactions", [])
    if not isinstance(header, dict) or not isinstance(reward, dict):
        raise IndexerError("block must contain header and reward objects")
    if not isinstance(transactions, list) or not all(
        isinstance(transaction, dict) for transaction in transactions
    ):
        raise IndexerError("block transactions must be an array of objects")
    chain_id = _chain_id(header.get("chain_id"))
    height = _uint(header.get("height"), "height")
    epoch = _uint(header.get("epoch_number"), "epoch_number")
    if epoch != height:
        raise IndexerError("epoch_number must equal block height")
    parsed_transactions = [
        _parse_transaction(transaction, chain_id) for transaction in transactions
    ]
    if any(
        transaction.revocation_effective_height not in (None, height)
        for transaction in parsed_transactions
    ):
        raise IndexerError(
            "device revocation effective height does not match its block"
        )
    if any(
        current.order_key >= following.order_key
        for current, following in zip(
            parsed_transactions, parsed_transactions[1:]
        )
    ):
        raise IndexerError("block transactions are not in canonical order")
    declared_transaction_root = _bytes_exact(
        header.get("transaction_merkle_root"), "transaction_merkle_root", 32
    )
    if _transaction_merkle_root(parsed_transactions) != declared_transaction_root:
        raise IndexerError("transaction Merkle root does not match block contents")
    winning_device = _bytes_exact(
        header.get("winning_device_public_key_hash"),
        "winning_device_public_key_hash",
        32,
    )
    winning_device_id = winning_device.hex()
    reward_device = _bytes_exact(
        reward.get("winning_device_id"),
        "reward.winning_device_id",
        32,
    )
    reward_address_bytes = _bytes_exact(reward.get("address"), "reward.address", 32)
    declared_reward_amount = _uint(reward.get("amount"), "reward.amount")
    reward_transactions = [
        transaction
        for transaction in parsed_transactions
        if transaction.kind == "reward_distribution"
    ]
    if winning_device == REVOCATION_ONLY_MARKER:
        if (
            _bytes_exact(header.get("winning_ticket"), "winning_ticket", 32)
            != REVOCATION_ONLY_MARKER
            or _bytes_exact(
                header.get("winning_submission_hash"),
                "winning_submission_hash",
                32,
            )
            != REVOCATION_ONLY_MARKER
            or _bytes_exact(
                header.get("winning_certificate_hash"),
                "winning_certificate_hash",
                32,
            )
            != REVOCATION_ONLY_MARKER
            or header.get("security_class") != "L0_SOFTWARE_TEST"
            or _bytes_exact(header.get("firmware_id"), "firmware_id", 32)
            != REVOCATION_ONLY_MARKER
            or header.get("attestation_hash") is not None
            or reward_device != REVOCATION_ONLY_MARKER
            or reward_address_bytes != REVOCATION_ONLY_MARKER
            or declared_reward_amount != 0
            or not parsed_transactions
            or any(
                transaction.kind != "device_revocation"
                for transaction in parsed_transactions
            )
        ):
            raise IndexerError("revocation-only block marker is invalid")
        reward_address = None
        reward_amount = None
    else:
        reward_device_id = reward_device.hex()
        if reward_device_id != winning_device_id:
            raise IndexerError(
                "reward winning device does not match the block header"
            )
        reward_address = reward_address_bytes.hex()
        reward_amount = declared_reward_amount
        if len(reward_transactions) != 1:
            raise IndexerError("block must contain exactly one reward transaction")
        reward_transaction = reward_transactions[0]
        if (
            reward_transaction.recipient != reward_address
            or reward_transaction.amount != reward_amount
            or reward_transaction.reward_winning_device_id != winning_device_id
            or reward_transaction.reward_epoch != epoch
        ):
            raise IndexerError("reward transaction does not match the block reward")
    block_hash = _hex32(block.get("block_hash"), "block_hash")
    if _canonical_block_hash(header).hex() != block_hash:
        raise IndexerError("block_hash does not match the canonical header")
    signatures = block.get("validator_signatures")
    if not isinstance(signatures, list) or not signatures:
        raise IndexerError("block must contain a validator signature")
    validator_ids: list[bytes] = []
    for signature in signatures:
        if not isinstance(signature, dict):
            raise IndexerError("validator signature must be an object")
        validator_ids.append(
            _bytes_exact(signature.get("validator_id"), "validator_id", 32)
        )
        _bytes_exact(signature.get("signature"), "validator_signature", 64)
    if any(
        current >= following
        for current, following in zip(validator_ids, validator_ids[1:])
    ):
        raise IndexerError("validator signatures are not in canonical order")
    return ParsedBlock(
        height=height,
        block_hash=block_hash,
        previous_hash=_hex32(
            header.get("previous_block_hash"), "previous_block_hash"
        ),
        chain_id=chain_id,
        epoch=epoch,
        winning_device_id=winning_device_id,
        reward_address=reward_address,
        reward_amount=reward_amount,
        transactions=parsed_transactions,
        raw_json=json.dumps(block, sort_keys=True, separators=(",", ":")),
    )


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL UNIQUE,
    previous_hash TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    winning_device_id TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    raw_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rewards (
    block_height INTEGER PRIMARY KEY REFERENCES blocks(height) ON DELETE CASCADE,
    address TEXT NOT NULL,
    amount INTEGER NOT NULL,
    winning_device_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rewards_address_idx ON rewards(address, block_height);
CREATE INDEX IF NOT EXISTS rewards_device_idx
    ON rewards(winning_device_id, block_height);
CREATE TABLE IF NOT EXISTS transactions (
    block_height INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL,
    sender TEXT,
    recipient TEXT,
    amount INTEGER,
    fee INTEGER,
    nonce INTEGER,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (block_height, ordinal)
);
CREATE INDEX IF NOT EXISTS transactions_sender_idx
    ON transactions(sender, block_height);
CREATE INDEX IF NOT EXISTS transactions_recipient_idx
    ON transactions(recipient, block_height);
CREATE TABLE IF NOT EXISTS balances (
    address TEXT PRIMARY KEY,
    amount INTEGER NOT NULL
);
"""


class IndexerStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "IndexerStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def reset(self) -> None:
        with self.connection:
            self._clear()

    def replace_snapshot(
        self,
        blocks: Iterable[dict[str, Any]],
        *,
        expected_chain_id: str | None = None,
        clear_existing: bool = False,
    ) -> dict[str, int]:
        parsed = sorted(
            (parse_block(block) for block in blocks),
            key=lambda item: item.height,
        )
        heights = [block.height for block in parsed]
        if len(heights) != len(set(heights)):
            raise IndexerError("snapshot contains duplicate block heights")
        if parsed and parsed[0].height != 1:
            raise IndexerError("full snapshot must begin at block height 1")
        if parsed and parsed[0].previous_hash != "00" * 32:
            raise IndexerError("first block must extend the zero genesis hash")
        for previous, current in zip(parsed, parsed[1:]):
            if current.height != previous.height + 1:
                raise IndexerError("snapshot contains a non-contiguous block range")
            if current.previous_hash != previous.block_hash:
                raise IndexerError("snapshot previous hash does not match its parent")
        if expected_chain_id and any(
            block.chain_id != expected_chain_id for block in parsed
        ):
            raise IndexerError("snapshot contains a block from another chain")

        observed_at = int(time.time())
        reorg_height: int | None = None
        with self.connection:
            if clear_existing:
                self._clear()
            for block in parsed:
                existing = self.connection.execute(
                    "SELECT block_hash FROM blocks WHERE height = ?", (block.height,)
                ).fetchone()
                if existing and existing["block_hash"] != block.block_hash:
                    reorg_height = block.height
                    self._delete_from(block.height)
                    break

            remote_tip = parsed[-1].height if parsed else -1
            local_tip_row = self.connection.execute(
                "SELECT MAX(height) AS height FROM blocks"
            ).fetchone()
            local_tip = local_tip_row["height"]
            if local_tip is not None and local_tip > remote_tip:
                reorg_height = remote_tip + 1
                self._delete_from(remote_tip + 1)

            for block in parsed:
                existing = self.connection.execute(
                    "SELECT block_hash FROM blocks WHERE height = ?", (block.height,)
                ).fetchone()
                if existing:
                    if existing["block_hash"] != block.block_hash:
                        raise IndexerError(
                            "reorg rollback did not remove divergent block"
                        )
                    continue
                parent = self.connection.execute(
                    "SELECT block_hash FROM blocks WHERE height = ?",
                    (block.height - 1,),
                ).fetchone()
                if parent and parent["block_hash"] != block.previous_hash:
                    raise IndexerError("new block does not extend the indexed parent")
                self._insert_block(block, observed_at)

            self._rebuild_balances()
            if expected_chain_id:
                self.connection.execute(
                    "INSERT OR REPLACE INTO metadata(key, value) VALUES('chain_id', ?)",
                    (expected_chain_id,),
                )

        return {
            "blocks": len(parsed),
            "tip": parsed[-1].height if parsed else -1,
            "reorg_height": -1 if reorg_height is None else reorg_height,
        }

    def summary(self) -> dict[str, int | str | None]:
        row = self.connection.execute(
            """
            SELECT COUNT(*) AS blocks, MAX(height) AS tip,
                   COALESCE((SELECT SUM(amount) FROM rewards), 0) AS total_rewards,
                   (SELECT COUNT(*) FROM transactions) AS transactions,
                   (SELECT COUNT(*) FROM balances) AS addresses
            FROM blocks
            """
        ).fetchone()
        chain = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'chain_id'"
        ).fetchone()
        return {
            "chain_id": chain["value"] if chain else None,
            "blocks": row["blocks"],
            "tip": row["tip"],
            "total_rewards": row["total_rewards"],
            "transactions": row["transactions"],
            "addresses": row["addresses"],
        }

    def public_export(self, *, genesis_unix: int | None = None) -> dict[str, Any]:
        block_rows = self.connection.execute(
            """
            SELECT b.height, b.block_hash, b.previous_hash, b.chain_id, b.epoch,
                   b.winning_device_id, r.address AS reward_address,
                   r.amount AS reward_amount
            FROM blocks b LEFT JOIN rewards r ON r.block_height = b.height
            ORDER BY b.height
            """
        ).fetchall()
        reward_rows = self.connection.execute(
            """
            SELECT block_height, address, amount, winning_device_id
            FROM rewards ORDER BY block_height
            """
        ).fetchall()
        balances = self.connection.execute(
            "SELECT address, amount FROM balances ORDER BY address"
        ).fetchall()
        hourly_stats = self.connection.execute(
            """
            SELECT (b.epoch / 120) AS epoch_hour_bucket,
                   COUNT(*) AS blocks, COALESCE(SUM(r.amount), 0) AS rewards
            FROM blocks b LEFT JOIN rewards r ON r.block_height = b.height
            GROUP BY epoch_hour_bucket
            ORDER BY epoch_hour_bucket
            """
        ).fetchall()
        daily_stats = self.connection.execute(
            """
            SELECT (b.epoch / 2880) AS epoch_day_bucket,
                   COUNT(*) AS blocks, COALESCE(SUM(r.amount), 0) AS rewards
            FROM blocks b LEFT JOIN rewards r ON r.block_height = b.height
            GROUP BY epoch_day_bucket
            ORDER BY epoch_day_bucket
            """
        ).fetchall()

        def block_item(row: sqlite3.Row) -> dict[str, Any]:
            item = dict(row)
            item["estimated_unix"] = (
                genesis_unix + item["epoch"] * 30
                if genesis_unix is not None
                else None
            )
            return item

        return {
            "format": "EPDN public index export v1",
            "generated_at_unix": int(time.time()),
            "calendar_time_basis": (
                {"genesis_unix": genesis_unix, "epoch_seconds": 30}
                if genesis_unix is not None
                else None
            ),
            "summary": self.summary(),
            "blocks": [block_item(row) for row in block_rows],
            "rewards": [dict(row) for row in reward_rows],
            "balances": [dict(row) for row in balances],
            "hourly_stats": [dict(row) for row in hourly_stats],
            "daily_stats": [dict(row) for row in daily_stats],
        }

    def _delete_from(self, height: int) -> None:
        self.connection.execute("DELETE FROM blocks WHERE height >= ?", (height,))

    def _clear(self) -> None:
        self.connection.execute("DELETE FROM transactions")
        self.connection.execute("DELETE FROM rewards")
        self.connection.execute("DELETE FROM blocks")
        self.connection.execute("DELETE FROM balances")
        self.connection.execute("DELETE FROM metadata")

    def _insert_block(self, block: ParsedBlock, observed_at: int) -> None:
        self.connection.execute(
            """
            INSERT INTO blocks(
                height, block_hash, previous_hash, chain_id, epoch,
                winning_device_id, observed_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                block.height,
                block.block_hash,
                block.previous_hash,
                block.chain_id,
                block.epoch,
                block.winning_device_id,
                observed_at,
                block.raw_json,
            ),
        )
        if block.reward_address is not None and block.reward_amount is not None:
            self.connection.execute(
                """
                INSERT INTO rewards(block_height, address, amount, winning_device_id)
                VALUES (?, ?, ?, ?)
                """,
                (
                    block.height,
                    block.reward_address,
                    block.reward_amount,
                    block.winning_device_id,
                ),
            )
        for ordinal, transaction in enumerate(block.transactions):
            self.connection.execute(
                """
                INSERT INTO transactions(
                    block_height, ordinal, kind, sender, recipient,
                    amount, fee, nonce, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block.height,
                    ordinal,
                    transaction.kind,
                    transaction.sender,
                    transaction.recipient,
                    transaction.amount,
                    transaction.fee,
                    transaction.nonce,
                    transaction.raw_json,
                ),
            )

    def _rebuild_balances(self) -> None:
        amounts: dict[str, int] = {}
        for row in self.connection.execute("SELECT address, amount FROM rewards"):
            amounts[row["address"]] = amounts.get(row["address"], 0) + row["amount"]
        for row in self.connection.execute(
            """
            SELECT kind, sender, recipient, amount, fee
            FROM transactions WHERE kind = 'transfer'
            ORDER BY block_height, ordinal
            """
        ):
            amount = row["amount"] or 0
            debit = amount + (row["fee"] or 0)
            amounts[row["sender"]] = amounts.get(row["sender"], 0) - debit
            amounts[row["recipient"]] = amounts.get(row["recipient"], 0) + amount
        self.connection.execute("DELETE FROM balances")
        if any(
            amount < -SQLITE_INTEGER_MAX or amount > SQLITE_INTEGER_MAX
            for amount in amounts.values()
        ):
            raise IndexerError("derived balance exceeds the SQLite MVP integer limit")
        self.connection.executemany(
            "INSERT INTO balances(address, amount) VALUES (?, ?)",
            sorted(amounts.items()),
        )
