use std::collections::BTreeMap;

use p256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    encoding::{ensure_exact_length, EncodeError, Encoder},
    transaction::{transaction_merkle_root, ChainTransaction, SignedTransfer, TransactionError},
    types::{
        hash_domain, Address, Hash32, SecurityClass, EPDN_PROTOCOL_VERSION, MAX_CHAIN_ID_BYTES,
    },
};

const BLOCK_HEADER_TYPE: u8 = 5;
const P256_COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;
const P256_RAW_SIGNATURE_BYTES: usize = 64;
pub const REVOCATION_ONLY_MARKER: Hash32 = [0; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardRecord {
    pub address: Address,
    pub amount: u64,
    pub winning_device_id: Hash32,
}

impl RewardRecord {
    #[must_use]
    pub const fn revocation_only() -> Self {
        Self {
            address: REVOCATION_ONLY_MARKER,
            amount: 0,
            winning_device_id: REVOCATION_ONLY_MARKER,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub protocol_version: u16,
    pub chain_id: String,
    pub height: u64,
    pub previous_block_hash: Hash32,
    pub epoch_number: u64,
    pub epoch_randomness: Hash32,
    pub winning_ticket: Hash32,
    pub winning_submission_hash: Hash32,
    pub winning_certificate_hash: Hash32,
    pub winning_device_public_key_hash: Hash32,
    pub security_class: SecurityClass,
    pub firmware_id: Hash32,
    pub attestation_hash: Option<Hash32>,
    pub transaction_merkle_root: Hash32,
    pub device_registry_root: Hash32,
    pub revocation_root: Hash32,
}

impl BlockHeader {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::with_header(BLOCK_HEADER_TYPE, self.protocol_version);
        encoder.string("chain_id", &self.chain_id, MAX_CHAIN_ID_BYTES)?;
        encoder.u64(self.height);
        encoder.fixed(&self.previous_block_hash);
        encoder.u64(self.epoch_number);
        encoder.fixed(&self.epoch_randomness);
        encoder.fixed(&self.winning_ticket);
        encoder.fixed(&self.winning_submission_hash);
        encoder.fixed(&self.winning_certificate_hash);
        encoder.fixed(&self.winning_device_public_key_hash);
        encoder.u8(self.security_class as u8);
        encoder.fixed(&self.firmware_id);
        match self.attestation_hash {
            Some(hash) => {
                encoder.u8(1);
                encoder.fixed(&hash);
            }
            None => encoder.u8(0),
        }
        encoder.fixed(&self.transaction_merkle_root);
        encoder.fixed(&self.device_registry_root);
        encoder.fixed(&self.revocation_root);
        Ok(encoder.finish())
    }

    pub fn block_hash(&self) -> Result<Hash32, EncodeError> {
        Ok(hash_domain(b"EPDN_BLOCK_V1", &[&self.canonical_bytes()?]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_id: Hash32,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub reward: RewardRecord,
    pub transactions: Vec<ChainTransaction>,
    /// Sorted by validator ID, with at most one entry per validator.
    pub validator_signatures: Vec<ValidatorSignature>,
    pub block_hash: Hash32,
}

#[derive(Debug, Error)]
pub enum BlockError {
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error("unsupported block protocol version {0}")]
    UnsupportedProtocol(u16),
    #[error("transaction Merkle root does not match the block header")]
    WrongTransactionRoot,
    #[error("block must contain exactly one reward-distribution transaction")]
    WrongRewardTransactionCount,
    #[error("block reward record does not match its committed reward transaction")]
    RewardMismatch,
    #[error("revocation-only block marker or transaction set is invalid")]
    InvalidRevocationOnlyBlock,
    #[error("transaction context does not match the containing block")]
    TransactionContextMismatch,
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("stored block hash does not match the canonical header")]
    WrongBlockHash,
    #[error("validator already signed this block")]
    DuplicateValidatorSignature,
    #[error("validator signature length is invalid")]
    InvalidSignatureLength,
    #[error("validator public key is invalid")]
    InvalidValidatorKey,
    #[error("validator identifier does not match its public key")]
    WrongValidatorId,
    #[error("validator signature is invalid")]
    InvalidSignature,
    #[error("validator signing failed")]
    SigningFailed,
    #[error("block transactions are not in canonical order")]
    NonCanonicalTransactionOrder,
}

impl Block {
    pub fn new(
        header: BlockHeader,
        reward: RewardRecord,
        transactions: Vec<ChainTransaction>,
    ) -> Result<Self, BlockError> {
        if header.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(BlockError::UnsupportedProtocol(header.protocol_version));
        }
        ensure_canonical_transaction_order(&transactions)?;
        if header.transaction_merkle_root != transaction_merkle_root(&transactions)? {
            return Err(BlockError::WrongTransactionRoot);
        }
        ensure_transactions_match_block(&header, &reward, &transactions)?;
        let block_hash = header.block_hash()?;
        Ok(Self {
            header,
            reward,
            transactions,
            validator_signatures: Vec::new(),
            block_hash,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), BlockError> {
        if self.header.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(BlockError::UnsupportedProtocol(
                self.header.protocol_version,
            ));
        }
        ensure_canonical_transaction_order(&self.transactions)?;
        if self.header.transaction_merkle_root != transaction_merkle_root(&self.transactions)? {
            return Err(BlockError::WrongTransactionRoot);
        }
        ensure_transactions_match_block(&self.header, &self.reward, &self.transactions)?;
        if self.block_hash != self.header.block_hash()? {
            return Err(BlockError::WrongBlockHash);
        }
        if self
            .validator_signatures
            .windows(2)
            .any(|window| window[0].validator_id >= window[1].validator_id)
        {
            return Err(BlockError::DuplicateValidatorSignature);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_revocation_only(&self) -> bool {
        self.header.winning_device_public_key_hash == REVOCATION_ONLY_MARKER
            && has_complete_revocation_only_marker(&self.header)
            && self.reward == RewardRecord::revocation_only()
    }

    pub fn sign(&mut self, validator_key: &SigningKey) -> Result<(), BlockError> {
        let validator_id = hash_domain(
            b"EPDN_VALIDATOR_ID_V1",
            &[validator_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()],
        );
        if self
            .validator_signatures
            .iter()
            .any(|entry| entry.validator_id == validator_id)
        {
            return Err(BlockError::DuplicateValidatorSignature);
        }
        let message = hash_domain(b"EPDN_BLOCK_SIGNATURE_V1", &[&self.block_hash]);
        let signature: Signature = validator_key
            .sign_prehash(&message)
            .map_err(|_| BlockError::SigningFailed)?;
        self.validator_signatures.push(ValidatorSignature {
            validator_id,
            signature: signature.to_bytes().to_vec(),
        });
        self.validator_signatures
            .sort_unstable_by_key(|entry| entry.validator_id);
        Ok(())
    }

    pub fn verify_validator_signature(
        &self,
        signature: &ValidatorSignature,
        validator_public_key: &[u8],
    ) -> Result<(), BlockError> {
        if validator_public_key.len() != P256_COMPRESSED_PUBLIC_KEY_BYTES {
            return Err(BlockError::InvalidValidatorKey);
        }
        let expected_id = hash_domain(b"EPDN_VALIDATOR_ID_V1", &[validator_public_key]);
        if signature.validator_id != expected_id {
            return Err(BlockError::WrongValidatorId);
        }
        ensure_exact_length(
            "validator_signature",
            &signature.signature,
            P256_RAW_SIGNATURE_BYTES,
        )
        .map_err(|_| BlockError::InvalidSignatureLength)?;
        let signature = Signature::from_slice(&signature.signature)
            .map_err(|_| BlockError::InvalidSignatureLength)?;
        let public_key = VerifyingKey::from_sec1_bytes(validator_public_key)
            .map_err(|_| BlockError::InvalidValidatorKey)?;
        let message = hash_domain(b"EPDN_BLOCK_SIGNATURE_V1", &[&self.block_hash]);
        public_key
            .verify_prehash(&message, &signature)
            .map_err(|_| BlockError::InvalidSignature)
    }
}

fn ensure_transactions_match_block(
    header: &BlockHeader,
    reward: &RewardRecord,
    transactions: &[ChainTransaction],
) -> Result<(), BlockError> {
    if header.winning_device_public_key_hash == REVOCATION_ONLY_MARKER {
        if !has_complete_revocation_only_marker(header)
            || reward != &RewardRecord::revocation_only()
            || transactions.is_empty()
            || transactions
                .iter()
                .any(|transaction| !matches!(transaction, ChainTransaction::DeviceRevocation(_)))
        {
            return Err(BlockError::InvalidRevocationOnlyBlock);
        }
        for transaction in transactions {
            let ChainTransaction::DeviceRevocation(revocation) = transaction else {
                return Err(BlockError::InvalidRevocationOnlyBlock);
            };
            revocation.canonical_bytes()?;
            if revocation.chain_id != header.chain_id
                || revocation.effective_block_height != header.height
            {
                return Err(BlockError::TransactionContextMismatch);
            }
        }
        return Ok(());
    }

    let mut rewards = Vec::new();
    for transaction in transactions {
        match transaction {
            ChainTransaction::Transfer(transfer) => transfer.verify(&header.chain_id)?,
            ChainTransaction::DeviceRevocation(revocation) => {
                revocation.canonical_bytes()?;
                if revocation.chain_id != header.chain_id
                    || revocation.effective_block_height != header.height
                {
                    return Err(BlockError::TransactionContextMismatch);
                }
            }
            ChainTransaction::RewardDistribution(committed_reward) => {
                rewards.push(committed_reward);
            }
        }
    }
    let [committed] = rewards.as_slice() else {
        return Err(BlockError::WrongRewardTransactionCount);
    };
    if committed.protocol_version != header.protocol_version
        || committed.chain_id != header.chain_id
        || committed.recipient_address != reward.address
        || committed.amount != reward.amount
        || committed.winning_device_id != reward.winning_device_id
        || committed.winning_device_id != header.winning_device_public_key_hash
        || committed.epoch_number != header.epoch_number
    {
        return Err(BlockError::RewardMismatch);
    }
    Ok(())
}

fn has_complete_revocation_only_marker(header: &BlockHeader) -> bool {
    header.winning_ticket == REVOCATION_ONLY_MARKER
        && header.winning_submission_hash == REVOCATION_ONLY_MARKER
        && header.winning_certificate_hash == REVOCATION_ONLY_MARKER
        && header.winning_device_public_key_hash == REVOCATION_ONLY_MARKER
        && header.security_class == SecurityClass::L0SoftwareTest
        && header.firmware_id == REVOCATION_ONLY_MARKER
        && header.attestation_hash.is_none()
}

fn ensure_canonical_transaction_order(transactions: &[ChainTransaction]) -> Result<(), BlockError> {
    let keys = transactions
        .iter()
        .map(ChainTransaction::canonical_order_key)
        .collect::<Result<Vec<_>, _>>()?;
    if keys.windows(2).any(|window| window[0] >= window[1]) {
        Err(BlockError::NonCanonicalTransactionOrder)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u64,
    pub next_nonce: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    accounts: BTreeMap<Address, AccountState>,
    fees_collected: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LedgerError {
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("account balance overflow")]
    BalanceOverflow,
    #[error("transaction nonce {actual} does not match expected nonce {expected}")]
    WrongNonce { actual: u64, expected: u64 },
    #[error("account has insufficient balance")]
    InsufficientBalance,
    #[error("account nonce overflow")]
    NonceOverflow,
    #[error("fee pool overflow")]
    FeeOverflow,
}

impl Ledger {
    pub fn credit(&mut self, address: Address, amount: u64) -> Result<u64, LedgerError> {
        let account = self.accounts.entry(address).or_default();
        let updated = account
            .balance
            .checked_add(amount)
            .ok_or(LedgerError::BalanceOverflow)?;
        account.balance = updated;
        Ok(updated)
    }

    pub fn apply_transfer(
        &mut self,
        transfer: &SignedTransfer,
        expected_chain_id: &str,
    ) -> Result<Hash32, LedgerError> {
        transfer.verify(expected_chain_id)?;
        let total = transfer
            .amount
            .checked_add(transfer.fee)
            .ok_or(TransactionError::AmountOverflow)?;
        let sender = self
            .accounts
            .get(&transfer.sender_address)
            .cloned()
            .unwrap_or_default();
        if transfer.nonce != sender.next_nonce {
            return Err(LedgerError::WrongNonce {
                actual: transfer.nonce,
                expected: sender.next_nonce,
            });
        }
        if sender.balance < total {
            return Err(LedgerError::InsufficientBalance);
        }
        let next_nonce = sender
            .next_nonce
            .checked_add(1)
            .ok_or(LedgerError::NonceOverflow)?;
        let next_fee_pool = self
            .fees_collected
            .checked_add(transfer.fee)
            .ok_or(LedgerError::FeeOverflow)?;
        if transfer.sender_address == transfer.recipient_address {
            self.accounts.insert(
                transfer.sender_address,
                AccountState {
                    balance: sender.balance - transfer.fee,
                    next_nonce,
                },
            );
        } else {
            let recipient = self
                .accounts
                .get(&transfer.recipient_address)
                .cloned()
                .unwrap_or_default();
            let recipient_balance = recipient
                .balance
                .checked_add(transfer.amount)
                .ok_or(LedgerError::BalanceOverflow)?;
            self.accounts.insert(
                transfer.sender_address,
                AccountState {
                    balance: sender.balance - total,
                    next_nonce,
                },
            );
            self.accounts.insert(
                transfer.recipient_address,
                AccountState {
                    balance: recipient_balance,
                    next_nonce: recipient.next_nonce,
                },
            );
        }
        self.fees_collected = next_fee_pool;
        Ok(transfer
            .transaction_hash()
            .map_err(TransactionError::from)?)
    }

    #[must_use]
    pub fn balance(&self, address: &Address) -> u64 {
        self.accounts
            .get(address)
            .map(|account| account.balance)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn next_nonce(&self, address: &Address) -> u64 {
        self.accounts
            .get(address)
            .map(|account| account.next_nonce)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn fees_collected(&self) -> u64 {
        self.fees_collected
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Address, &AccountState)> {
        self.accounts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{ChainTransaction, DeviceRevocationTransaction, RewardTransaction};

    fn header(reward: &RewardRecord) -> BlockHeader {
        BlockHeader {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            height: 1,
            previous_block_hash: [0; 32],
            epoch_number: 1,
            epoch_randomness: [1; 32],
            winning_ticket: [2; 32],
            winning_submission_hash: [3; 32],
            winning_certificate_hash: [4; 32],
            winning_device_public_key_hash: reward.winning_device_id,
            security_class: SecurityClass::L2NativeHardwareIdentity,
            firmware_id: [5; 32],
            attestation_hash: None,
            transaction_merkle_root: [0; 32],
            device_registry_root: [6; 32],
            revocation_root: [7; 32],
        }
    }

    #[test]
    fn block_hash_and_reward_ledger_are_deterministic() {
        let reward = RewardRecord {
            address: [8; 32],
            amount: 100,
            winning_device_id: [9; 32],
        };
        let reward_tx = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            recipient_address: reward.address,
            amount: reward.amount,
            winning_device_id: reward.winning_device_id,
            epoch_number: 1,
        });
        let transactions = vec![reward_tx];
        let mut first_header = header(&reward);
        first_header.transaction_merkle_root =
            transaction_merkle_root(&transactions).expect("root");
        let first =
            Block::new(first_header.clone(), reward.clone(), transactions.clone()).expect("block");
        let second = Block::new(first_header, reward.clone(), transactions).expect("block");
        assert_eq!(first.block_hash, second.block_hash);

        let mut ledger = Ledger::default();
        assert_eq!(ledger.credit(reward.address, reward.amount), Ok(100));
        assert_eq!(ledger.balance(&reward.address), 100);
    }

    #[test]
    fn validator_signature_is_bound_to_block_hash() {
        let reward = RewardRecord {
            address: [8; 32],
            amount: 100,
            winning_device_id: [9; 32],
        };
        let key = SigningKey::from_slice(&[10; 32]).expect("valid key");
        let reward_tx = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            recipient_address: reward.address,
            amount: reward.amount,
            winning_device_id: reward.winning_device_id,
            epoch_number: 1,
        });
        let transactions = vec![reward_tx];
        let mut block_header = header(&reward);
        block_header.transaction_merkle_root =
            transaction_merkle_root(&transactions).expect("root");
        let mut block = Block::new(block_header, reward, transactions).expect("block");
        block.sign(&key).expect("sign");
        block
            .verify_validator_signature(
                &block.validator_signatures[0],
                key.verifying_key().to_encoded_point(true).as_bytes(),
            )
            .expect("valid signature");
    }

    #[test]
    fn block_rejects_reward_record_tampering() {
        let reward = RewardRecord {
            address: [8; 32],
            amount: 100,
            winning_device_id: [9; 32],
        };
        let reward_tx = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            recipient_address: reward.address,
            amount: reward.amount,
            winning_device_id: reward.winning_device_id,
            epoch_number: 1,
        });
        let transactions = vec![reward_tx];
        let mut block_header = header(&reward);
        block_header.transaction_merkle_root =
            transaction_merkle_root(&transactions).expect("root");
        let mut block =
            Block::new(block_header, reward, transactions).expect("valid committed reward");
        block.reward.amount += 1;
        assert!(matches!(
            block.verify_integrity(),
            Err(BlockError::RewardMismatch)
        ));
    }

    #[test]
    fn block_rejects_missing_or_duplicate_reward_transactions() {
        let reward = RewardRecord {
            address: [8; 32],
            amount: 100,
            winning_device_id: [9; 32],
        };
        let mut empty_header = header(&reward);
        empty_header.transaction_merkle_root = transaction_merkle_root(&[]).expect("empty root");
        assert!(matches!(
            Block::new(empty_header, reward.clone(), Vec::new()),
            Err(BlockError::WrongRewardTransactionCount)
        ));

        let reward_tx = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            recipient_address: reward.address,
            amount: reward.amount,
            winning_device_id: reward.winning_device_id,
            epoch_number: 1,
        });
        let second_reward_tx = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            recipient_address: [10; 32],
            amount: reward.amount,
            winning_device_id: reward.winning_device_id,
            epoch_number: 1,
        });
        let mut transactions = vec![reward_tx, second_reward_tx];
        transactions.sort_unstable_by_key(|transaction| {
            transaction.canonical_order_key().expect("canonical key")
        });
        let mut duplicate_header = header(&reward);
        duplicate_header.transaction_merkle_root =
            transaction_merkle_root(&transactions).expect("root");
        assert!(matches!(
            Block::new(duplicate_header, reward, transactions),
            Err(BlockError::WrongRewardTransactionCount)
        ));
    }

    #[test]
    fn revocation_only_block_requires_complete_marker_and_only_revocations() {
        let revocation = ChainTransaction::DeviceRevocation(DeviceRevocationTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            device_id: [11; 32],
            reason: "compromised".to_owned(),
            effective_block_height: 1,
        });
        let transactions = vec![revocation];
        let reward = RewardRecord::revocation_only();
        let mut block_header = header(&reward);
        block_header.winning_ticket = REVOCATION_ONLY_MARKER;
        block_header.winning_submission_hash = REVOCATION_ONLY_MARKER;
        block_header.winning_certificate_hash = REVOCATION_ONLY_MARKER;
        block_header.winning_device_public_key_hash = REVOCATION_ONLY_MARKER;
        block_header.security_class = SecurityClass::L0SoftwareTest;
        block_header.firmware_id = REVOCATION_ONLY_MARKER;
        block_header.transaction_merkle_root =
            transaction_merkle_root(&transactions).expect("root");
        let block = Block::new(block_header.clone(), reward.clone(), transactions)
            .expect("valid revocation-only block");
        assert!(block.is_revocation_only());

        block_header.winning_ticket = [1; 32];
        assert!(matches!(
            Block::new(
                block_header,
                reward,
                vec![ChainTransaction::DeviceRevocation(
                    DeviceRevocationTransaction {
                        protocol_version: EPDN_PROTOCOL_VERSION,
                        chain_id: "epdn-test".to_owned(),
                        device_id: [11; 32],
                        reason: "compromised".to_owned(),
                        effective_block_height: 1,
                    }
                )],
            ),
            Err(BlockError::InvalidRevocationOnlyBlock)
        ));
    }

    #[test]
    fn failed_transfer_does_not_partially_mutate_ledger() {
        let key = SigningKey::from_slice(&[12; 32]).expect("valid key");
        let sender = hash_domain(
            b"EPDN_WALLET_ADDRESS_V1",
            &[key.verifying_key().to_encoded_point(true).as_bytes()],
        );
        let recipient = [13; 32];
        let transfer = SignedTransfer::create("epdn-test".to_owned(), recipient, 1, 0, 0, &key)
            .expect("transfer");
        let mut ledger = Ledger::default();
        ledger.credit(sender, 100).expect("fund sender");
        ledger
            .credit(recipient, u64::MAX)
            .expect("saturate recipient");
        assert!(matches!(
            ledger.apply_transfer(&transfer, "epdn-test"),
            Err(LedgerError::BalanceOverflow)
        ));
        assert_eq!(ledger.balance(&sender), 100);
        assert_eq!(ledger.next_nonce(&sender), 0);
    }
}
