use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    encoding::{ensure_exact_length, DecodeError, Decoder, EncodeError, Encoder},
    registry::MAX_REVOCATION_REASON_BYTES,
    types::{
        hash_domain, Address, Hash32, EPDN_PROTOCOL_VERSION, MAX_CHAIN_ID_BYTES,
        MAX_TRANSACTION_BYTES,
    },
};

const TRANSFER_OBJECT_TYPE: u8 = 6;
const REVOCATION_OBJECT_TYPE: u8 = 7;
const REWARD_OBJECT_TYPE: u8 = 8;
const P256_COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;
const P256_RAW_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TransactionKind {
    Transfer = 1,
    DeviceRegistration = 2,
    DeviceCertificateUpdate = 3,
    DeviceRevocation = 4,
    FirmwarePolicyUpdate = 5,
    ValidatorUpdate = 6,
    RewardDistribution = 7,
    MinerRewardAddressUpdate = 8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransfer {
    pub protocol_version: u16,
    pub chain_id: String,
    /// Canonical SEC1 compressed P-256 public key.
    pub sender_public_key: Vec<u8>,
    pub sender_address: Address,
    pub recipient_address: Address,
    pub amount: u64,
    pub fee: u64,
    /// Exact next account nonce, starting at zero.
    pub nonce: u64,
    /// Fixed-width P-256 ECDSA signature: 32-byte big-endian r || 32-byte s.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevocationTransaction {
    pub protocol_version: u16,
    pub chain_id: String,
    pub device_id: Hash32,
    pub reason: String,
    pub effective_block_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardTransaction {
    pub protocol_version: u16,
    pub chain_id: String,
    pub recipient_address: Address,
    pub amount: u64,
    pub winning_device_id: Hash32,
    pub epoch_number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ChainTransaction {
    Transfer(SignedTransfer),
    DeviceRevocation(DeviceRevocationTransaction),
    RewardDistribution(RewardTransaction),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransactionError {
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error(transparent)]
    Decoding(#[from] DecodeError),
    #[error("transaction is for chain {actual}, not {expected}")]
    WrongChain { actual: String, expected: String },
    #[error("sender address does not match the P-256 public key")]
    WrongSenderAddress,
    #[error("P-256 public key is invalid")]
    InvalidPublicKey,
    #[error("P-256 signature must be fixed-width 64-byte r || s")]
    InvalidSignatureLength,
    #[error("transaction signature is invalid")]
    InvalidSignature,
    #[error("unsupported transaction protocol version {0}")]
    UnsupportedProtocol(u16),
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("amount plus fee overflows u64")]
    AmountOverflow,
    #[error("revocation reason must not be empty")]
    RevocationReasonEmpty,
    #[error("revocation reason exceeds {MAX_REVOCATION_REASON_BYTES} bytes")]
    RevocationReasonTooLong,
}

impl SignedTransfer {
    pub fn create(
        chain_id: String,
        recipient_address: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        sender_key: &SigningKey,
    ) -> Result<Self, TransactionError> {
        if amount == 0 {
            return Err(TransactionError::ZeroAmount);
        }
        amount
            .checked_add(fee)
            .ok_or(TransactionError::AmountOverflow)?;
        let public_key = sender_key.verifying_key().to_encoded_point(true);
        let sender_public_key = public_key.as_bytes().to_vec();
        let sender_address = hash_domain(b"EPDN_WALLET_ADDRESS_V1", &[&sender_public_key]);
        let mut transfer = Self {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id,
            sender_public_key,
            sender_address,
            recipient_address,
            amount,
            fee,
            nonce,
            signature: vec![0; P256_RAW_SIGNATURE_BYTES],
        };
        let signature: Signature = sender_key.sign(&transfer.signature_payload()?);
        transfer.signature = signature.to_bytes().to_vec();
        Ok(transfer)
    }

    pub fn verify(&self, expected_chain_id: &str) -> Result<(), TransactionError> {
        if self.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(TransactionError::UnsupportedProtocol(self.protocol_version));
        }
        if self.chain_id != expected_chain_id {
            return Err(TransactionError::WrongChain {
                actual: self.chain_id.clone(),
                expected: expected_chain_id.to_owned(),
            });
        }
        if self.amount == 0 {
            return Err(TransactionError::ZeroAmount);
        }
        self.amount
            .checked_add(self.fee)
            .ok_or(TransactionError::AmountOverflow)?;
        ensure_exact_length(
            "sender_public_key",
            &self.sender_public_key,
            P256_COMPRESSED_PUBLIC_KEY_BYTES,
        )
        .map_err(|_| TransactionError::InvalidPublicKey)?;
        let expected_address = hash_domain(b"EPDN_WALLET_ADDRESS_V1", &[&self.sender_public_key]);
        if expected_address != self.sender_address {
            return Err(TransactionError::WrongSenderAddress);
        }
        ensure_exact_length("signature", &self.signature, P256_RAW_SIGNATURE_BYTES)
            .map_err(|_| TransactionError::InvalidSignatureLength)?;
        let public_key = VerifyingKey::from_sec1_bytes(&self.sender_public_key)
            .map_err(|_| TransactionError::InvalidPublicKey)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransactionError::InvalidSignatureLength)?;
        public_key
            .verify(&self.signature_payload()?, &signature)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        ensure_exact_length(
            "sender_public_key",
            &self.sender_public_key,
            P256_COMPRESSED_PUBLIC_KEY_BYTES,
        )?;
        let mut encoder = Encoder::with_header(TRANSFER_OBJECT_TYPE, self.protocol_version);
        encoder.u8(TransactionKind::Transfer as u8);
        encoder.string("chain_id", &self.chain_id, MAX_CHAIN_ID_BYTES)?;
        encoder.fixed(&self.sender_public_key);
        encoder.fixed(&self.sender_address);
        encoder.fixed(&self.recipient_address);
        encoder.u64(self.amount);
        encoder.u64(self.fee);
        encoder.u64(self.nonce);
        Ok(encoder.finish())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        ensure_exact_length("signature", &self.signature, P256_RAW_SIGNATURE_BYTES)?;
        let mut bytes = self.unsigned_canonical_bytes()?;
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(EncodeError::LengthExceeded {
                field: "transfer",
                actual: bytes.len(),
                maximum: MAX_TRANSACTION_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::with_header(
            input,
            MAX_TRANSACTION_BYTES,
            TRANSFER_OBJECT_TYPE,
            EPDN_PROTOCOL_VERSION,
        )?;
        let kind = decoder.u8()?;
        if kind != TransactionKind::Transfer as u8 {
            return Err(DecodeError::InvalidEnum {
                field: "transaction_kind",
                value: kind,
            });
        }
        let transfer = Self {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: decoder.string("chain_id", MAX_CHAIN_ID_BYTES)?,
            sender_public_key: decoder
                .fixed::<P256_COMPRESSED_PUBLIC_KEY_BYTES>()?
                .to_vec(),
            sender_address: decoder.fixed()?,
            recipient_address: decoder.fixed()?,
            amount: decoder.u64()?,
            fee: decoder.u64()?,
            nonce: decoder.u64()?,
            signature: decoder.bytes_u16("signature", P256_RAW_SIGNATURE_BYTES)?,
        };
        if transfer.signature.len() != P256_RAW_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical { field: "signature" });
        }
        decoder.finish()?;
        Ok(transfer)
    }

    pub fn transaction_hash(&self) -> Result<Hash32, EncodeError> {
        Ok(hash_domain(
            b"EPDN_TRANSACTION_V1",
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn signature_payload(&self) -> Result<Vec<u8>, EncodeError> {
        let unsigned = self.unsigned_canonical_bytes()?;
        let mut payload = Vec::with_capacity(b"EPDN_TRANSFER_SIGNATURE_V1".len() + unsigned.len());
        payload.extend_from_slice(b"EPDN_TRANSFER_SIGNATURE_V1");
        payload.extend_from_slice(&unsigned);
        Ok(payload)
    }
}

impl DeviceRevocationTransaction {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        if self.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(TransactionError::UnsupportedProtocol(self.protocol_version));
        }
        if self.reason.trim().is_empty() {
            return Err(TransactionError::RevocationReasonEmpty);
        }
        if self.reason.len() > MAX_REVOCATION_REASON_BYTES {
            return Err(TransactionError::RevocationReasonTooLong);
        }
        let mut encoder = Encoder::with_header(REVOCATION_OBJECT_TYPE, self.protocol_version);
        encoder.u8(TransactionKind::DeviceRevocation as u8);
        encoder.string("chain_id", &self.chain_id, MAX_CHAIN_ID_BYTES)?;
        encoder.fixed(&self.device_id);
        encoder.string(
            "revocation_reason",
            &self.reason,
            MAX_REVOCATION_REASON_BYTES,
        )?;
        encoder.u64(self.effective_block_height);
        Ok(encoder.finish())
    }

    pub fn transaction_hash(&self) -> Result<Hash32, TransactionError> {
        Ok(hash_domain(
            b"EPDN_TRANSACTION_V1",
            &[&self.canonical_bytes()?],
        ))
    }
}

impl RewardTransaction {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        if self.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(TransactionError::UnsupportedProtocol(self.protocol_version));
        }
        let mut encoder = Encoder::with_header(REWARD_OBJECT_TYPE, self.protocol_version);
        encoder.u8(TransactionKind::RewardDistribution as u8);
        encoder.string("chain_id", &self.chain_id, MAX_CHAIN_ID_BYTES)?;
        encoder.fixed(&self.recipient_address);
        encoder.u64(self.amount);
        encoder.fixed(&self.winning_device_id);
        encoder.u64(self.epoch_number);
        Ok(encoder.finish())
    }

    pub fn transaction_hash(&self) -> Result<Hash32, TransactionError> {
        Ok(hash_domain(
            b"EPDN_TRANSACTION_V1",
            &[&self.canonical_bytes()?],
        ))
    }
}

impl ChainTransaction {
    #[must_use]
    pub fn kind(&self) -> TransactionKind {
        match self {
            Self::Transfer(_) => TransactionKind::Transfer,
            Self::DeviceRevocation(_) => TransactionKind::DeviceRevocation,
            Self::RewardDistribution(_) => TransactionKind::RewardDistribution,
        }
    }

    pub fn transaction_hash(&self) -> Result<Hash32, TransactionError> {
        match self {
            Self::Transfer(transfer) => Ok(transfer.transaction_hash()?),
            Self::DeviceRevocation(revocation) => revocation.transaction_hash(),
            Self::RewardDistribution(reward) => reward.transaction_hash(),
        }
    }

    pub fn canonical_order_key(&self) -> Result<Vec<u8>, TransactionError> {
        let hash = self.transaction_hash()?;
        let mut key = Vec::with_capacity(73);
        key.push(self.kind() as u8);
        match self {
            Self::Transfer(transfer) => {
                key.extend_from_slice(&transfer.sender_address);
                key.extend_from_slice(&transfer.nonce.to_be_bytes());
            }
            Self::DeviceRevocation(revocation) => {
                key.extend_from_slice(&revocation.device_id);
            }
            Self::RewardDistribution(reward) => {
                key.extend_from_slice(&reward.epoch_number.to_be_bytes());
                key.extend_from_slice(&reward.recipient_address);
            }
        }
        key.extend_from_slice(&hash);
        Ok(key)
    }

    #[must_use]
    pub fn touches_address(&self, address: &Address) -> bool {
        match self {
            Self::Transfer(transfer) => {
                &transfer.sender_address == address || &transfer.recipient_address == address
            }
            Self::RewardDistribution(reward) => &reward.recipient_address == address,
            Self::DeviceRevocation(_) => false,
        }
    }
}

pub fn transaction_merkle_root(
    transactions: &[ChainTransaction],
) -> Result<Hash32, TransactionError> {
    if transactions.is_empty() {
        return Ok(hash_domain(b"EPDN_EMPTY_TRANSACTION_ROOT_V1", &[]));
    }
    let mut level = transactions
        .iter()
        .map(ChainTransaction::transaction_hash)
        .collect::<Result<Vec<_>, _>>()?;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_domain(
                b"EPDN_TRANSACTION_MERKLE_NODE_V1",
                &[&pair[0], right],
            ));
        }
        level = next;
    }
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_transfer_is_deterministic_and_round_trips() {
        let key = SigningKey::from_slice(&[21; 32]).expect("valid key");
        let first = SignedTransfer::create("epdn-test".to_owned(), [9; 32], 25, 2, 0, &key)
            .expect("transfer");
        let second = SignedTransfer::create("epdn-test".to_owned(), [9; 32], 25, 2, 0, &key)
            .expect("transfer");
        assert_eq!(first, second);
        first.verify("epdn-test").expect("valid signature");
        let bytes = first.canonical_bytes().expect("encode");
        assert_eq!(SignedTransfer::decode(&bytes).expect("decode"), first);
    }

    #[test]
    fn transfer_rejects_wrong_network_and_tampering() {
        let key = SigningKey::from_slice(&[21; 32]).expect("valid key");
        let mut transfer = SignedTransfer::create("epdn-test".to_owned(), [9; 32], 25, 2, 0, &key)
            .expect("transfer");
        assert!(matches!(
            transfer.verify("other-chain"),
            Err(TransactionError::WrongChain { .. })
        ));
        transfer.amount += 1;
        assert!(matches!(
            transfer.verify("epdn-test"),
            Err(TransactionError::InvalidSignature)
        ));
    }

    #[test]
    fn merkle_root_is_order_sensitive_and_repeatable() {
        let first = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            recipient_address: [1; 32],
            amount: 100,
            winning_device_id: [2; 32],
            epoch_number: 1,
        });
        let second = ChainTransaction::DeviceRevocation(DeviceRevocationTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            device_id: [3; 32],
            reason: "test".to_owned(),
            effective_block_height: 2,
        });
        let root = transaction_merkle_root(&[first.clone(), second.clone()]).expect("root");
        assert_eq!(
            root,
            transaction_merkle_root(&[first.clone(), second.clone()]).expect("root")
        );
        assert_ne!(
            root,
            transaction_merkle_root(&[second, first]).expect("root")
        );
    }

    #[test]
    fn revocation_reason_is_non_empty_and_byte_bounded() {
        let transaction = |reason: String| DeviceRevocationTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            device_id: [3; 32],
            reason,
            effective_block_height: 2,
        };
        assert!(matches!(
            transaction("  ".to_owned()).canonical_bytes(),
            Err(TransactionError::RevocationReasonEmpty)
        ));
        assert!(matches!(
            transaction("é".repeat(65)).canonical_bytes(),
            Err(TransactionError::RevocationReasonTooLong)
        ));
        transaction("operator request".to_owned())
            .canonical_bytes()
            .expect("valid reason");
    }
}
