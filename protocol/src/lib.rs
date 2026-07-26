//! Consensus-critical primitives for EPDN.
//!
//! Hash inputs use the explicitly specified EPDN deterministic binary encoding
//! V1. JSON is never used to derive a consensus hash.

pub mod block;
pub mod certificate;
pub mod consensus;
pub mod encoding;
pub mod randomness;
pub mod registry;
pub mod ticket;
pub mod transaction;
pub mod types;

pub use block::{
    AccountState, Block, BlockError, BlockHeader, Ledger, LedgerError, RewardRecord,
    ValidatorSignature, REVOCATION_ONLY_MARKER,
};
pub use certificate::{CertificateError, DeviceCertificate, DeviceCertificatePayload};
pub use consensus::{
    EpochContext, NetworkMode, TicketPool, TicketValidationError, ValidatedTicket,
};
pub use encoding::{DecodeError, EncodeError};
pub use randomness::{commitment_for, CommitRevealError, CommitRevealRound, RandomnessOutcome};
pub use registry::{DeviceRegistry, RegisteredDevice, RegistryError, Revocation};
pub use ticket::{TicketError, TicketSubmission};
pub use transaction::{
    transaction_merkle_root, ChainTransaction, DeviceRevocationTransaction, RewardTransaction,
    SignedTransfer, TransactionError, TransactionKind,
};
pub use types::{
    hash_domain, hex_lower, parse_hex_32, Address, EpochChallenge, Hash32, HexError, SecurityClass,
    BLOCK_REWARD, EPDN_PROTOCOL_VERSION, MAX_CERTIFICATE_BYTES, MAX_SUBMISSION_BYTES,
    MAX_TRANSACTION_BYTES,
};
