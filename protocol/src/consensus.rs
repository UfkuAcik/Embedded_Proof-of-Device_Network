use std::collections::{BTreeMap, BTreeSet};

use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::CertificateError,
    encoding::EncodeError,
    registry::DeviceRegistry,
    ticket::{TicketError, TicketSubmission},
    types::{Hash32, SecurityClass, EPDN_PROTOCOL_VERSION, MAX_SUBMISSION_BYTES},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Development,
    Testnet,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochContext {
    pub protocol_version: u16,
    pub chain_id: String,
    pub epoch_number: u64,
    pub previous_block_hash: Hash32,
    pub network_randomness: Hash32,
    pub approved_firmware_ids: BTreeSet<Hash32>,
    pub minimum_security_class: SecurityClass,
    pub network_mode: NetworkMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedTicket {
    pub device_id: Hash32,
    pub submission_hash: Hash32,
    pub score: Hash32,
    pub submission: TicketSubmission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketPool {
    context: EpochContext,
    accepted: BTreeMap<Hash32, ValidatedTicket>,
    seen_ticket_hashes: BTreeSet<Hash32>,
    seen_submission_hashes: BTreeSet<Hash32>,
}

#[derive(Debug, Error)]
pub enum TicketValidationError {
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    #[error(transparent)]
    Cryptographic(#[from] TicketError),
    #[error("submission exceeds {MAX_SUBMISSION_BYTES} bytes")]
    Oversized,
    #[error("unsupported protocol version {0}")]
    UnsupportedProtocol(u16),
    #[error("ticket is for chain {actual}, not {expected}")]
    WrongChain { actual: String, expected: String },
    #[error("ticket epoch {actual} is stale; current epoch is {current}")]
    StaleEpoch { actual: u64, current: u64 },
    #[error("ticket epoch {actual} is in the future; current epoch is {current}")]
    FutureEpoch { actual: u64, current: u64 },
    #[error("previous block hash does not match the current epoch")]
    WrongPreviousBlock,
    #[error("network randomness does not match the current epoch")]
    WrongRandomness,
    #[error("device is not registered")]
    UnregisteredDevice,
    #[error("device certificate is revoked")]
    RevokedDevice,
    #[error("firmware is not on the network allowlist")]
    FirmwareNotAllowed,
    #[error("firmware is not permitted by the device certificate")]
    FirmwareNotCertified,
    #[error("ticket attempts a security-class downgrade")]
    SecurityDowngrade,
    #[error("reported security class does not match the device certificate")]
    SecurityClassMismatch,
    #[error("device does not meet the registered minimum security class")]
    InsufficientSecurityClass,
    #[error("L0 software identity is forbidden on production")]
    L0ForbiddenOnProduction,
    #[error("device already submitted a ticket in this epoch")]
    DuplicateDeviceEpoch,
    #[error("ticket was already submitted")]
    DuplicateTicket,
    #[error("submission replay was already observed")]
    DuplicateSubmission,
    #[error("stored ticket pool is internally inconsistent")]
    InconsistentPool,
}

impl TicketPool {
    #[must_use]
    pub fn new(context: EpochContext) -> Self {
        Self {
            context,
            accepted: BTreeMap::new(),
            seen_ticket_hashes: BTreeSet::new(),
            seen_submission_hashes: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn context(&self) -> &EpochContext {
        &self.context
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ValidatedTicket> {
        self.accepted.values()
    }

    pub fn validate_and_add(
        &mut self,
        submission: TicketSubmission,
        registry: &DeviceRegistry,
        authority_key: &VerifyingKey,
    ) -> Result<&ValidatedTicket, TicketValidationError> {
        let encoded = submission.canonical_bytes()?;
        if encoded.len() > MAX_SUBMISSION_BYTES {
            return Err(TicketValidationError::Oversized);
        }
        let challenge = &submission.challenge;
        if challenge.protocol_version != EPDN_PROTOCOL_VERSION
            || challenge.protocol_version != self.context.protocol_version
        {
            return Err(TicketValidationError::UnsupportedProtocol(
                challenge.protocol_version,
            ));
        }
        if challenge.chain_id != self.context.chain_id {
            return Err(TicketValidationError::WrongChain {
                actual: challenge.chain_id.clone(),
                expected: self.context.chain_id.clone(),
            });
        }
        if challenge.epoch_number < self.context.epoch_number {
            return Err(TicketValidationError::StaleEpoch {
                actual: challenge.epoch_number,
                current: self.context.epoch_number,
            });
        }
        if challenge.epoch_number > self.context.epoch_number {
            return Err(TicketValidationError::FutureEpoch {
                actual: challenge.epoch_number,
                current: self.context.epoch_number,
            });
        }
        if challenge.previous_block_hash != self.context.previous_block_hash {
            return Err(TicketValidationError::WrongPreviousBlock);
        }
        if challenge.network_randomness != self.context.network_randomness {
            return Err(TicketValidationError::WrongRandomness);
        }

        let device = registry
            .get(&challenge.device_public_key_hash)
            .ok_or(TicketValidationError::UnregisteredDevice)?;
        if device.revocation.is_some() {
            return Err(TicketValidationError::RevokedDevice);
        }
        device.certificate.verify(
            authority_key,
            &self.context.chain_id,
            self.context.epoch_number,
        )?;

        let certified_class = device.certificate.payload.security_class;
        if challenge.security_class < certified_class {
            return Err(TicketValidationError::SecurityDowngrade);
        }
        if challenge.security_class != certified_class {
            return Err(TicketValidationError::SecurityClassMismatch);
        }
        if self.context.network_mode == NetworkMode::Production
            && certified_class == SecurityClass::L0SoftwareTest
        {
            return Err(TicketValidationError::L0ForbiddenOnProduction);
        }
        if certified_class < device.minimum_security_class
            || certified_class < self.context.minimum_security_class
        {
            return Err(TicketValidationError::InsufficientSecurityClass);
        }
        if !self
            .context
            .approved_firmware_ids
            .contains(&challenge.approved_firmware_id)
        {
            return Err(TicketValidationError::FirmwareNotAllowed);
        }
        if !device
            .certificate
            .payload
            .allowed_firmware_ids
            .contains(&challenge.approved_firmware_id)
        {
            return Err(TicketValidationError::FirmwareNotCertified);
        }

        let submission_hash = submission.submission_hash()?;
        if self.seen_submission_hashes.contains(&submission_hash) {
            return Err(TicketValidationError::DuplicateSubmission);
        }
        if self.seen_ticket_hashes.contains(&submission.ticket) {
            return Err(TicketValidationError::DuplicateTicket);
        }
        if self
            .accepted
            .contains_key(&challenge.device_public_key_hash)
        {
            return Err(TicketValidationError::DuplicateDeviceEpoch);
        }

        submission.verify_crypto(&device.certificate.payload.device_public_key)?;
        let device_id = challenge.device_public_key_hash;
        let validated = ValidatedTicket {
            device_id,
            submission_hash,
            score: submission.score(),
            submission,
        };
        self.seen_submission_hashes.insert(submission_hash);
        self.seen_ticket_hashes.insert(validated.submission.ticket);
        self.accepted.insert(device_id, validated);
        self.accepted
            .get(&device_id)
            .ok_or(TicketValidationError::UnregisteredDevice)
    }

    pub fn verify_integrity(
        &self,
        registry: &DeviceRegistry,
        authority_key: &VerifyingKey,
    ) -> Result<(), TicketValidationError> {
        let mut replayed = Self::new(self.context.clone());
        for ticket in self.accepted.values() {
            replayed.validate_and_add(ticket.submission.clone(), registry, authority_key)?;
        }
        if &replayed != self {
            return Err(TicketValidationError::InconsistentPool);
        }
        Ok(())
    }

    #[must_use]
    pub fn winner(&self) -> Option<&ValidatedTicket> {
        self.accepted
            .values()
            .min_by_key(|ticket| (ticket.score, ticket.device_id, ticket.submission_hash))
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;

    #[test]
    fn ticket_pool_integrity_replays_from_an_empty_pool_and_checks_exact_equality() {
        let context = EpochContext {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            epoch_number: 1,
            previous_block_hash: [0; 32],
            network_randomness: [1; 32],
            approved_firmware_ids: BTreeSet::from([[2; 32]]),
            minimum_security_class: SecurityClass::L0SoftwareTest,
            network_mode: NetworkMode::Testnet,
        };
        let authority = SigningKey::from_slice(&[3; 32]).expect("valid key");
        let registry = DeviceRegistry::default();
        let pool = TicketPool::new(context);
        pool.verify_integrity(&registry, authority.verifying_key())
            .expect("empty pool is self-consistent");

        let mut corrupted = pool;
        corrupted.seen_submission_hashes.insert([4; 32]);
        assert!(matches!(
            corrupted.verify_integrity(&registry, authority.verifying_key()),
            Err(TicketValidationError::InconsistentPool)
        ));
    }
}
