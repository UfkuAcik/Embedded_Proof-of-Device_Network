use std::collections::{BTreeMap, BTreeSet};

use epdn_protocol::{
    hash_domain, transaction_merkle_root, Address, Block, BlockError, BlockHeader,
    CertificateError, ChainTransaction, DeviceCertificate, DeviceCertificatePayload,
    DeviceRegistry, DeviceRevocationTransaction, EncodeError, EpochChallenge, EpochContext, Hash32,
    Ledger, LedgerError, NetworkMode, RegistryError, RewardRecord, RewardTransaction,
    SecurityClass, SignedTransfer, TicketPool, TicketSubmission, TicketValidationError,
    TransactionError, ValidatedTicket, ValidatorSignature, BLOCK_REWARD, EPDN_PROTOCOL_VERSION,
    REVOCATION_ONLY_MARKER,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub chain_id: String,
    pub network_mode: NetworkMode,
    pub minimum_security_class: SecurityClass,
    pub approved_firmware_ids: BTreeSet<Hash32>,
    pub reward_amount: u64,
}

impl NodeConfig {
    #[must_use]
    pub fn local_testnet() -> Self {
        Self {
            chain_id: "epdn-local-testnet-v1".to_owned(),
            network_mode: NetworkMode::Testnet,
            minimum_security_class: SecurityClass::L0SoftwareTest,
            approved_firmware_ids: BTreeSet::from([hash_domain(
                b"EPDN_FIRMWARE_ID_V1",
                &[b"epdn-miner-development"],
            )]),
            reward_amount: BLOCK_REWARD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    /// Canonical SEC1 compressed P-256 public key.
    pub device_public_key: Vec<u8>,
    pub platform: String,
    pub board_family: String,
    pub security_class: SecurityClass,
    pub provisioned_at_unix_seconds: u64,
    pub chip_revision: Option<String>,
    pub batch_id: Option<String>,
    pub manufacturer: Option<String>,
    pub allowed_firmware_ids: Vec<Hash32>,
    pub expires_at_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCore {
    config: NodeConfig,
    registry: DeviceRegistry,
    registration_heights: BTreeMap<Hash32, u64>,
    ticket_pool: TicketPool,
    ledger: Ledger,
    blocks: Vec<Block>,
    transactions: BTreeMap<Hash32, TransactionRecord>,
    pending_transactions: BTreeSet<Hash32>,
    paused_devices: BTreeSet<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub hash: Hash32,
    pub transaction: ChainTransaction,
    pub submitted_epoch: u64,
    pub included_block_height: Option<u64>,
}

/// Stable authenticated local-snapshot payload for record format V3.
///
/// This deliberately mirrors `NodeCore` instead of serializing it directly.
/// `ChainTransaction` uses an internally tagged representation for REST JSON,
/// which bincode cannot deserialize. The storage-only enum below uses bincode's
/// data-model-compatible external variant index. Any field or variant change
/// here requires a journal record-version bump and an explicit migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredNodeCoreV3 {
    config: NodeConfig,
    registry: DeviceRegistry,
    registration_heights: BTreeMap<Hash32, u64>,
    ticket_pool: TicketPool,
    ledger: Ledger,
    blocks: Vec<StoredBlockV2>,
    transactions: BTreeMap<Hash32, StoredTransactionRecordV2>,
    pending_transactions: BTreeSet<Hash32>,
    paused_devices: BTreeSet<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredBlockV2 {
    header: BlockHeader,
    reward: RewardRecord,
    transactions: Vec<StoredChainTransactionV2>,
    validator_signatures: Vec<ValidatorSignature>,
    block_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredTransactionRecordV2 {
    hash: Hash32,
    transaction: StoredChainTransactionV2,
    submitted_epoch: u64,
    included_block_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum StoredChainTransactionV2 {
    Transfer(SignedTransfer),
    DeviceRevocation(DeviceRevocationTransaction),
    RewardDistribution(RewardTransaction),
}

impl From<&NodeCore> for StoredNodeCoreV3 {
    fn from(state: &NodeCore) -> Self {
        Self {
            config: state.config.clone(),
            registry: state.registry.clone(),
            registration_heights: state.registration_heights.clone(),
            ticket_pool: state.ticket_pool.clone(),
            ledger: state.ledger.clone(),
            blocks: state.blocks.iter().map(StoredBlockV2::from).collect(),
            transactions: state
                .transactions
                .iter()
                .map(|(hash, record)| (*hash, StoredTransactionRecordV2::from(record)))
                .collect(),
            pending_transactions: state.pending_transactions.clone(),
            paused_devices: state.paused_devices.clone(),
        }
    }
}

impl From<StoredNodeCoreV3> for NodeCore {
    fn from(state: StoredNodeCoreV3) -> Self {
        Self {
            config: state.config,
            registry: state.registry,
            registration_heights: state.registration_heights,
            ticket_pool: state.ticket_pool,
            ledger: state.ledger,
            blocks: state.blocks.into_iter().map(Block::from).collect(),
            transactions: state
                .transactions
                .into_iter()
                .map(|(hash, record)| (hash, TransactionRecord::from(record)))
                .collect(),
            pending_transactions: state.pending_transactions,
            paused_devices: state.paused_devices,
        }
    }
}

impl From<&Block> for StoredBlockV2 {
    fn from(block: &Block) -> Self {
        Self {
            header: block.header.clone(),
            reward: block.reward.clone(),
            transactions: block
                .transactions
                .iter()
                .map(StoredChainTransactionV2::from)
                .collect(),
            validator_signatures: block.validator_signatures.clone(),
            block_hash: block.block_hash,
        }
    }
}

impl From<StoredBlockV2> for Block {
    fn from(block: StoredBlockV2) -> Self {
        Self {
            header: block.header,
            reward: block.reward,
            transactions: block
                .transactions
                .into_iter()
                .map(ChainTransaction::from)
                .collect(),
            validator_signatures: block.validator_signatures,
            block_hash: block.block_hash,
        }
    }
}

impl From<&TransactionRecord> for StoredTransactionRecordV2 {
    fn from(record: &TransactionRecord) -> Self {
        Self {
            hash: record.hash,
            transaction: StoredChainTransactionV2::from(&record.transaction),
            submitted_epoch: record.submitted_epoch,
            included_block_height: record.included_block_height,
        }
    }
}

impl From<StoredTransactionRecordV2> for TransactionRecord {
    fn from(record: StoredTransactionRecordV2) -> Self {
        Self {
            hash: record.hash,
            transaction: ChainTransaction::from(record.transaction),
            submitted_epoch: record.submitted_epoch,
            included_block_height: record.included_block_height,
        }
    }
}

impl From<&ChainTransaction> for StoredChainTransactionV2 {
    fn from(transaction: &ChainTransaction) -> Self {
        match transaction {
            ChainTransaction::Transfer(transfer) => Self::Transfer(transfer.clone()),
            ChainTransaction::DeviceRevocation(revocation) => {
                Self::DeviceRevocation(revocation.clone())
            }
            ChainTransaction::RewardDistribution(reward) => {
                Self::RewardDistribution(reward.clone())
            }
        }
    }
}

impl From<StoredChainTransactionV2> for ChainTransaction {
    fn from(transaction: StoredChainTransactionV2) -> Self {
        match transaction {
            StoredChainTransactionV2::Transfer(transfer) => Self::Transfer(transfer),
            StoredChainTransactionV2::DeviceRevocation(revocation) => {
                Self::DeviceRevocation(revocation)
            }
            StoredChainTransactionV2::RewardDistribution(reward) => {
                Self::RewardDistribution(reward)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Ticket(#[from] TicketValidationError),
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error(transparent)]
    Block(#[from] BlockError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("transaction hash was already accepted")]
    TransactionReplay,
    #[error("certificate expiry must be after the current epoch")]
    InvalidCertificateExpiry,
    #[error("certificate contains firmware outside the node allowlist")]
    FirmwareOutsideAllowlist,
    #[error("there are no accepted tickets to finalize")]
    NoTickets,
    #[error("device is not registered")]
    DeviceNotRegistered,
    #[error("device certificate is revoked")]
    DeviceRevoked,
    #[error("device is administratively paused")]
    DevicePaused,
    #[error("winner disappeared from the registry")]
    WinnerNotRegistered,
    #[error("loaded state uses a different node configuration")]
    ConfigurationMismatch,
    #[error("loaded block chain is internally inconsistent")]
    InvalidStoredChain,
}

impl NodeCore {
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        let genesis_randomness = hash_domain(
            b"EPDN_INSECURE_DEV_RANDOMNESS_V1",
            &[config.chain_id.as_bytes(), &1_u64.to_be_bytes()],
        );
        let context = EpochContext {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: config.chain_id.clone(),
            epoch_number: 1,
            previous_block_hash: [0; 32],
            network_randomness: genesis_randomness,
            approved_firmware_ids: config.approved_firmware_ids.clone(),
            minimum_security_class: config.minimum_security_class,
            network_mode: config.network_mode,
        };
        Self {
            config,
            registry: DeviceRegistry::default(),
            registration_heights: BTreeMap::new(),
            ticket_pool: TicketPool::new(context),
            ledger: Ledger::default(),
            blocks: Vec::new(),
            transactions: BTreeMap::new(),
            pending_transactions: BTreeSet::new(),
            paused_devices: BTreeSet::new(),
        }
    }

    pub fn validate_loaded(
        &self,
        expected_config: &NodeConfig,
        authority_key: &VerifyingKey,
        validator_key: &VerifyingKey,
    ) -> Result<(), NodeError> {
        if &self.config != expected_config {
            return Err(NodeError::ConfigurationMismatch);
        }
        let mut expected_previous = [0; 32];
        let mut expected_height = 1_u64;
        let mut replayed_ledger = Ledger::default();
        let mut replayed_registry = DeviceRegistry::default();
        let mut included_transactions = BTreeSet::new();
        let chain_height = self.chain_height();
        if self.registration_heights.len() != self.registry.len()
            || self.registry.iter().any(|(device_id, _)| {
                self.registration_heights
                    .get(device_id)
                    .is_none_or(|height| *height == 0 || *height > chain_height.saturating_add(1))
            })
            || self
                .registration_heights
                .keys()
                .any(|device_id| self.registry.get(device_id).is_none())
        {
            return Err(NodeError::InvalidStoredChain);
        }
        let validator_public_key = validator_key.to_encoded_point(true);
        for block in &self.blocks {
            block.verify_integrity()?;
            if block.validator_signatures.len() != 1 {
                return Err(NodeError::InvalidStoredChain);
            }
            block.verify_validator_signature(
                &block.validator_signatures[0],
                validator_public_key.as_bytes(),
            )?;
            if block.header.height != expected_height
                || block.header.previous_block_hash != expected_previous
                || block.header.chain_id != self.config.chain_id
                || block.header.epoch_number != expected_height
                || (!block.is_revocation_only() && block.reward.amount != self.config.reward_amount)
            {
                return Err(NodeError::InvalidStoredChain);
            }
            for (device_id, registration_height) in &self.registration_heights {
                if *registration_height != block.header.height {
                    continue;
                }
                let registered = self
                    .registry
                    .get(device_id)
                    .ok_or(NodeError::InvalidStoredChain)?;
                let replayed_id = replayed_registry.register(
                    registered.certificate.clone(),
                    registered.reward_address,
                    registered.minimum_security_class,
                    authority_key,
                    &self.config.chain_id,
                    block.header.epoch_number,
                )?;
                if &replayed_id != device_id {
                    return Err(NodeError::InvalidStoredChain);
                }
            }
            for transaction in &block.transactions {
                let hash = transaction.transaction_hash()?;
                if !included_transactions.insert(hash) {
                    return Err(NodeError::InvalidStoredChain);
                }
                let record = self
                    .transactions
                    .get(&hash)
                    .ok_or(NodeError::InvalidStoredChain)?;
                if record.hash != hash
                    || record.transaction != *transaction
                    || record.included_block_height != Some(block.header.height)
                    || record.submitted_epoch > block.header.epoch_number
                {
                    return Err(NodeError::InvalidStoredChain);
                }
                match transaction {
                    ChainTransaction::Transfer(transfer) => {
                        replayed_ledger.apply_transfer(transfer, &self.config.chain_id)?;
                    }
                    ChainTransaction::DeviceRevocation(revocation) => {
                        if revocation.protocol_version != EPDN_PROTOCOL_VERSION
                            || revocation.chain_id != self.config.chain_id
                            || revocation.effective_block_height != block.header.height
                        {
                            return Err(NodeError::InvalidStoredChain);
                        }
                        replayed_registry.revoke(
                            &revocation.device_id,
                            revocation.reason.clone(),
                            block.header.height,
                        )?;
                    }
                    ChainTransaction::RewardDistribution(reward) => {
                        replayed_ledger.credit(reward.recipient_address, reward.amount)?;
                    }
                }
            }
            if !block.is_revocation_only() {
                let winning_device = replayed_registry
                    .get(&block.header.winning_device_public_key_hash)
                    .ok_or(NodeError::InvalidStoredChain)?;
                if winning_device.revocation.is_some()
                    || winning_device.reward_address != block.reward.address
                    || winning_device.certificate.certificate_hash()?
                        != block.header.winning_certificate_hash
                    || winning_device.certificate.payload.security_class
                        != block.header.security_class
                    || !self
                        .config
                        .approved_firmware_ids
                        .contains(&block.header.firmware_id)
                    || !winning_device
                        .certificate
                        .payload
                        .allowed_firmware_ids
                        .contains(&block.header.firmware_id)
                {
                    return Err(NodeError::InvalidStoredChain);
                }
            }
            if replayed_registry.registry_root()? != block.header.device_registry_root
                || replayed_registry.revocation_root() != block.header.revocation_root
            {
                return Err(NodeError::InvalidStoredChain);
            }
            expected_previous = block.block_hash;
            expected_height = expected_height.saturating_add(1);
        }
        if self.ticket_pool.context().previous_block_hash != expected_previous
            || self.ticket_pool.context().chain_id != self.config.chain_id
            || self.ticket_pool.context().epoch_number != expected_height
            || self.ticket_pool.context().approved_firmware_ids != self.config.approved_firmware_ids
            || self.ticket_pool.context().minimum_security_class
                != self.config.minimum_security_class
            || self.ticket_pool.context().network_mode != self.config.network_mode
            || replayed_ledger != self.ledger
        {
            return Err(NodeError::InvalidStoredChain);
        }
        for (device_id, registered) in self.registry.iter() {
            let registration_height = self
                .registration_heights
                .get(device_id)
                .ok_or(NodeError::InvalidStoredChain)?;
            if *registration_height <= chain_height {
                if replayed_registry.get(device_id) != Some(registered) {
                    return Err(NodeError::InvalidStoredChain);
                }
            } else if registered.revocation.is_some() {
                return Err(NodeError::InvalidStoredChain);
            }
        }
        if replayed_registry
            .iter()
            .any(|(device_id, registered)| self.registry.get(device_id) != Some(registered))
        {
            return Err(NodeError::InvalidStoredChain);
        }
        for (_, device) in self.registry.iter() {
            device.certificate.verify(
                authority_key,
                &self.config.chain_id,
                device.certificate.payload.issued_at_epoch,
            )?;
        }
        self.ticket_pool
            .verify_integrity(&self.registry, authority_key)?;
        for (hash, record) in &self.transactions {
            if &record.transaction.transaction_hash()? != hash || &record.hash != hash {
                return Err(NodeError::InvalidStoredChain);
            }
            match record.included_block_height {
                Some(_) if !included_transactions.contains(hash) => {
                    return Err(NodeError::InvalidStoredChain);
                }
                None if !self.pending_transactions.contains(hash) => {
                    return Err(NodeError::InvalidStoredChain);
                }
                None if matches!(&record.transaction, ChainTransaction::RewardDistribution(_)) => {
                    return Err(NodeError::InvalidStoredChain);
                }
                _ => {}
            }
        }
        for hash in &self.pending_transactions {
            let record = self
                .transactions
                .get(hash)
                .ok_or(NodeError::InvalidStoredChain)?;
            if record.included_block_height.is_some() {
                return Err(NodeError::InvalidStoredChain);
            }
        }
        let mut pending_revocations = BTreeSet::new();
        for hash in &self.pending_transactions {
            if let ChainTransaction::DeviceRevocation(revocation) = &self
                .transactions
                .get(hash)
                .ok_or(NodeError::InvalidStoredChain)?
                .transaction
            {
                if revocation.protocol_version != EPDN_PROTOCOL_VERSION
                    || revocation.chain_id != self.config.chain_id
                    || revocation.effective_block_height != self.chain_height().saturating_add(1)
                    || self
                        .registry
                        .get(&revocation.device_id)
                        .is_none_or(|device| device.revocation.is_some())
                    || !pending_revocations.insert(revocation.device_id)
                {
                    return Err(NodeError::InvalidStoredChain);
                }
            }
        }
        if self
            .paused_devices
            .iter()
            .any(|device_id| self.registry.get(device_id).is_none())
        {
            return Err(NodeError::InvalidStoredChain);
        }
        self.validate_pending_transfers(None)?;
        Ok(())
    }

    pub fn issue_certificate(
        &self,
        mut enrollment: Enrollment,
        authority_key: &SigningKey,
    ) -> Result<DeviceCertificate, NodeError> {
        let current_epoch = self.current_epoch().epoch_number;
        if enrollment.expires_at_epoch <= current_epoch {
            return Err(NodeError::InvalidCertificateExpiry);
        }
        enrollment.allowed_firmware_ids.sort_unstable();
        enrollment.allowed_firmware_ids.dedup();
        if enrollment
            .allowed_firmware_ids
            .iter()
            .any(|firmware| !self.config.approved_firmware_ids.contains(firmware))
        {
            return Err(NodeError::FirmwareOutsideAllowlist);
        }

        let serial_hash = hash_domain(
            b"EPDN_CERT_SERIAL_V1",
            &[
                &enrollment.device_public_key,
                self.config.chain_id.as_bytes(),
                &current_epoch.to_be_bytes(),
            ],
        );
        let mut serial = [0_u8; 16];
        serial.copy_from_slice(&serial_hash[..16]);
        let authority_id = hash_domain(
            b"EPDN_AUTHORITY_ID_V1",
            &[authority_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()],
        );
        let mut payload = DeviceCertificatePayload {
            protocol_version: EPDN_PROTOCOL_VERSION,
            serial,
            device_public_key: enrollment.device_public_key,
            platform: enrollment.platform,
            board_family: enrollment.board_family,
            security_class: enrollment.security_class,
            authority_id,
            provisioned_at_unix_seconds: enrollment.provisioned_at_unix_seconds,
            issued_at_epoch: current_epoch,
            expires_at_epoch: enrollment.expires_at_epoch,
            allowed_chain_id: self.config.chain_id.clone(),
            chip_revision: enrollment.chip_revision,
            batch_id: enrollment.batch_id,
            manufacturer: enrollment.manufacturer,
            allowed_firmware_ids: enrollment.allowed_firmware_ids,
        };
        payload.normalize_firmware_policy();
        Ok(DeviceCertificate::issue(payload, authority_key)?)
    }

    pub fn register_device(
        &mut self,
        certificate: DeviceCertificate,
        reward_address: Address,
        authority_key: &VerifyingKey,
    ) -> Result<Hash32, NodeError> {
        let certificate_class = certificate.payload.security_class;
        let device_id = self.registry.register(
            certificate,
            reward_address,
            certificate_class,
            authority_key,
            &self.config.chain_id,
            self.current_epoch().epoch_number,
        )?;
        self.registration_heights
            .insert(device_id, self.chain_height().saturating_add(1));
        Ok(device_id)
    }

    pub fn challenge_for(
        &self,
        device_id: Hash32,
        firmware_id: Hash32,
    ) -> Result<EpochChallenge, NodeError> {
        let device = self
            .registry
            .get(&device_id)
            .ok_or(NodeError::DeviceNotRegistered)?;
        if device.revocation.is_some() || self.has_pending_revocation(&device_id) {
            return Err(NodeError::DeviceRevoked);
        }
        if self.paused_devices.contains(&device_id) {
            return Err(NodeError::DevicePaused);
        }
        if !self.config.approved_firmware_ids.contains(&firmware_id)
            || !device
                .certificate
                .payload
                .allowed_firmware_ids
                .contains(&firmware_id)
        {
            return Err(NodeError::FirmwareOutsideAllowlist);
        }
        let context = self.current_epoch();
        Ok(EpochChallenge {
            protocol_version: context.protocol_version,
            chain_id: context.chain_id.clone(),
            epoch_number: context.epoch_number,
            previous_block_hash: context.previous_block_hash,
            network_randomness: context.network_randomness,
            device_public_key_hash: device_id,
            approved_firmware_id: firmware_id,
            security_class: device.certificate.payload.security_class,
        })
    }

    pub fn submit_ticket(
        &mut self,
        submission: TicketSubmission,
        authority_key: &VerifyingKey,
    ) -> Result<ValidatedTicket, NodeError> {
        if self.has_pending_revocation(&submission.challenge.device_public_key_hash) {
            return Err(NodeError::DeviceRevoked);
        }
        if self
            .paused_devices
            .contains(&submission.challenge.device_public_key_hash)
        {
            return Err(NodeError::DevicePaused);
        }
        let validated = self
            .ticket_pool
            .validate_and_add(submission, &self.registry, authority_key)?
            .clone();
        Ok(validated)
    }

    pub fn revoke_device(
        &mut self,
        device_id: &Hash32,
        reason: String,
    ) -> Result<Hash32, NodeError> {
        if self.has_pending_revocation(device_id) {
            return Err(NodeError::DeviceRevoked);
        }
        let effective_block_height = self.chain_height().saturating_add(1);
        let mut validated_registry = self.registry.clone();
        validated_registry.revoke(device_id, reason.clone(), effective_block_height)?;
        let transaction = ChainTransaction::DeviceRevocation(DeviceRevocationTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: self.config.chain_id.clone(),
            device_id: *device_id,
            reason,
            effective_block_height,
        });
        self.enqueue_transaction(transaction)
    }

    pub fn pause_device(&mut self, device_id: &Hash32) -> Result<(), NodeError> {
        let device = self
            .registry
            .get(device_id)
            .ok_or(NodeError::DeviceNotRegistered)?;
        if device.revocation.is_some() {
            return Err(NodeError::DeviceRevoked);
        }
        self.paused_devices.insert(*device_id);
        Ok(())
    }

    pub fn resume_device(&mut self, device_id: &Hash32) -> Result<(), NodeError> {
        if self.registry.get(device_id).is_none() {
            return Err(NodeError::DeviceNotRegistered);
        }
        self.paused_devices.remove(device_id);
        Ok(())
    }

    #[must_use]
    pub fn is_paused(&self, device_id: &Hash32) -> bool {
        self.paused_devices.contains(device_id)
    }

    pub fn finalize_epoch(&mut self, validator_key: &SigningKey) -> Result<Block, NodeError> {
        let winner = self
            .ticket_pool
            .iter()
            .filter(|ticket| {
                self.registry
                    .get(&ticket.device_id)
                    .is_some_and(|device| device.revocation.is_none())
                    && !self.has_pending_revocation(&ticket.device_id)
                    && !self.paused_devices.contains(&ticket.device_id)
            })
            .min_by_key(|ticket| (ticket.score, ticket.device_id, ticket.submission_hash))
            .cloned();
        let Some(winner) = winner else {
            return self.finalize_revocation_only(validator_key);
        };
        let registered = self
            .registry
            .get(&winner.device_id)
            .cloned()
            .ok_or(NodeError::WinnerNotRegistered)?;
        let reward = RewardRecord {
            address: registered.reward_address,
            amount: self.config.reward_amount,
            winning_device_id: winner.device_id,
        };
        let reward_transaction = ChainTransaction::RewardDistribution(RewardTransaction {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: self.config.chain_id.clone(),
            recipient_address: reward.address,
            amount: reward.amount,
            winning_device_id: reward.winning_device_id,
            epoch_number: self.current_epoch().epoch_number,
        });
        let reward_hash = reward_transaction.transaction_hash()?;
        let mut transaction_pairs = self
            .pending_transactions
            .iter()
            .map(|hash| {
                let transaction = self
                    .transactions
                    .get(hash)
                    .ok_or(NodeError::InvalidStoredChain)?
                    .transaction
                    .clone();
                Ok((transaction.canonical_order_key()?, transaction))
            })
            .collect::<Result<Vec<_>, NodeError>>()?;
        transaction_pairs.push((
            reward_transaction.canonical_order_key()?,
            reward_transaction.clone(),
        ));
        transaction_pairs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let block_transactions = transaction_pairs
            .into_iter()
            .map(|(_, transaction)| transaction)
            .collect::<Vec<_>>();
        let block_height = self.chain_height().saturating_add(1);
        let mut next_ledger = self.ledger.clone();
        let mut next_registry = self.registry.clone();
        for transaction in &block_transactions {
            match transaction {
                ChainTransaction::Transfer(transfer) => {
                    next_ledger.apply_transfer(transfer, &self.config.chain_id)?;
                }
                ChainTransaction::DeviceRevocation(revocation) => {
                    if revocation.protocol_version != EPDN_PROTOCOL_VERSION
                        || revocation.chain_id != self.config.chain_id
                        || revocation.effective_block_height != block_height
                    {
                        return Err(NodeError::InvalidStoredChain);
                    }
                    next_registry.revoke(
                        &revocation.device_id,
                        revocation.reason.clone(),
                        block_height,
                    )?;
                }
                ChainTransaction::RewardDistribution(committed_reward) => {
                    next_ledger
                        .credit(committed_reward.recipient_address, committed_reward.amount)?;
                }
            }
        }
        let header = BlockHeader {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: self.config.chain_id.clone(),
            height: block_height,
            previous_block_hash: self.current_epoch().previous_block_hash,
            epoch_number: self.current_epoch().epoch_number,
            epoch_randomness: self.current_epoch().network_randomness,
            winning_ticket: winner.submission.ticket,
            winning_submission_hash: winner.submission_hash,
            winning_certificate_hash: registered.certificate.certificate_hash()?,
            winning_device_public_key_hash: winner.device_id,
            security_class: registered.certificate.payload.security_class,
            firmware_id: winner.submission.challenge.approved_firmware_id,
            attestation_hash: None,
            transaction_merkle_root: transaction_merkle_root(&block_transactions)?,
            device_registry_root: next_registry.registry_root()?,
            revocation_root: next_registry.revocation_root(),
        };
        let mut block = Block::new(header, reward.clone(), block_transactions)?;
        block.sign(validator_key)?;
        self.ledger = next_ledger;
        self.registry = next_registry;
        for hash in &self.pending_transactions {
            if let Some(record) = self.transactions.get_mut(hash) {
                record.included_block_height = Some(block_height);
            }
        }
        self.pending_transactions.clear();
        self.transactions.insert(
            reward_hash,
            TransactionRecord {
                hash: reward_hash,
                transaction: reward_transaction,
                submitted_epoch: block.header.epoch_number,
                included_block_height: Some(block_height),
            },
        );
        self.blocks.push(block.clone());

        self.advance_epoch(&block);
        Ok(block)
    }

    fn finalize_revocation_only(&mut self, validator_key: &SigningKey) -> Result<Block, NodeError> {
        let block_height = self.chain_height().saturating_add(1);
        let mut revocation_pairs = self
            .pending_transactions
            .iter()
            .filter_map(|hash| {
                self.transactions.get(hash).and_then(|record| {
                    if matches!(&record.transaction, ChainTransaction::DeviceRevocation(_)) {
                        Some((*hash, record.transaction.clone()))
                    } else {
                        None
                    }
                })
            })
            .map(|(hash, transaction)| Ok((transaction.canonical_order_key()?, hash, transaction)))
            .collect::<Result<Vec<_>, NodeError>>()?;
        if revocation_pairs.is_empty() {
            return Err(NodeError::NoTickets);
        }
        revocation_pairs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut next_registry = self.registry.clone();
        for (_, _, transaction) in &revocation_pairs {
            let ChainTransaction::DeviceRevocation(revocation) = transaction else {
                return Err(NodeError::InvalidStoredChain);
            };
            if revocation.protocol_version != EPDN_PROTOCOL_VERSION
                || revocation.chain_id != self.config.chain_id
                || revocation.effective_block_height != block_height
            {
                return Err(NodeError::InvalidStoredChain);
            }
            next_registry.revoke(
                &revocation.device_id,
                revocation.reason.clone(),
                block_height,
            )?;
        }
        let block_transactions = revocation_pairs
            .iter()
            .map(|(_, _, transaction)| transaction.clone())
            .collect::<Vec<_>>();
        let header = BlockHeader {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: self.config.chain_id.clone(),
            height: block_height,
            previous_block_hash: self.current_epoch().previous_block_hash,
            epoch_number: self.current_epoch().epoch_number,
            epoch_randomness: self.current_epoch().network_randomness,
            winning_ticket: REVOCATION_ONLY_MARKER,
            winning_submission_hash: REVOCATION_ONLY_MARKER,
            winning_certificate_hash: REVOCATION_ONLY_MARKER,
            winning_device_public_key_hash: REVOCATION_ONLY_MARKER,
            security_class: SecurityClass::L0SoftwareTest,
            firmware_id: REVOCATION_ONLY_MARKER,
            attestation_hash: None,
            transaction_merkle_root: transaction_merkle_root(&block_transactions)?,
            device_registry_root: next_registry.registry_root()?,
            revocation_root: next_registry.revocation_root(),
        };
        let mut block = Block::new(header, RewardRecord::revocation_only(), block_transactions)?;
        block.sign(validator_key)?;
        self.registry = next_registry;
        for (_, hash, _) in &revocation_pairs {
            let record = self
                .transactions
                .get_mut(hash)
                .ok_or(NodeError::InvalidStoredChain)?;
            record.included_block_height = Some(block_height);
            self.pending_transactions.remove(hash);
        }
        self.blocks.push(block.clone());
        self.advance_epoch(&block);
        Ok(block)
    }

    fn advance_epoch(&mut self, block: &Block) {
        let next_epoch = block.header.epoch_number.saturating_add(1);
        let next_randomness = hash_domain(
            b"EPDN_INSECURE_DEV_RANDOMNESS_V1",
            &[&block.block_hash, &next_epoch.to_be_bytes()],
        );
        self.ticket_pool = TicketPool::new(EpochContext {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: self.config.chain_id.clone(),
            epoch_number: next_epoch,
            previous_block_hash: block.block_hash,
            network_randomness: next_randomness,
            approved_firmware_ids: self.config.approved_firmware_ids.clone(),
            minimum_security_class: self.config.minimum_security_class,
            network_mode: self.config.network_mode,
        });
    }

    #[must_use]
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    #[must_use]
    pub fn current_epoch(&self) -> &EpochContext {
        self.ticket_pool.context()
    }

    #[must_use]
    pub fn ticket_pool(&self) -> &TicketPool {
        &self.ticket_pool
    }

    #[must_use]
    pub fn registry(&self) -> &DeviceRegistry {
        &self.registry
    }

    #[must_use]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    #[must_use]
    pub fn block_by_height(&self, height: u64) -> Option<&Block> {
        height
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.blocks.get(index))
    }

    #[must_use]
    pub fn block_by_hash(&self, hash: &Hash32) -> Option<&Block> {
        self.blocks.iter().find(|block| &block.block_hash == hash)
    }

    #[must_use]
    pub fn balance(&self, address: &Address) -> u64 {
        self.ledger.balance(address)
    }

    #[must_use]
    pub fn next_nonce(&self, address: &Address) -> u64 {
        let pending = self
            .pending_transactions
            .iter()
            .filter_map(|hash| self.transactions.get(hash))
            .filter(|record| {
                matches!(
                    &record.transaction,
                    ChainTransaction::Transfer(transfer)
                        if &transfer.sender_address == address
                )
            })
            .count();
        self.ledger
            .next_nonce(address)
            .saturating_add(u64::try_from(pending).unwrap_or(u64::MAX))
    }

    pub fn submit_transfer(&mut self, transfer: SignedTransfer) -> Result<Hash32, NodeError> {
        let hash = transfer.transaction_hash()?;
        if self.transactions.contains_key(&hash) {
            return Err(NodeError::TransactionReplay);
        }
        self.validate_pending_transfers(Some(&transfer))?;
        self.enqueue_transaction(ChainTransaction::Transfer(transfer))
    }

    #[must_use]
    pub fn transaction(&self, hash: &Hash32) -> Option<&TransactionRecord> {
        self.transactions.get(hash)
    }

    #[must_use]
    pub fn address_transactions(&self, address: &Address) -> Vec<&TransactionRecord> {
        self.transactions
            .values()
            .filter(|record| record.transaction.touches_address(address))
            .collect()
    }

    #[must_use]
    pub fn device_rewards(&self, device_id: &Hash32) -> Vec<&TransactionRecord> {
        self.transactions
            .values()
            .filter(|record| {
                matches!(
                    &record.transaction,
                    ChainTransaction::RewardDistribution(reward)
                        if &reward.winning_device_id == device_id
                )
            })
            .collect()
    }

    #[must_use]
    pub fn chain_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn enqueue_transaction(&mut self, transaction: ChainTransaction) -> Result<Hash32, NodeError> {
        let hash = transaction.transaction_hash()?;
        if self.transactions.contains_key(&hash) {
            return Err(NodeError::TransactionReplay);
        }
        self.transactions.insert(
            hash,
            TransactionRecord {
                hash,
                transaction,
                submitted_epoch: self.current_epoch().epoch_number,
                included_block_height: None,
            },
        );
        self.pending_transactions.insert(hash);
        Ok(hash)
    }

    fn has_pending_revocation(&self, device_id: &Hash32) -> bool {
        self.pending_transactions.iter().any(|hash| {
            self.transactions.get(hash).is_some_and(|record| {
                matches!(
                    &record.transaction,
                    ChainTransaction::DeviceRevocation(revocation)
                        if &revocation.device_id == device_id
                )
            })
        })
    }

    fn validate_pending_transfers(
        &self,
        additional: Option<&SignedTransfer>,
    ) -> Result<(), NodeError> {
        let mut transfers = self
            .pending_transactions
            .iter()
            .filter_map(|hash| self.transactions.get(hash))
            .filter_map(|record| {
                if let ChainTransaction::Transfer(transfer) = &record.transaction {
                    Some(transfer.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if let Some(transfer) = additional {
            transfers.push(transfer.clone());
        }
        let mut keyed_transfers = transfers
            .into_iter()
            .map(|transfer| {
                Ok((
                    transfer.sender_address,
                    transfer.nonce,
                    transfer.transaction_hash()?,
                    transfer,
                ))
            })
            .collect::<Result<Vec<_>, EncodeError>>()?;
        keyed_transfers.sort_unstable_by_key(|(sender, nonce, hash, _)| (*sender, *nonce, *hash));

        for sender in keyed_transfers
            .iter()
            .map(|(sender, _, _, _)| *sender)
            .collect::<BTreeSet<_>>()
        {
            let mut sender_ledger = self.ledger.clone();
            for (_, _, _, transfer) in keyed_transfers
                .iter()
                .filter(|(transfer_sender, _, _, _)| *transfer_sender == sender)
            {
                sender_ledger.apply_transfer(transfer, &self.config.chain_id)?;
            }
        }

        let mut projected_ledger = self.ledger.clone();
        for (_, _, _, transfer) in &keyed_transfers {
            projected_ledger.apply_transfer(transfer, &self.config.chain_id)?;
        }
        Ok(())
    }
}
