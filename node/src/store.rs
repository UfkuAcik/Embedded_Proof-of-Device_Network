use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use bincode::Options;
use epdn_protocol::hash_domain;
use p256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::core::{NodeCore, StoredNodeCoreV3};

const RECORD_MAGIC: &[u8; 4] = b"EPSJ";
const RECORD_VERSION: u16 = 3;
const CHECKSUM_DOMAIN: &[u8] = b"EPDN_STATE_RECORD_CHECKSUM_V3";
const SIGNATURE_DOMAIN: &[u8] = b"EPDN_STATE_RECORD_SIGNATURE_V3";
const VALIDATOR_ID_DOMAIN: &[u8] = b"EPDN_VALIDATOR_ID_V1";
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

/// Atomically replaced, validator-authenticated local state snapshot.
///
/// Consensus objects retain their EPDN binary encoding. Snapshot V3 uses an
/// explicit storage DTO and fixed-width, big-endian bincode only for local
/// process recovery; these bytes never participate in a consensus hash. The
/// configured validator key signs the complete record metadata and payload.
/// Unsigned V1/V2 records and any truncated or trailing bytes fail closed.
#[derive(Debug, Clone)]
pub struct JournalStore {
    path: PathBuf,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("state journal I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("state journal contains an invalid record header")]
    InvalidHeader,
    #[error("state journal record version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("state journal record is too large: {0} bytes")]
    Oversized(usize),
    #[error("state journal checksum mismatch")]
    ChecksumMismatch,
    #[error("state journal is truncated")]
    TruncatedRecord,
    #[error("state journal contains trailing bytes")]
    TrailingData,
    #[error("state journal was signed by a different validator")]
    ValidatorMismatch,
    #[error("state journal validator signature is invalid")]
    SignatureMismatch,
    #[error("state journal signing failed")]
    SigningFailed,
    #[error("state serialization failed: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
}

impl JournalStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self, validator_key: &VerifyingKey) -> Result<Option<NodeCore>, StoreError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Io(error)),
        };
        let mut reader = BufReader::new(file);
        let mut magic = [0_u8; 4];
        if !read_exact_or_truncated(&mut reader, &mut magic)? {
            return Err(StoreError::TruncatedRecord);
        }
        if &magic != RECORD_MAGIC {
            return Err(StoreError::InvalidHeader);
        }
        let mut version_bytes = [0_u8; 2];
        if !read_exact_or_truncated(&mut reader, &mut version_bytes)? {
            return Err(StoreError::TruncatedRecord);
        }
        let version = u16::from_be_bytes(version_bytes);
        if version != RECORD_VERSION {
            return Err(StoreError::UnsupportedVersion(version));
        }
        let mut length_bytes = [0_u8; 4];
        if !read_exact_or_truncated(&mut reader, &mut length_bytes)? {
            return Err(StoreError::TruncatedRecord);
        }
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length > MAX_STATE_BYTES {
            return Err(StoreError::Oversized(length));
        }
        let mut checksum = [0_u8; 32];
        if !read_exact_or_truncated(&mut reader, &mut checksum)? {
            return Err(StoreError::TruncatedRecord);
        }
        let mut stored_validator_id = [0_u8; 32];
        if !read_exact_or_truncated(&mut reader, &mut stored_validator_id)? {
            return Err(StoreError::TruncatedRecord);
        }
        let mut signature_bytes = [0_u8; 64];
        if !read_exact_or_truncated(&mut reader, &mut signature_bytes)? {
            return Err(StoreError::TruncatedRecord);
        }
        let mut payload = vec![0_u8; length];
        if !read_exact_or_truncated(&mut reader, &mut payload)? {
            return Err(StoreError::TruncatedRecord);
        }
        let mut trailing = [0_u8; 1];
        if read_partial(&mut reader, &mut trailing)? != 0 {
            return Err(StoreError::TrailingData);
        }
        if hash_domain(CHECKSUM_DOMAIN, &[&payload]) != checksum {
            return Err(StoreError::ChecksumMismatch);
        }
        let expected_validator_id = validator_id(validator_key);
        if stored_validator_id != expected_validator_id {
            return Err(StoreError::ValidatorMismatch);
        }
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| StoreError::SignatureMismatch)?;
        let digest = record_signature_digest(
            &version_bytes,
            &length_bytes,
            &checksum,
            &stored_validator_id,
            &payload,
        );
        validator_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| StoreError::SignatureMismatch)?;
        let stored: StoredNodeCoreV3 = decoding_options().deserialize(&payload)?;
        Ok(Some(NodeCore::from(stored)))
    }

    pub fn save(&self, state: &NodeCore, validator_key: &SigningKey) -> Result<(), StoreError> {
        let stored = StoredNodeCoreV3::from(state);
        let payload = encoding_options().serialize(&stored)?;
        if payload.len() > MAX_STATE_BYTES {
            return Err(StoreError::Oversized(payload.len()));
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let version_bytes = RECORD_VERSION.to_be_bytes();
        let length_bytes = (payload.len() as u32).to_be_bytes();
        let checksum = hash_domain(CHECKSUM_DOMAIN, &[&payload]);
        let validator_id = validator_id(validator_key.verifying_key());
        let digest = record_signature_digest(
            &version_bytes,
            &length_bytes,
            &checksum,
            &validator_id,
            &payload,
        );
        let signature: Signature = validator_key
            .sign_prehash(&digest)
            .map_err(|_| StoreError::SigningFailed)?;
        let mut record = Vec::with_capacity(4 + 2 + 4 + 32 + 32 + 64 + payload.len());
        record.extend_from_slice(RECORD_MAGIC);
        record.extend_from_slice(&version_bytes);
        record.extend_from_slice(&length_bytes);
        record.extend_from_slice(&checksum);
        record.extend_from_slice(&validator_id);
        record.extend_from_slice(signature.to_bytes().as_slice());
        record.extend_from_slice(&payload);
        let directory = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temporary = NamedTempFile::new_in(directory)?;
        temporary.write_all(&record)?;
        temporary.flush()?;
        temporary.as_file().sync_data()?;
        temporary
            .persist(&self.path)
            .map_err(|error| StoreError::Io(error.error))?;
        sync_directory(directory)?;
        Ok(())
    }
}

fn validator_id(validator_key: &VerifyingKey) -> [u8; 32] {
    let encoded = validator_key.to_encoded_point(true);
    hash_domain(VALIDATOR_ID_DOMAIN, &[encoded.as_bytes()])
}

fn record_signature_digest(
    version: &[u8; 2],
    length: &[u8; 4],
    checksum: &[u8; 32],
    validator_id: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    hash_domain(
        SIGNATURE_DOMAIN,
        &[
            RECORD_MAGIC,
            version,
            length,
            checksum,
            validator_id,
            payload,
        ],
    )
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), io::Error> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), io::Error> {
    Ok(())
}

fn encoding_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
}

fn decoding_options() -> impl Options {
    encoding_options()
        .with_limit(MAX_STATE_BYTES as u64)
        .reject_trailing_bytes()
}

fn read_partial(reader: &mut impl Read, output: &mut [u8]) -> Result<usize, io::Error> {
    let mut offset = 0;
    while offset < output.len() {
        match reader.read(&mut output[offset..]) {
            Ok(0) => break,
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(offset)
}

fn read_exact_or_truncated(reader: &mut impl Read, output: &mut [u8]) -> Result<bool, io::Error> {
    Ok(read_partial(reader, output)? == output.len())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        time::{SystemTime, UNIX_EPOCH},
    };

    use epdn_protocol::{
        hash_domain, ChainTransaction, SecurityClass, SignedTransfer, TicketSubmission,
    };
    use p256::ecdsa::SigningKey;

    use super::*;
    use crate::core::{Enrollment, NodeConfig};

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).expect("valid test key")
    }

    fn temporary_journal(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "epdn-{label}-{}-{nonce}.journal",
            std::process::id()
        ))
    }

    #[test]
    fn authenticated_snapshot_rejects_trailing_data_and_replaces_atomically() {
        let path = temporary_journal("truncated-state");
        let store = JournalStore::new(&path);
        let validator = key(80);
        let state = NodeCore::new(NodeConfig::local_testnet());
        store.save(&state, &validator).expect("save");
        assert_eq!(
            store.load(validator.verifying_key()).expect("load"),
            Some(state)
        );

        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"EP").expect("write truncated record");
        file.sync_data().expect("sync");
        drop(file);
        assert!(matches!(
            store.load(validator.verifying_key()),
            Err(StoreError::TrailingData)
        ));

        let mut replacement_config = NodeConfig::local_testnet();
        replacement_config.reward_amount += 1;
        let replacement = NodeCore::new(replacement_config);
        store
            .save(&replacement, &validator)
            .expect("replace truncated journal with atomic snapshot");
        assert_eq!(
            store
                .load(validator.verifying_key())
                .expect("load replacement"),
            Some(replacement)
        );

        fs::remove_file(path).expect("remove test journal");
    }

    #[test]
    fn signed_snapshot_v3_is_deterministic_and_round_trips_a_valid_non_empty_chain() {
        let path = temporary_journal("non-empty-state");
        let deterministic_path_a = temporary_journal("deterministic-state-a");
        let deterministic_path_b = temporary_journal("deterministic-state-b");
        let store = JournalStore::new(&path);
        let config = NodeConfig::local_testnet();
        let firmware_id = *config
            .approved_firmware_ids
            .iter()
            .next()
            .expect("firmware");
        let authority = key(81);
        let validator = key(82);
        let miner = key(83);
        let revoked_miner = key(84);
        let wallet = key(85);
        let wallet_public = wallet.verifying_key().to_encoded_point(true);
        let reward_address = hash_domain(b"EPDN_WALLET_ADDRESS_V1", &[wallet_public.as_bytes()]);
        let mut state = NodeCore::new(config.clone());

        let enrollment = |device: &SigningKey, serial_offset: u64| Enrollment {
            device_public_key: device
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            platform: "esp32".to_owned(),
            board_family: "esp32-generic".to_owned(),
            security_class: SecurityClass::L2NativeHardwareIdentity,
            provisioned_at_unix_seconds: 1_700_000_000 + serial_offset,
            chip_revision: Some("v3.1".to_owned()),
            batch_id: Some("snapshot-v3-test".to_owned()),
            manufacturer: None,
            allowed_firmware_ids: vec![firmware_id],
            expires_at_epoch: 100,
        };

        let miner_certificate = state
            .issue_certificate(enrollment(&miner, 1), &authority)
            .expect("miner certificate");
        let miner_id = state
            .register_device(miner_certificate, reward_address, authority.verifying_key())
            .expect("miner registration");
        let revoked_certificate = state
            .issue_certificate(enrollment(&revoked_miner, 2), &authority)
            .expect("second certificate");
        let revoked_id = state
            .register_device(revoked_certificate, [86; 32], authority.verifying_key())
            .expect("second registration");

        let first_challenge = state
            .challenge_for(miner_id, firmware_id)
            .expect("first challenge");
        state
            .submit_ticket(
                TicketSubmission::create(first_challenge, &miner).expect("first ticket"),
                authority.verifying_key(),
            )
            .expect("first ticket accepted");
        state
            .finalize_epoch(&validator)
            .expect("first reward block");
        store
            .save(&state, &validator)
            .expect("save first block snapshot");

        let transfer = SignedTransfer::create(config.chain_id.clone(), [87; 32], 25, 2, 0, &wallet)
            .expect("signed transfer");
        state.submit_transfer(transfer).expect("transfer accepted");
        state
            .revoke_device(&revoked_id, "snapshot V3 regression".to_owned())
            .expect("revocation accepted");

        let second_challenge = state
            .challenge_for(miner_id, firmware_id)
            .expect("second challenge");
        state
            .submit_ticket(
                TicketSubmission::create(second_challenge, &miner).expect("second ticket"),
                authority.verifying_key(),
            )
            .expect("second ticket accepted");
        let second_block = state
            .finalize_epoch(&validator)
            .expect("second reward block");
        assert!(second_block
            .transactions
            .iter()
            .any(|transaction| matches!(transaction, ChainTransaction::Transfer(_))));
        assert!(second_block
            .transactions
            .iter()
            .any(|transaction| matches!(transaction, ChainTransaction::DeviceRevocation(_))));
        assert!(second_block
            .transactions
            .iter()
            .any(|transaction| matches!(transaction, ChainTransaction::RewardDistribution(_))));

        store
            .save(&state, &validator)
            .expect("save complete snapshot");
        JournalStore::new(&deterministic_path_a)
            .save(&state, &validator)
            .expect("save deterministic snapshot A");
        JournalStore::new(&deterministic_path_b)
            .save(&state, &validator)
            .expect("save deterministic snapshot B");
        assert_eq!(
            fs::read(&deterministic_path_a).expect("read deterministic snapshot A"),
            fs::read(&deterministic_path_b).expect("read deterministic snapshot B")
        );
        let loaded = store
            .load(validator.verifying_key())
            .expect("load complete snapshot")
            .expect("state");
        assert_eq!(loaded, state);
        loaded
            .validate_loaded(
                &config,
                authority.verifying_key(),
                validator.verifying_key(),
            )
            .expect("loaded state validates");
        assert_eq!(loaded.chain_height(), 2);
        assert_eq!(loaded.balance(&reward_address), 173);

        fs::remove_file(path).expect("remove test journal");
        fs::remove_file(deterministic_path_a).expect("remove deterministic journal A");
        fs::remove_file(deterministic_path_b).expect("remove deterministic journal B");
    }

    #[test]
    fn signed_snapshot_rejects_wrong_validator_and_rechecks_signature_after_checksum() {
        let path = temporary_journal("authenticated-state");
        let store = JournalStore::new(&path);
        let validator = key(88);
        let wrong_validator = key(89);
        let state = NodeCore::new(NodeConfig::local_testnet());
        store.save(&state, &validator).expect("save signed state");

        assert!(matches!(
            store.load(wrong_validator.verifying_key()),
            Err(StoreError::ValidatorMismatch)
        ));

        let mut record = fs::read(&path).expect("read signed state");
        let payload_offset = 4 + 2 + 4 + 32 + 32 + 64;
        record[payload_offset] ^= 1;
        let checksum = hash_domain(CHECKSUM_DOMAIN, &[&record[payload_offset..]]);
        record[10..42].copy_from_slice(&checksum);
        fs::write(&path, record).expect("write forged checksum with stale signature");
        assert!(matches!(
            store.load(validator.verifying_key()),
            Err(StoreError::SignatureMismatch)
        ));

        fs::remove_file(path).expect("remove test journal");
    }

    #[test]
    fn signed_snapshot_rejects_unsigned_v1_and_v2_formats_explicitly() {
        let validator = key(90);
        for version in [1_u16, 2_u16] {
            let path = temporary_journal(&format!("unsupported-v{version}"));
            let mut file = File::create(&path).expect("create journal");
            file.write_all(RECORD_MAGIC).expect("write magic");
            file.write_all(&version.to_be_bytes())
                .expect("write old version");
            file.sync_data().expect("sync old record");

            assert!(matches!(
                JournalStore::new(&path).load(validator.verifying_key()),
                Err(StoreError::UnsupportedVersion(actual)) if actual == version
            ));
            fs::remove_file(path).expect("remove test journal");
        }
    }
}
