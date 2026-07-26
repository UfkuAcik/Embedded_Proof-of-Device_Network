use std::collections::BTreeMap;

use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::{CertificateError, DeviceCertificate},
    encoding::EncodeError,
    types::{hash_domain, Address, Hash32, SecurityClass},
};

pub const MAX_REVOCATION_REASON_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub reason: String,
    pub block_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub certificate: DeviceCertificate,
    pub reward_address: Address,
    pub minimum_security_class: SecurityClass,
    pub revocation: Option<Revocation>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistry {
    devices: BTreeMap<Hash32, RegisteredDevice>,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error("device is already registered")]
    AlreadyRegistered,
    #[error("device is not registered")]
    NotRegistered,
    #[error("device is already revoked")]
    AlreadyRevoked,
    #[error("revocation reason must not be empty")]
    RevocationReasonEmpty,
    #[error("revocation reason exceeds {MAX_REVOCATION_REASON_BYTES} bytes")]
    RevocationReasonTooLong,
}

impl DeviceRegistry {
    pub fn register(
        &mut self,
        certificate: DeviceCertificate,
        reward_address: Address,
        minimum_security_class: SecurityClass,
        authority_key: &VerifyingKey,
        expected_chain_id: &str,
        current_epoch: u64,
    ) -> Result<Hash32, RegistryError> {
        certificate.verify(authority_key, expected_chain_id, current_epoch)?;
        let device_id = certificate.device_public_key_hash();
        if self.devices.contains_key(&device_id) {
            return Err(RegistryError::AlreadyRegistered);
        }
        self.devices.insert(
            device_id,
            RegisteredDevice {
                certificate,
                reward_address,
                minimum_security_class,
                revocation: None,
            },
        );
        Ok(device_id)
    }

    pub fn revoke(
        &mut self,
        device_id: &Hash32,
        reason: String,
        block_height: u64,
    ) -> Result<(), RegistryError> {
        if reason.trim().is_empty() {
            return Err(RegistryError::RevocationReasonEmpty);
        }
        if reason.len() > MAX_REVOCATION_REASON_BYTES {
            return Err(RegistryError::RevocationReasonTooLong);
        }
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or(RegistryError::NotRegistered)?;
        if device.revocation.is_some() {
            return Err(RegistryError::AlreadyRevoked);
        }
        device.revocation = Some(Revocation {
            reason,
            block_height,
        });
        Ok(())
    }

    #[must_use]
    pub fn get(&self, device_id: &Hash32) -> Option<&RegisteredDevice> {
        self.devices.get(device_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Hash32, &RegisteredDevice)> {
        self.devices.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub fn registry_root(&self) -> Result<Hash32, EncodeError> {
        let mut bytes = Vec::with_capacity(self.devices.len().saturating_mul(129));
        bytes.extend_from_slice(&(self.devices.len() as u64).to_be_bytes());
        for (device_id, registered) in &self.devices {
            bytes.extend_from_slice(device_id);
            bytes.extend_from_slice(&registered.certificate.certificate_hash()?);
            bytes.extend_from_slice(&registered.reward_address);
            bytes.push(registered.minimum_security_class as u8);
            bytes.push(u8::from(registered.revocation.is_some()));
        }
        Ok(hash_domain(b"EPDN_DEVICE_REGISTRY_ROOT_V1", &[&bytes]))
    }

    #[must_use]
    pub fn revocation_root(&self) -> Hash32 {
        let revoked_count = self
            .devices
            .values()
            .filter(|device| device.revocation.is_some())
            .count();
        let mut bytes = Vec::with_capacity(revoked_count.saturating_mul(192));
        bytes.extend_from_slice(&(revoked_count as u64).to_be_bytes());
        for (device_id, registered) in &self.devices {
            if let Some(revocation) = &registered.revocation {
                bytes.extend_from_slice(device_id);
                bytes.extend_from_slice(&revocation.block_height.to_be_bytes());
                bytes.extend_from_slice(&(revocation.reason.len() as u16).to_be_bytes());
                bytes.extend_from_slice(revocation.reason.as_bytes());
            }
        }
        hash_domain(b"EPDN_REVOCATION_ROOT_V1", &[&bytes])
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;
    use crate::{
        certificate::DeviceCertificatePayload,
        types::{hash_domain, EPDN_PROTOCOL_VERSION},
    };

    fn certificate(authority: &SigningKey) -> DeviceCertificate {
        DeviceCertificate::issue(
            DeviceCertificatePayload {
                protocol_version: EPDN_PROTOCOL_VERSION,
                serial: [1; 16],
                device_public_key: SigningKey::from_slice(&[2; 32])
                    .expect("valid key")
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                platform: "esp32".to_owned(),
                board_family: "generic".to_owned(),
                security_class: SecurityClass::L2NativeHardwareIdentity,
                authority_id: hash_domain(
                    b"EPDN_AUTHORITY_ID_V1",
                    &[authority.verifying_key().to_encoded_point(true).as_bytes()],
                ),
                provisioned_at_unix_seconds: 1_700_000_000,
                issued_at_epoch: 1,
                expires_at_epoch: 100,
                allowed_chain_id: "epdn-test".to_owned(),
                chip_revision: Some("v1".to_owned()),
                batch_id: None,
                manufacturer: Some("EPDN test fixture".to_owned()),
                allowed_firmware_ids: vec![[4; 32]],
            },
            authority,
        )
        .expect("valid certificate")
    }

    #[test]
    fn registry_and_revocation_roots_are_deterministic() {
        let authority = SigningKey::from_slice(&[3; 32]).expect("valid key");
        let certificate = certificate(&authority);
        let device_id = certificate.device_public_key_hash();
        let mut first = DeviceRegistry::default();
        first
            .register(
                certificate.clone(),
                [8; 32],
                SecurityClass::L1ProtectedSoftwareIdentity,
                authority.verifying_key(),
                "epdn-test",
                2,
            )
            .expect("register");
        let mut second = first.clone();
        assert_eq!(
            first.registry_root().expect("root"),
            second.registry_root().expect("root")
        );

        second
            .revoke(&device_id, "operator request".to_owned(), 9)
            .expect("revoke");
        assert_ne!(first.revocation_root(), second.revocation_root());
        assert_ne!(
            first.registry_root().expect("root"),
            second.registry_root().expect("root")
        );
    }
}
