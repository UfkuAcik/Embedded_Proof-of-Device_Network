use p256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    encoding::{ensure_exact_length, DecodeError, Decoder, EncodeError, Encoder},
    types::{
        hash_domain, Hash32, SecurityClass, EPDN_PROTOCOL_VERSION, MAX_BATCH_ID_BYTES,
        MAX_BOARD_FAMILY_BYTES, MAX_CERTIFICATE_BYTES, MAX_CHAIN_ID_BYTES, MAX_CHIP_REVISION_BYTES,
        MAX_FIRMWARE_POLICIES, MAX_MANUFACTURER_BYTES, MAX_PLATFORM_BYTES,
    },
};

const CERTIFICATE_PAYLOAD_TYPE: u8 = 2;
const CERTIFICATE_TYPE: u8 = 3;
const P256_COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;
const P256_RAW_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificatePayload {
    pub protocol_version: u16,
    pub serial: [u8; 16],
    /// Canonical SEC1 compressed P-256 public key (33 bytes).
    pub device_public_key: Vec<u8>,
    pub platform: String,
    pub board_family: String,
    pub security_class: SecurityClass,
    pub authority_id: Hash32,
    pub provisioned_at_unix_seconds: u64,
    pub issued_at_epoch: u64,
    pub expires_at_epoch: u64,
    pub allowed_chain_id: String,
    pub chip_revision: Option<String>,
    pub batch_id: Option<String>,
    pub manufacturer: Option<String>,
    /// Sorted, duplicate-free firmware identifiers.
    pub allowed_firmware_ids: Vec<Hash32>,
}

impl DeviceCertificatePayload {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.allowed_firmware_ids.len() > MAX_FIRMWARE_POLICIES {
            return Err(EncodeError::LengthExceeded {
                field: "allowed_firmware_ids",
                actual: self.allowed_firmware_ids.len(),
                maximum: MAX_FIRMWARE_POLICIES,
            });
        }
        if self
            .allowed_firmware_ids
            .windows(2)
            .any(|window| window[0] >= window[1])
        {
            return Err(EncodeError::NonCanonicalOrder {
                field: "allowed_firmware_ids",
            });
        }

        let mut encoder = Encoder::with_header(CERTIFICATE_PAYLOAD_TYPE, self.protocol_version);
        encoder.fixed(&self.serial);
        ensure_exact_length(
            "device_public_key",
            &self.device_public_key,
            P256_COMPRESSED_PUBLIC_KEY_BYTES,
        )?;
        encoder.fixed(&self.device_public_key);
        encoder.string("platform", &self.platform, MAX_PLATFORM_BYTES)?;
        encoder.string("board_family", &self.board_family, MAX_BOARD_FAMILY_BYTES)?;
        encoder.u8(self.security_class as u8);
        encoder.fixed(&self.authority_id);
        encoder.u64(self.provisioned_at_unix_seconds);
        encoder.u64(self.issued_at_epoch);
        encoder.u64(self.expires_at_epoch);
        encoder.string(
            "allowed_chain_id",
            &self.allowed_chain_id,
            MAX_CHAIN_ID_BYTES,
        )?;
        encode_optional_string(
            &mut encoder,
            "chip_revision",
            self.chip_revision.as_deref(),
            MAX_CHIP_REVISION_BYTES,
        )?;
        encode_optional_string(
            &mut encoder,
            "batch_id",
            self.batch_id.as_deref(),
            MAX_BATCH_ID_BYTES,
        )?;
        encode_optional_string(
            &mut encoder,
            "manufacturer",
            self.manufacturer.as_deref(),
            MAX_MANUFACTURER_BYTES,
        )?;
        encoder.u16(self.allowed_firmware_ids.len() as u16);
        for firmware_id in &self.allowed_firmware_ids {
            encoder.fixed(firmware_id);
        }
        Ok(encoder.finish())
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::with_header(
            input,
            MAX_CERTIFICATE_BYTES,
            CERTIFICATE_PAYLOAD_TYPE,
            EPDN_PROTOCOL_VERSION,
        )?;
        let serial = decoder.fixed()?;
        let device_public_key = decoder
            .fixed::<P256_COMPRESSED_PUBLIC_KEY_BYTES>()?
            .to_vec();
        let platform = decoder.string("platform", MAX_PLATFORM_BYTES)?;
        let board_family = decoder.string("board_family", MAX_BOARD_FAMILY_BYTES)?;
        let security_class = SecurityClass::from_wire(decoder.u8()?)?;
        let authority_id = decoder.fixed()?;
        let provisioned_at_unix_seconds = decoder.u64()?;
        let issued_at_epoch = decoder.u64()?;
        let expires_at_epoch = decoder.u64()?;
        let allowed_chain_id = decoder.string("allowed_chain_id", MAX_CHAIN_ID_BYTES)?;
        let chip_revision =
            decode_optional_string(&mut decoder, "chip_revision", MAX_CHIP_REVISION_BYTES)?;
        let batch_id = decode_optional_string(&mut decoder, "batch_id", MAX_BATCH_ID_BYTES)?;
        let manufacturer =
            decode_optional_string(&mut decoder, "manufacturer", MAX_MANUFACTURER_BYTES)?;
        let firmware_count = usize::from(decoder.u16()?);
        if firmware_count > MAX_FIRMWARE_POLICIES {
            return Err(DecodeError::LengthExceeded {
                field: "allowed_firmware_ids",
                actual: firmware_count,
                maximum: MAX_FIRMWARE_POLICIES,
            });
        }
        let mut allowed_firmware_ids = Vec::with_capacity(firmware_count);
        for _ in 0..firmware_count {
            allowed_firmware_ids.push(decoder.fixed()?);
        }
        decoder.finish()?;
        if allowed_firmware_ids
            .windows(2)
            .any(|window| window[0] >= window[1])
        {
            return Err(DecodeError::NonCanonical {
                field: "allowed_firmware_ids",
            });
        }
        Ok(Self {
            protocol_version: EPDN_PROTOCOL_VERSION,
            serial,
            device_public_key,
            platform,
            board_family,
            security_class,
            authority_id,
            provisioned_at_unix_seconds,
            issued_at_epoch,
            expires_at_epoch,
            allowed_chain_id,
            chip_revision,
            batch_id,
            manufacturer,
            allowed_firmware_ids,
        })
    }

    pub fn normalize_firmware_policy(&mut self) {
        self.allowed_firmware_ids.sort_unstable();
        self.allowed_firmware_ids.dedup();
    }
}

fn encode_optional_string(
    encoder: &mut Encoder,
    field: &'static str,
    value: Option<&str>,
    maximum: usize,
) -> Result<(), EncodeError> {
    match value {
        Some("") => Err(EncodeError::NonCanonicalValue { field }),
        Some(value) => {
            encoder.u8(1);
            encoder.string(field, value, maximum)
        }
        None => {
            encoder.u8(0);
            Ok(())
        }
    }
}

fn decode_optional_string(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    maximum: usize,
) -> Result<Option<String>, DecodeError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => {
            let value = decoder.string(field, maximum)?;
            if value.is_empty() {
                Err(DecodeError::NonCanonical { field })
            } else {
                Ok(Some(value))
            }
        }
        value => Err(DecodeError::InvalidEnum { field, value }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub payload: DeviceCertificatePayload,
    pub issuer_signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error("certificate authority identifier does not match the configured authority")]
    WrongAuthority,
    #[error("certificate is for chain {actual}, not {expected}")]
    WrongChain { actual: String, expected: String },
    #[error("certificate is not valid before epoch {0}")]
    NotYetValid(u64),
    #[error("certificate expired at epoch {0}")]
    Expired(u64),
    #[error("certificate validity interval is empty or reversed")]
    InvalidValidity,
    #[error("certificate contains an invalid SEC1 compressed P-256 public key")]
    InvalidPublicKey,
    #[error("certificate contains an invalid fixed-width P-256 signature length")]
    InvalidSignatureLength,
    #[error("certificate signature is invalid")]
    InvalidSignature,
    #[error("certificate signing failed")]
    SigningFailed,
    #[error("unsupported certificate protocol version {0}")]
    UnsupportedProtocol(u16),
}

impl DeviceCertificate {
    pub fn issue(
        payload: DeviceCertificatePayload,
        authority_key: &SigningKey,
    ) -> Result<Self, CertificateError> {
        if payload.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocol(
                payload.protocol_version,
            ));
        }
        let authority_public_key = authority_key.verifying_key().to_encoded_point(true);
        let expected_authority_id =
            hash_domain(b"EPDN_AUTHORITY_ID_V1", &[authority_public_key.as_bytes()]);
        if payload.authority_id != expected_authority_id {
            return Err(CertificateError::WrongAuthority);
        }
        if payload.issued_at_epoch >= payload.expires_at_epoch {
            return Err(CertificateError::InvalidValidity);
        }
        let payload_bytes = payload.canonical_bytes()?;
        let digest = hash_domain(b"EPDN_CERT_SIGNATURE_V1", &[&payload_bytes]);
        let issuer_signature: Signature = authority_key
            .sign_prehash(&digest)
            .map_err(|_| CertificateError::SigningFailed)?;
        let issuer_signature = issuer_signature.to_bytes().to_vec();
        Ok(Self {
            payload,
            issuer_signature,
        })
    }

    pub fn verify(
        &self,
        authority_key: &VerifyingKey,
        expected_chain_id: &str,
        current_epoch: u64,
    ) -> Result<(), CertificateError> {
        if self.payload.protocol_version != EPDN_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocol(
                self.payload.protocol_version,
            ));
        }
        let authority_public_key = authority_key.to_encoded_point(true);
        let expected_authority_id =
            hash_domain(b"EPDN_AUTHORITY_ID_V1", &[authority_public_key.as_bytes()]);
        if self.payload.authority_id != expected_authority_id {
            return Err(CertificateError::WrongAuthority);
        }
        if self.payload.allowed_chain_id != expected_chain_id {
            return Err(CertificateError::WrongChain {
                actual: self.payload.allowed_chain_id.clone(),
                expected: expected_chain_id.to_owned(),
            });
        }
        if self.payload.issued_at_epoch >= self.payload.expires_at_epoch {
            return Err(CertificateError::InvalidValidity);
        }
        if current_epoch < self.payload.issued_at_epoch {
            return Err(CertificateError::NotYetValid(self.payload.issued_at_epoch));
        }
        if current_epoch >= self.payload.expires_at_epoch {
            return Err(CertificateError::Expired(self.payload.expires_at_epoch));
        }

        ensure_exact_length(
            "issuer_signature",
            &self.issuer_signature,
            P256_RAW_SIGNATURE_BYTES,
        )
        .map_err(|_| CertificateError::InvalidSignatureLength)?;
        let signature = Signature::from_slice(&self.issuer_signature)
            .map_err(|_| CertificateError::InvalidSignatureLength)?;
        let payload_bytes = self.payload.canonical_bytes()?;
        let digest = hash_domain(b"EPDN_CERT_SIGNATURE_V1", &[&payload_bytes]);
        authority_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        ensure_exact_length(
            "issuer_signature",
            &self.issuer_signature,
            P256_RAW_SIGNATURE_BYTES,
        )?;
        let payload = self.payload.canonical_bytes()?;
        let mut encoder = Encoder::with_header(CERTIFICATE_TYPE, self.payload.protocol_version);
        encoder.bytes_u32("certificate_payload", &payload, MAX_CERTIFICATE_BYTES)?;
        encoder.bytes_u16(
            "issuer_signature",
            &self.issuer_signature,
            P256_RAW_SIGNATURE_BYTES,
        )?;
        let bytes = encoder.finish();
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(EncodeError::LengthExceeded {
                field: "certificate",
                actual: bytes.len(),
                maximum: MAX_CERTIFICATE_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::with_header(
            input,
            MAX_CERTIFICATE_BYTES,
            CERTIFICATE_TYPE,
            EPDN_PROTOCOL_VERSION,
        )?;
        let payload_bytes = decoder.bytes_u32("certificate_payload", MAX_CERTIFICATE_BYTES)?;
        let issuer_signature = decoder.bytes_u16("issuer_signature", P256_RAW_SIGNATURE_BYTES)?;
        if issuer_signature.len() != P256_RAW_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical {
                field: "issuer_signature",
            });
        }
        decoder.finish()?;
        let payload = DeviceCertificatePayload::decode(&payload_bytes)?;
        Ok(Self {
            payload,
            issuer_signature,
        })
    }

    pub fn certificate_hash(&self) -> Result<Hash32, EncodeError> {
        Ok(hash_domain(
            b"EPDN_CERT_HASH_V1",
            &[&self.canonical_bytes()?],
        ))
    }

    #[must_use]
    pub fn device_public_key_hash(&self) -> Hash32 {
        hash_domain(
            b"EPDN_DEVICE_PUBLIC_KEY_V1",
            &[&self.payload.device_public_key],
        )
    }

    pub fn device_verifying_key(&self) -> Result<VerifyingKey, CertificateError> {
        VerifyingKey::from_sec1_bytes(&self.payload.device_public_key)
            .map_err(|_| CertificateError::InvalidPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(authority_key: &SigningKey) -> DeviceCertificatePayload {
        DeviceCertificatePayload {
            protocol_version: EPDN_PROTOCOL_VERSION,
            serial: [9; 16],
            device_public_key: SigningKey::from_slice(&[7; 32])
                .expect("valid key")
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            platform: "esp32".to_owned(),
            board_family: "esp32-generic".to_owned(),
            security_class: SecurityClass::L1ProtectedSoftwareIdentity,
            authority_id: hash_domain(
                b"EPDN_AUTHORITY_ID_V1",
                &[authority_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()],
            ),
            provisioned_at_unix_seconds: 1_700_000_000,
            issued_at_epoch: 1,
            expires_at_epoch: 100,
            allowed_chain_id: "epdn-test".to_owned(),
            chip_revision: Some("v3.1".to_owned()),
            batch_id: Some("dev-batch-01".to_owned()),
            manufacturer: None,
            allowed_firmware_ids: vec![[3; 32], [4; 32]],
        }
    }

    #[test]
    fn signed_certificate_round_trips_and_verifies() {
        let authority = SigningKey::from_slice(&[5; 32]).expect("valid key");
        let certificate =
            DeviceCertificate::issue(payload(&authority), &authority).expect("valid certificate");
        let encoded = certificate.canonical_bytes().expect("encodable");
        let decoded = DeviceCertificate::decode(&encoded).expect("decodable");
        assert_eq!(decoded, certificate);
        assert!(decoded
            .verify(authority.verifying_key(), "epdn-test", 50)
            .is_ok());
    }

    #[test]
    fn tampered_certificate_fails_closed() {
        let authority = SigningKey::from_slice(&[5; 32]).expect("valid key");
        let mut certificate =
            DeviceCertificate::issue(payload(&authority), &authority).expect("valid certificate");
        certificate.payload.platform = "desktop-emulator".to_owned();
        assert!(matches!(
            certificate.verify(authority.verifying_key(), "epdn-test", 50),
            Err(CertificateError::InvalidSignature)
        ));
    }

    #[test]
    fn certificate_expiry_is_epoch_bounded() {
        let authority = SigningKey::from_slice(&[5; 32]).expect("valid key");
        let certificate =
            DeviceCertificate::issue(payload(&authority), &authority).expect("valid certificate");
        assert!(matches!(
            certificate.verify(authority.verifying_key(), "epdn-test", 100),
            Err(CertificateError::Expired(100))
        ));
    }
}
