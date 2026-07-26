use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::encoding::{DecodeError, Decoder, EncodeError, Encoder};

pub const EPDN_PROTOCOL_VERSION: u16 = 1;
pub const MAX_CHAIN_ID_BYTES: usize = 64;
pub const MAX_PLATFORM_BYTES: usize = 32;
pub const MAX_BOARD_FAMILY_BYTES: usize = 48;
pub const MAX_CHIP_REVISION_BYTES: usize = 32;
pub const MAX_BATCH_ID_BYTES: usize = 64;
pub const MAX_MANUFACTURER_BYTES: usize = 64;
pub const MAX_FIRMWARE_POLICIES: usize = 16;
pub const MAX_CHALLENGE_BYTES: usize = 512;
pub const MAX_CERTIFICATE_BYTES: usize = 4_096;
pub const MAX_SUBMISSION_BYTES: usize = 8_192;
pub const MAX_TRANSACTION_BYTES: usize = 2_048;
pub const BLOCK_REWARD: u64 = 100;

pub type Hash32 = [u8; 32];
pub type Address = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityClass {
    L0SoftwareTest = 0,
    L1ProtectedSoftwareIdentity = 1,
    L2NativeHardwareIdentity = 2,
    L3ExternalSecureElement = 3,
    L4AttestedPlatform = 4,
}

impl SecurityClass {
    pub fn from_wire(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::L0SoftwareTest),
            1 => Ok(Self::L1ProtectedSoftwareIdentity),
            2 => Ok(Self::L2NativeHardwareIdentity),
            3 => Ok(Self::L3ExternalSecureElement),
            4 => Ok(Self::L4AttestedPlatform),
            _ => Err(DecodeError::InvalidEnum {
                field: "security_class",
                value,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochChallenge {
    pub protocol_version: u16,
    pub chain_id: String,
    pub epoch_number: u64,
    pub previous_block_hash: Hash32,
    pub network_randomness: Hash32,
    pub device_public_key_hash: Hash32,
    pub approved_firmware_id: Hash32,
    pub security_class: SecurityClass,
}

impl EpochChallenge {
    const OBJECT_TYPE: u8 = 1;

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut encoder = Encoder::with_header(Self::OBJECT_TYPE, self.protocol_version);
        encoder.string("chain_id", &self.chain_id, MAX_CHAIN_ID_BYTES)?;
        encoder.u64(self.epoch_number);
        encoder.fixed(&self.previous_block_hash);
        encoder.fixed(&self.network_randomness);
        encoder.fixed(&self.device_public_key_hash);
        encoder.fixed(&self.approved_firmware_id);
        encoder.u8(self.security_class as u8);
        Ok(encoder.finish())
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::with_header(
            input,
            MAX_CHALLENGE_BYTES,
            Self::OBJECT_TYPE,
            EPDN_PROTOCOL_VERSION,
        )?;
        let challenge = Self {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: decoder.string("chain_id", MAX_CHAIN_ID_BYTES)?,
            epoch_number: decoder.u64()?,
            previous_block_hash: decoder.fixed()?,
            network_randomness: decoder.fixed()?,
            device_public_key_hash: decoder.fixed()?,
            approved_firmware_id: decoder.fixed()?,
            security_class: SecurityClass::from_wire(decoder.u8()?)?,
        };
        decoder.finish()?;
        Ok(challenge)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HexError {
    #[error("{field} must contain exactly {expected} hexadecimal bytes")]
    InvalidLength {
        field: &'static str,
        expected: usize,
    },
    #[error("{field} contains invalid hexadecimal data")]
    InvalidHex { field: &'static str },
}

pub fn hash_domain(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn parse_hex_32(field: &'static str, value: &str) -> Result<Hash32, HexError> {
    if value.len() != 64 {
        return Err(HexError::InvalidLength {
            field,
            expected: 32,
        });
    }
    let mut output = [0_u8; 32];
    decode_hex_into(value, &mut output).map_err(|()| HexError::InvalidHex { field })?;
    Ok(output)
}

fn decode_hex_into(input: &str, output: &mut [u8]) -> Result<(), ()> {
    if input.len() != output.len() * 2 {
        return Err(());
    }
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(input.as_bytes()[index * 2])?;
        let low = hex_nibble(input.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(())
}

fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> EpochChallenge {
        EpochChallenge {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            epoch_number: 42,
            previous_block_hash: [1; 32],
            network_randomness: [2; 32],
            device_public_key_hash: [3; 32],
            approved_firmware_id: [4; 32],
            security_class: SecurityClass::L2NativeHardwareIdentity,
        }
    }

    #[test]
    fn challenge_encoding_is_deterministic_and_round_trips() {
        let encoded = challenge().canonical_bytes().expect("valid challenge");
        assert_eq!(&encoded[..7], b"EPDN\x01\x00\x01");
        assert_eq!(EpochChallenge::decode(&encoded), Ok(challenge()));
    }

    #[test]
    fn challenge_rejects_trailing_and_oversized_data() {
        let mut trailing = challenge().canonical_bytes().expect("valid challenge");
        trailing.push(0);
        assert!(matches!(
            EpochChallenge::decode(&trailing),
            Err(DecodeError::TrailingBytes(1))
        ));

        let oversized = vec![0; MAX_CHALLENGE_BYTES + 1];
        assert!(matches!(
            EpochChallenge::decode(&oversized),
            Err(DecodeError::Oversized { .. })
        ));
    }

    #[test]
    fn hex_parser_accepts_mixed_case_and_rejects_bad_input() {
        let parsed = parse_hex_32(
            "value",
            "Aa000000000000000000000000000000000000000000000000000000000000Bb",
        )
        .expect("valid hex");
        assert_eq!(parsed[0], 0xaa);
        assert_eq!(parsed[31], 0xbb);
        assert!(parse_hex_32("value", "ff").is_err());
    }
}
