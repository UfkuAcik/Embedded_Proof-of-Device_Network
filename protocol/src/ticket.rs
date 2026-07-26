use std::cmp::Ordering;

use p256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    encoding::{ensure_exact_length, DecodeError, Decoder, EncodeError, Encoder},
    types::{
        hash_domain, EpochChallenge, Hash32, EPDN_PROTOCOL_VERSION, MAX_CHALLENGE_BYTES,
        MAX_SUBMISSION_BYTES,
    },
};

const TICKET_SUBMISSION_TYPE: u8 = 4;
const P256_RAW_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketSubmission {
    pub challenge: EpochChallenge,
    pub deterministic_proof: Vec<u8>,
    pub ticket: Hash32,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TicketError {
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error("device public key does not match the challenge")]
    WrongDevice,
    #[error("ticket proof length is invalid")]
    InvalidProofLength,
    #[error("submission signature length is invalid")]
    InvalidSignatureLength,
    #[error("device public key is invalid")]
    InvalidPublicKey,
    #[error("deterministic proof is invalid")]
    InvalidProof,
    #[error("ticket hash does not match the signed challenge and device identity")]
    InvalidTicket,
    #[error("submission signature is invalid")]
    InvalidSignature,
    #[error("P-256 deterministic signing failed")]
    SigningFailed,
}

impl TicketSubmission {
    pub fn create(challenge: EpochChallenge, device_key: &SigningKey) -> Result<Self, TicketError> {
        let public_key = device_key.verifying_key().to_encoded_point(true);
        let public_key_hash = hash_domain(b"EPDN_DEVICE_PUBLIC_KEY_V1", &[public_key.as_bytes()]);
        if challenge.device_public_key_hash != public_key_hash {
            return Err(TicketError::WrongDevice);
        }
        let ticket_input = challenge.canonical_bytes()?;
        let proof_message = hash_domain(b"EPDN_PROOF_V1", &[&ticket_input]);
        let deterministic_proof: Signature = device_key
            .sign_prehash(&proof_message)
            .map_err(|_| TicketError::SigningFailed)?;
        let deterministic_proof = deterministic_proof.to_bytes().to_vec();
        // The proof establishes possession of the provisioned key, but its
        // ECDSA bytes are deliberately excluded from eligibility. ECDSA
        // verification cannot prove that a signer used RFC 6979; including
        // signature bytes here would let a malicious key holder vary the
        // nonce, grind candidate tickets, and submit only its best score.
        let ticket = hash_domain(
            b"EPDN_TICKET_V1",
            &[&challenge.device_public_key_hash, &ticket_input],
        );
        let submission_hash = hash_domain(b"EPDN_SUBMISSION_V1", &[&ticket_input, &ticket]);
        let signature: Signature = device_key
            .sign_prehash(&submission_hash)
            .map_err(|_| TicketError::SigningFailed)?;
        let signature = signature.to_bytes().to_vec();
        Ok(Self {
            challenge,
            deterministic_proof,
            ticket,
            signature,
        })
    }

    pub fn verify_crypto(&self, device_public_key: &[u8]) -> Result<(), TicketError> {
        let expected_device_hash = hash_domain(b"EPDN_DEVICE_PUBLIC_KEY_V1", &[device_public_key]);
        if expected_device_hash != self.challenge.device_public_key_hash {
            return Err(TicketError::WrongDevice);
        }
        ensure_exact_length(
            "deterministic_proof",
            &self.deterministic_proof,
            P256_RAW_SIGNATURE_BYTES,
        )
        .map_err(|_| TicketError::InvalidProofLength)?;
        ensure_exact_length("signature", &self.signature, P256_RAW_SIGNATURE_BYTES)
            .map_err(|_| TicketError::InvalidSignatureLength)?;

        let verifying_key = VerifyingKey::from_sec1_bytes(device_public_key)
            .map_err(|_| TicketError::InvalidPublicKey)?;
        let proof = Signature::from_slice(&self.deterministic_proof)
            .map_err(|_| TicketError::InvalidProofLength)?;
        let ticket_input = self.challenge.canonical_bytes()?;
        let proof_message = hash_domain(b"EPDN_PROOF_V1", &[&ticket_input]);
        verifying_key
            .verify_prehash(&proof_message, &proof)
            .map_err(|_| TicketError::InvalidProof)?;

        let expected_ticket = hash_domain(
            b"EPDN_TICKET_V1",
            &[&self.challenge.device_public_key_hash, &ticket_input],
        );
        if self.ticket != expected_ticket {
            return Err(TicketError::InvalidTicket);
        }

        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TicketError::InvalidSignatureLength)?;
        verifying_key
            .verify_prehash(&self.submission_hash()?, &signature)
            .map_err(|_| TicketError::InvalidSignature)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        ensure_exact_length(
            "deterministic_proof",
            &self.deterministic_proof,
            P256_RAW_SIGNATURE_BYTES,
        )?;
        ensure_exact_length("signature", &self.signature, P256_RAW_SIGNATURE_BYTES)?;
        let challenge = self.challenge.canonical_bytes()?;
        let mut encoder =
            Encoder::with_header(TICKET_SUBMISSION_TYPE, self.challenge.protocol_version);
        encoder.bytes_u32("challenge", &challenge, MAX_CHALLENGE_BYTES)?;
        encoder.bytes_u16(
            "deterministic_proof",
            &self.deterministic_proof,
            P256_RAW_SIGNATURE_BYTES,
        )?;
        encoder.fixed(&self.ticket);
        encoder.bytes_u16("signature", &self.signature, P256_RAW_SIGNATURE_BYTES)?;
        let bytes = encoder.finish();
        if bytes.len() > MAX_SUBMISSION_BYTES {
            return Err(EncodeError::LengthExceeded {
                field: "ticket_submission",
                actual: bytes.len(),
                maximum: MAX_SUBMISSION_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::with_header(
            input,
            MAX_SUBMISSION_BYTES,
            TICKET_SUBMISSION_TYPE,
            EPDN_PROTOCOL_VERSION,
        )?;
        let challenge_bytes = decoder.bytes_u32("challenge", MAX_CHALLENGE_BYTES)?;
        let deterministic_proof =
            decoder.bytes_u16("deterministic_proof", P256_RAW_SIGNATURE_BYTES)?;
        if deterministic_proof.len() != P256_RAW_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical {
                field: "deterministic_proof",
            });
        }
        let ticket = decoder.fixed()?;
        let signature = decoder.bytes_u16("signature", P256_RAW_SIGNATURE_BYTES)?;
        if signature.len() != P256_RAW_SIGNATURE_BYTES {
            return Err(DecodeError::NonCanonical { field: "signature" });
        }
        decoder.finish()?;
        let challenge = EpochChallenge::decode(&challenge_bytes)?;
        Ok(Self {
            challenge,
            deterministic_proof,
            ticket,
            signature,
        })
    }

    pub fn submission_hash(&self) -> Result<Hash32, EncodeError> {
        let ticket_input = self.challenge.canonical_bytes()?;
        Ok(hash_domain(
            b"EPDN_SUBMISSION_V1",
            &[&ticket_input, &self.ticket],
        ))
    }

    #[must_use]
    pub fn score(&self) -> Hash32 {
        hash_domain(b"EPDN_SCORE_V1", &[&self.ticket])
    }

    pub fn compare_for_winner(&self, other: &Self) -> Result<Ordering, EncodeError> {
        Ok(self
            .score()
            .cmp(&other.score())
            .then_with(|| {
                self.challenge
                    .device_public_key_hash
                    .cmp(&other.challenge.device_public_key_hash)
            })
            .then(self.submission_hash()?.cmp(&other.submission_hash()?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SecurityClass;

    fn challenge(device_key: &SigningKey) -> EpochChallenge {
        EpochChallenge {
            protocol_version: EPDN_PROTOCOL_VERSION,
            chain_id: "epdn-test".to_owned(),
            epoch_number: 8,
            previous_block_hash: [1; 32],
            network_randomness: [2; 32],
            device_public_key_hash: hash_domain(
                b"EPDN_DEVICE_PUBLIC_KEY_V1",
                &[device_key.verifying_key().to_encoded_point(true).as_bytes()],
            ),
            approved_firmware_id: [3; 32],
            security_class: SecurityClass::L2NativeHardwareIdentity,
        }
    }

    #[test]
    fn ticket_is_deterministic_and_round_trips() {
        let key = SigningKey::from_slice(&[11; 32]).expect("valid key");
        let first = TicketSubmission::create(challenge(&key), &key).expect("valid ticket");
        let second = TicketSubmission::create(challenge(&key), &key).expect("valid ticket");
        assert_eq!(first, second);
        first
            .verify_crypto(key.verifying_key().to_encoded_point(true).as_bytes())
            .expect("valid proof and signature");

        let encoded = first.canonical_bytes().expect("encodable");
        assert_eq!(
            TicketSubmission::decode(&encoded).expect("decodable"),
            first
        );
    }

    #[test]
    fn proof_signature_variants_cannot_grind_ticket_or_score() {
        let key = SigningKey::from_slice(&[11; 32]).expect("valid key");
        let original = TicketSubmission::create(challenge(&key), &key).expect("valid ticket");
        let proof = Signature::from_slice(&original.deterministic_proof).expect("valid proof");
        let alternate_proof =
            Signature::from_scalars(proof.r().to_bytes(), (-proof.s()).to_bytes())
                .expect("the ECDSA high/low-S twin is valid");
        assert_ne!(proof.to_bytes(), alternate_proof.to_bytes());

        let mut alternate = original.clone();
        alternate.deterministic_proof = alternate_proof.to_bytes().to_vec();
        alternate
            .verify_crypto(key.verifying_key().to_encoded_point(true).as_bytes())
            .expect("alternate valid proof");

        assert_eq!(original.ticket, alternate.ticket);
        assert_eq!(original.score(), alternate.score());
        assert_eq!(
            original.submission_hash().expect("original hash"),
            alternate.submission_hash().expect("alternate hash")
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let key = SigningKey::from_slice(&[11; 32]).expect("valid key");
        let mut submission = TicketSubmission::create(challenge(&key), &key).expect("valid ticket");
        submission.ticket[0] ^= 1;
        assert!(matches!(
            submission.verify_crypto(key.verifying_key().to_encoded_point(true).as_bytes()),
            Err(TicketError::InvalidTicket)
        ));
    }

    #[test]
    fn parser_rejects_truncated_and_oversized_packets() {
        let key = SigningKey::from_slice(&[11; 32]).expect("valid key");
        let encoded = TicketSubmission::create(challenge(&key), &key)
            .expect("valid ticket")
            .canonical_bytes()
            .expect("encodable");
        assert!(TicketSubmission::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(matches!(
            TicketSubmission::decode(&vec![0; MAX_SUBMISSION_BYTES + 1]),
            Err(DecodeError::Oversized { .. })
        ));
    }
}
