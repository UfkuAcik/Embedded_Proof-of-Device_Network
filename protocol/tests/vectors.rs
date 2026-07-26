use epdn_protocol::{
    hex_lower, DeviceCertificate, EpochChallenge, SignedTransfer, TicketSubmission,
};
use p256::ecdsa::VerifyingKey;
use serde_json::Value;

fn bytes(vector: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        vector[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing vector field {field}")),
    )
    .unwrap_or_else(|_| panic!("invalid hex in vector field {field}"))
}

#[test]
fn rust_matches_the_checked_in_cross_platform_v1_vector() {
    let vector: Value =
        serde_json::from_str(include_str!("../test-vectors/v1.json")).expect("valid vector JSON");

    let challenge =
        EpochChallenge::decode(&bytes(&vector, "challenge_hex")).expect("challenge decode");
    assert_eq!(
        hex_lower(&challenge.canonical_bytes().expect("challenge encode")),
        vector["challenge_hex"]
    );

    let certificate =
        DeviceCertificate::decode(&bytes(&vector, "certificate_hex")).expect("certificate decode");
    assert_eq!(
        certificate.payload.provisioned_at_unix_seconds,
        1_700_000_000
    );
    assert_eq!(certificate.payload.chip_revision.as_deref(), Some("v3.1"));
    assert_eq!(
        certificate.payload.batch_id.as_deref(),
        Some("vector-batch-01")
    );
    assert_eq!(
        certificate.payload.manufacturer.as_deref(),
        Some("EPDN test vectors")
    );
    let authority_public =
        VerifyingKey::from_sec1_bytes(&bytes(&vector, "authority_public_key_sec1_compressed_hex"))
            .expect("authority public key");
    certificate
        .verify(&authority_public, "epdn-vector-testnet", 42)
        .expect("certificate signature");
    assert_eq!(
        hex_lower(&certificate.certificate_hash().expect("certificate hash")),
        vector["certificate_hash_hex"]
    );

    let submission =
        TicketSubmission::decode(&bytes(&vector, "submission_hex")).expect("submission decode");
    submission
        .verify_crypto(&bytes(&vector, "device_public_key_sec1_compressed_hex"))
        .expect("ticket proof and signature");
    assert_eq!(hex_lower(&submission.ticket), vector["ticket_hex"]);
    assert_eq!(
        hex_lower(&submission.submission_hash().expect("submission hash")),
        vector["submission_hash_hex"]
    );
    assert_eq!(hex_lower(&submission.score()), vector["score_hex"]);

    let transfer =
        SignedTransfer::decode(&bytes(&vector, "transfer_hex")).expect("transfer decode");
    transfer
        .verify("epdn-vector-testnet")
        .expect("transfer signature");
    assert_eq!(
        hex_lower(&transfer.signature_payload().expect("signature payload")),
        vector["transfer_signature_payload_hex"]
    );
    assert_eq!(
        hex_lower(&transfer.transaction_hash().expect("transaction hash")),
        vector["transfer_hash_hex"]
    );
}
