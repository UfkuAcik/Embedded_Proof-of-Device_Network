use epdn_protocol::{DeviceCertificate, EpochChallenge, SignedTransfer, TicketSubmission};
use serde_json::Value;

fn corpus_bytes(seed: &str) -> Vec<u8> {
    let encoded = seed
        .trim()
        .strip_prefix("hex:")
        .expect("checked-in corpus seeds use the reviewable hex format")
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    hex::decode(encoded).expect("checked-in corpus seed must contain valid hex")
}

fn vector_bytes(vector: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        vector[field]
            .as_str()
            .expect("vector field must be a hex string"),
    )
    .expect("vector field must contain valid hex")
}

#[test]
fn valid_fuzz_seeds_match_v1_vectors_and_round_trip_canonically() {
    let vector: Value =
        serde_json::from_str(include_str!("../test-vectors/v1.json")).expect("valid V1 vector");

    let challenge_seed = corpus_bytes(include_str!(
        "../fuzz/corpus/epoch_challenge_decode/valid_v1"
    ));
    assert_eq!(challenge_seed, vector_bytes(&vector, "challenge_hex"));
    let challenge = EpochChallenge::decode(&challenge_seed).expect("valid challenge seed");
    assert_eq!(
        challenge.canonical_bytes().expect("canonical challenge"),
        challenge_seed
    );

    let certificate_seed = corpus_bytes(include_str!(
        "../fuzz/corpus/device_certificate_decode/valid_v1"
    ));
    assert_eq!(certificate_seed, vector_bytes(&vector, "certificate_hex"));
    let certificate = DeviceCertificate::decode(&certificate_seed).expect("valid certificate seed");
    assert_eq!(
        certificate
            .canonical_bytes()
            .expect("canonical certificate"),
        certificate_seed
    );

    let submission_seed = corpus_bytes(include_str!(
        "../fuzz/corpus/ticket_submission_decode/valid_v1"
    ));
    assert_eq!(submission_seed, vector_bytes(&vector, "submission_hex"));
    let submission =
        TicketSubmission::decode(&submission_seed).expect("valid ticket-submission seed");
    assert_eq!(
        submission
            .canonical_bytes()
            .expect("canonical ticket submission"),
        submission_seed
    );

    let transfer_seed = corpus_bytes(include_str!(
        "../fuzz/corpus/signed_transfer_decode/valid_v1"
    ));
    assert_eq!(transfer_seed, vector_bytes(&vector, "transfer_hex"));
    let transfer = SignedTransfer::decode(&transfer_seed).expect("valid transfer seed");
    assert_eq!(
        transfer.canonical_bytes().expect("canonical transfer"),
        transfer_seed
    );
}

#[test]
fn truncated_fuzz_seeds_are_rejected_by_every_consensus_parser() {
    let challenge = corpus_bytes(include_str!(
        "../fuzz/corpus/epoch_challenge_decode/truncated_header"
    ));
    assert!(EpochChallenge::decode(&challenge).is_err());

    let certificate = corpus_bytes(include_str!(
        "../fuzz/corpus/device_certificate_decode/truncated_header"
    ));
    assert!(DeviceCertificate::decode(&certificate).is_err());

    let submission = corpus_bytes(include_str!(
        "../fuzz/corpus/ticket_submission_decode/truncated_header"
    ));
    assert!(TicketSubmission::decode(&submission).is_err());

    let transfer = corpus_bytes(include_str!(
        "../fuzz/corpus/signed_transfer_decode/truncated_header"
    ));
    assert!(SignedTransfer::decode(&transfer).is_err());
}
