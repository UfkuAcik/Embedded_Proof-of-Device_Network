use epdn_protocol::{
    hash_domain, hex_lower, DeviceCertificate, DeviceCertificatePayload, EpochChallenge,
    SecurityClass, SignedTransfer, TicketSubmission, EPDN_PROTOCOL_VERSION,
};
use p256::ecdsa::SigningKey;
use serde_json::json;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).expect("test-vector scalar is valid")
}

fn main() {
    let authority = key(1);
    let device = key(2);
    let wallet = key(3);
    let authority_public = authority.verifying_key().to_encoded_point(true);
    let device_public = device.verifying_key().to_encoded_point(true);
    let firmware_id = hash_domain(b"EPDN_FIRMWARE_ID_V1", &[b"epdn-vector-firmware"]);
    let device_id = hash_domain(b"EPDN_DEVICE_PUBLIC_KEY_V1", &[device_public.as_bytes()]);
    let challenge = EpochChallenge {
        protocol_version: EPDN_PROTOCOL_VERSION,
        chain_id: "epdn-vector-testnet".to_owned(),
        epoch_number: 42,
        previous_block_hash: [0x11; 32],
        network_randomness: [0x22; 32],
        device_public_key_hash: device_id,
        approved_firmware_id: firmware_id,
        security_class: SecurityClass::L2NativeHardwareIdentity,
    };
    let submission = TicketSubmission::create(challenge.clone(), &device).expect("ticket");
    let certificate = DeviceCertificate::issue(
        DeviceCertificatePayload {
            protocol_version: EPDN_PROTOCOL_VERSION,
            serial: [0x44; 16],
            device_public_key: device_public.as_bytes().to_vec(),
            platform: "esp32".to_owned(),
            board_family: "esp32-generic".to_owned(),
            security_class: SecurityClass::L2NativeHardwareIdentity,
            authority_id: hash_domain(b"EPDN_AUTHORITY_ID_V1", &[authority_public.as_bytes()]),
            provisioned_at_unix_seconds: 1_700_000_000,
            issued_at_epoch: 1,
            expires_at_epoch: 10_000,
            allowed_chain_id: "epdn-vector-testnet".to_owned(),
            chip_revision: Some("v3.1".to_owned()),
            batch_id: Some("vector-batch-01".to_owned()),
            manufacturer: Some("EPDN test vectors".to_owned()),
            allowed_firmware_ids: vec![firmware_id],
        },
        &authority,
    )
    .expect("certificate");
    let transfer = SignedTransfer::create(
        "epdn-vector-testnet".to_owned(),
        [0x55; 32],
        25,
        2,
        7,
        &wallet,
    )
    .expect("transfer");

    let output = json!({
        "format": "EPDN deterministic binary encoding V1",
        "warning": "The private keys below are public test fixtures and MUST NOT be used elsewhere.",
        "authority_private_key_hex": hex_lower(&[1; 32]),
        "authority_public_key_sec1_compressed_hex": hex_lower(authority_public.as_bytes()),
        "device_private_key_hex": hex_lower(&[2; 32]),
        "device_public_key_sec1_compressed_hex": hex_lower(device_public.as_bytes()),
        "wallet_private_key_hex": hex_lower(&[3; 32]),
        "wallet_public_key_sec1_compressed_hex": hex_lower(
            wallet.verifying_key().to_encoded_point(true).as_bytes()
        ),
        "firmware_id_hex": hex_lower(&firmware_id),
        "device_public_key_hash_hex": hex_lower(&device_id),
        "challenge_hex": hex_lower(&challenge.canonical_bytes().expect("challenge bytes")),
        "deterministic_proof_raw_rs_hex": hex_lower(&submission.deterministic_proof),
        "ticket_hex": hex_lower(&submission.ticket),
        "submission_hash_hex": hex_lower(&submission.submission_hash().expect("hash")),
        "score_hex": hex_lower(&submission.score()),
        "submission_signature_raw_rs_hex": hex_lower(&submission.signature),
        "submission_hex": hex_lower(&submission.canonical_bytes().expect("submission bytes")),
        "certificate_payload_hex": hex_lower(
            &certificate.payload.canonical_bytes().expect("payload bytes")
        ),
        "certificate_signature_raw_rs_hex": hex_lower(&certificate.issuer_signature),
        "certificate_hex": hex_lower(&certificate.canonical_bytes().expect("certificate bytes")),
        "certificate_hash_hex": hex_lower(&certificate.certificate_hash().expect("certificate hash")),
        "transfer_unsigned_hex": hex_lower(
            &transfer.unsigned_canonical_bytes().expect("unsigned transfer")
        ),
        "transfer_signature_payload_hex": hex_lower(
            &transfer.signature_payload().expect("signature payload")
        ),
        "transfer_signature_raw_rs_hex": hex_lower(&transfer.signature),
        "transfer_hex": hex_lower(&transfer.canonical_bytes().expect("transfer bytes")),
        "transfer_hash_hex": hex_lower(&transfer.transaction_hash().expect("transfer hash")),
    });
    println!("{}", serde_json::to_string_pretty(&output).expect("JSON"));
}
