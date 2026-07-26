use epdn_node::{Enrollment, NodeConfig, NodeCore, NodeError};
use epdn_protocol::{
    hash_domain, DecodeError, LedgerError, NetworkMode, SecurityClass, SignedTransfer,
    TicketSubmission, TicketValidationError, TransactionError, EPDN_PROTOCOL_VERSION,
    MAX_SUBMISSION_BYTES,
};
use p256::ecdsa::SigningKey;

struct Fixture {
    node: NodeCore,
    authority: SigningKey,
    validator: SigningKey,
    device: SigningKey,
    device_id: [u8; 32],
    firmware_id: [u8; 32],
    wallet: SigningKey,
    wallet_address: [u8; 32],
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).expect("test scalar is valid")
}

fn compressed_public_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn wallet_address(key: &SigningKey) -> [u8; 32] {
    hash_domain(
        b"EPDN_WALLET_ADDRESS_V1",
        &[key.verifying_key().to_encoded_point(true).as_bytes()],
    )
}

fn fixture_with(network_mode: NetworkMode, security_class: SecurityClass) -> Fixture {
    let authority = key(31);
    let validator = key(32);
    let device = key(33);
    let wallet = key(34);
    let wallet_address = wallet_address(&wallet);
    let mut config = NodeConfig::local_testnet();
    config.network_mode = network_mode;
    config.minimum_security_class = SecurityClass::L0SoftwareTest;
    let firmware_id = *config
        .approved_firmware_ids
        .iter()
        .next()
        .expect("default firmware");
    let mut node = NodeCore::new(config);
    let certificate = node
        .issue_certificate(
            Enrollment {
                device_public_key: compressed_public_key(&device),
                platform: "esp32".to_owned(),
                board_family: "esp32-generic".to_owned(),
                security_class,
                provisioned_at_unix_seconds: 1_700_000_000,
                chip_revision: Some("v3.1".to_owned()),
                batch_id: Some("test-batch".to_owned()),
                manufacturer: None,
                allowed_firmware_ids: vec![firmware_id],
                expires_at_epoch: 1_000,
            },
            &authority,
        )
        .expect("certificate");
    let device_id = node
        .register_device(certificate, wallet_address, authority.verifying_key())
        .expect("registration");
    Fixture {
        node,
        authority,
        validator,
        device,
        device_id,
        firmware_id,
        wallet,
        wallet_address,
    }
}

fn fixture() -> Fixture {
    fixture_with(
        NetworkMode::Testnet,
        SecurityClass::L2NativeHardwareIdentity,
    )
}

fn valid_submission(fixture: &Fixture) -> TicketSubmission {
    let challenge = fixture
        .node
        .challenge_for(fixture.device_id, fixture.firmware_id)
        .expect("challenge");
    TicketSubmission::create(challenge, &fixture.device).expect("submission")
}

#[test]
fn valid_ticket_is_accepted_and_exact_replay_is_rejected() {
    let mut fixture = fixture();
    let submission = valid_submission(&fixture);
    fixture
        .node
        .submit_ticket(submission.clone(), fixture.authority.verifying_key())
        .expect("first ticket");
    assert!(matches!(
        fixture
            .node
            .submit_ticket(submission, fixture.authority.verifying_key()),
        Err(NodeError::Ticket(
            TicketValidationError::DuplicateSubmission
        ))
    ));
}

#[test]
fn second_ticket_from_same_device_is_rejected_even_before_bad_crypto() {
    let mut fixture = fixture();
    let first = valid_submission(&fixture);
    fixture
        .node
        .submit_ticket(first.clone(), fixture.authority.verifying_key())
        .expect("first ticket");
    let mut second = first;
    second.ticket[0] ^= 1;
    assert!(matches!(
        fixture
            .node
            .submit_ticket(second, fixture.authority.verifying_key()),
        Err(NodeError::Ticket(
            TicketValidationError::DuplicateDeviceEpoch
        ))
    ));
}

#[test]
fn stale_future_wrong_chain_and_wrong_randomness_are_rejected() {
    let cases = [
        ("stale", -1_i8),
        ("future", 1_i8),
        ("wrong_chain", 2_i8),
        ("wrong_randomness", 3_i8),
        ("wrong_previous_block", 4_i8),
    ];
    for (name, mutation) in cases {
        let mut fixture = fixture();
        let mut challenge = fixture
            .node
            .challenge_for(fixture.device_id, fixture.firmware_id)
            .expect("challenge");
        match mutation {
            -1 => challenge.epoch_number -= 1,
            1 => challenge.epoch_number += 1,
            2 => challenge.chain_id = "other-chain".to_owned(),
            3 => challenge.network_randomness[0] ^= 1,
            4 => challenge.previous_block_hash[0] ^= 1,
            _ => unreachable!(),
        }
        let submission =
            TicketSubmission::create(challenge, &fixture.device).expect("signed submission");
        let error = fixture
            .node
            .submit_ticket(submission, fixture.authority.verifying_key())
            .expect_err(name);
        match mutation {
            -1 => assert!(matches!(
                error,
                NodeError::Ticket(TicketValidationError::StaleEpoch { .. })
            )),
            1 => assert!(matches!(
                error,
                NodeError::Ticket(TicketValidationError::FutureEpoch { .. })
            )),
            2 => assert!(matches!(
                error,
                NodeError::Ticket(TicketValidationError::WrongChain { .. })
            )),
            3 => assert!(matches!(
                error,
                NodeError::Ticket(TicketValidationError::WrongRandomness)
            )),
            4 => assert!(matches!(
                error,
                NodeError::Ticket(TicketValidationError::WrongPreviousBlock)
            )),
            _ => unreachable!(),
        }
    }
}

#[test]
fn firmware_security_downgrade_and_unregistered_device_are_rejected() {
    let mut fixture = fixture();
    let mut challenge = fixture
        .node
        .challenge_for(fixture.device_id, fixture.firmware_id)
        .expect("challenge");
    challenge.approved_firmware_id = [99; 32];
    let wrong_firmware = TicketSubmission::create(challenge, &fixture.device).expect("submission");
    assert!(matches!(
        fixture
            .node
            .submit_ticket(wrong_firmware, fixture.authority.verifying_key()),
        Err(NodeError::Ticket(TicketValidationError::FirmwareNotAllowed))
    ));

    let mut challenge = fixture
        .node
        .challenge_for(fixture.device_id, fixture.firmware_id)
        .expect("challenge");
    challenge.security_class = SecurityClass::L1ProtectedSoftwareIdentity;
    let downgrade = TicketSubmission::create(challenge, &fixture.device).expect("submission");
    assert!(matches!(
        fixture
            .node
            .submit_ticket(downgrade, fixture.authority.verifying_key()),
        Err(NodeError::Ticket(TicketValidationError::SecurityDowngrade))
    ));

    let unknown_key = key(41);
    let mut challenge = fixture
        .node
        .challenge_for(fixture.device_id, fixture.firmware_id)
        .expect("challenge");
    challenge.device_public_key_hash = hash_domain(
        b"EPDN_DEVICE_PUBLIC_KEY_V1",
        &[unknown_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()],
    );
    let unknown = TicketSubmission::create(challenge, &unknown_key).expect("submission");
    assert!(matches!(
        fixture
            .node
            .submit_ticket(unknown, fixture.authority.verifying_key()),
        Err(NodeError::Ticket(TicketValidationError::UnregisteredDevice))
    ));
}

#[test]
fn revoked_and_paused_devices_fail_closed() {
    let mut revoked = fixture();
    let submission = valid_submission(&revoked);
    revoked
        .node
        .revoke_device(&revoked.device_id, "compromised".to_owned())
        .expect("revoke");
    assert!(matches!(
        revoked
            .node
            .submit_ticket(submission, revoked.authority.verifying_key()),
        Err(NodeError::Ticket(TicketValidationError::RevokedDevice))
            | Err(NodeError::DeviceRevoked)
    ));

    let mut paused = fixture();
    let submission = valid_submission(&paused);
    paused.node.pause_device(&paused.device_id).expect("pause");
    assert!(matches!(
        paused
            .node
            .submit_ticket(submission, paused.authority.verifying_key()),
        Err(NodeError::DevicePaused)
    ));
}

#[test]
fn sole_miner_pending_revocation_finalizes_as_rewardless_management_block() {
    let mut fixture = fixture();
    let submission = valid_submission(&fixture);
    fixture
        .node
        .submit_ticket(submission, fixture.authority.verifying_key())
        .expect("ticket accepted before revocation");
    fixture
        .node
        .revoke_device(&fixture.device_id, "compromised identity".to_owned())
        .expect("revocation queued");

    let block = fixture
        .node
        .finalize_epoch(&fixture.validator)
        .expect("revocation-only block avoids finalization deadlock");
    assert!(block.is_revocation_only());
    assert_eq!(block.reward.amount, 0);
    assert_eq!(fixture.node.balance(&fixture.wallet_address), 0);
    assert_eq!(block.transactions.len(), 1);
    assert!(matches!(
        &block.transactions[0],
        epdn_protocol::ChainTransaction::DeviceRevocation(revocation)
            if revocation.device_id == fixture.device_id
    ));
    assert!(fixture
        .node
        .registry()
        .get(&fixture.device_id)
        .is_some_and(|device| device.revocation.is_some()));
    block
        .verify_integrity()
        .expect("management block integrity");
}

#[test]
fn production_rejects_l0_identity() {
    let mut fixture = fixture_with(NetworkMode::Production, SecurityClass::L0SoftwareTest);
    let submission = valid_submission(&fixture);
    assert!(matches!(
        fixture
            .node
            .submit_ticket(submission, fixture.authority.verifying_key()),
        Err(NodeError::Ticket(
            TicketValidationError::L0ForbiddenOnProduction
        ))
    ));
}

#[test]
fn malformed_and_oversized_consensus_packets_are_rejected() {
    assert!(TicketSubmission::decode(b"not-epdn").is_err());
    assert!(matches!(
        TicketSubmission::decode(&vec![0; MAX_SUBMISSION_BYTES + 1]),
        Err(DecodeError::Oversized { .. })
    ));
}

#[test]
fn reward_transfer_nonce_replay_network_and_balance_rules_are_enforced() {
    let mut fixture = fixture();
    let submission = valid_submission(&fixture);
    fixture
        .node
        .submit_ticket(submission, fixture.authority.verifying_key())
        .expect("ticket");
    fixture
        .node
        .finalize_epoch(&fixture.validator)
        .expect("block");
    assert_eq!(fixture.node.balance(&fixture.wallet_address), 100);

    let recipient = [55; 32];
    let transfer = SignedTransfer::create(
        fixture.node.config().chain_id.clone(),
        recipient,
        40,
        2,
        0,
        &fixture.wallet,
    )
    .expect("transfer");
    fixture
        .node
        .submit_transfer(transfer.clone())
        .expect("accepted");
    assert_eq!(fixture.node.balance(&fixture.wallet_address), 100);
    assert_eq!(fixture.node.balance(&recipient), 0);
    assert_eq!(fixture.node.next_nonce(&fixture.wallet_address), 1);
    assert!(matches!(
        fixture.node.submit_transfer(transfer),
        Err(NodeError::TransactionReplay)
    ));

    let wrong_nonce = SignedTransfer::create(
        fixture.node.config().chain_id.clone(),
        [56; 32],
        1,
        0,
        0,
        &fixture.wallet,
    )
    .expect("transfer");
    assert!(matches!(
        fixture.node.submit_transfer(wrong_nonce),
        Err(NodeError::Ledger(LedgerError::WrongNonce { .. }))
    ));

    let wrong_network =
        SignedTransfer::create("other-chain".to_owned(), [57; 32], 1, 0, 1, &fixture.wallet)
            .expect("transfer");
    assert!(matches!(
        fixture.node.submit_transfer(wrong_network),
        Err(NodeError::Ledger(LedgerError::Transaction(
            TransactionError::WrongChain { .. }
        )))
    ));

    let too_large = SignedTransfer::create(
        fixture.node.config().chain_id.clone(),
        [58; 32],
        10_000,
        0,
        1,
        &fixture.wallet,
    )
    .expect("transfer");
    assert!(matches!(
        fixture.node.submit_transfer(too_large),
        Err(NodeError::Ledger(LedgerError::InsufficientBalance))
    ));

    let next_ticket = valid_submission(&fixture);
    fixture
        .node
        .submit_ticket(next_ticket, fixture.authority.verifying_key())
        .expect("next-epoch ticket");
    fixture
        .node
        .finalize_epoch(&fixture.validator)
        .expect("block with transfer");
    assert_eq!(fixture.node.balance(&fixture.wallet_address), 158);
    assert_eq!(fixture.node.balance(&recipient), 40);
    assert_eq!(fixture.node.next_nonce(&fixture.wallet_address), 1);
}

#[test]
fn block_commits_reward_and_revocation_transactions() {
    let mut fixture = fixture();
    let second_device = key(61);
    let certificate = fixture
        .node
        .issue_certificate(
            Enrollment {
                device_public_key: compressed_public_key(&second_device),
                platform: "esp32".to_owned(),
                board_family: "esp32-generic".to_owned(),
                security_class: SecurityClass::L2NativeHardwareIdentity,
                provisioned_at_unix_seconds: 1_700_000_001,
                chip_revision: None,
                batch_id: None,
                manufacturer: None,
                allowed_firmware_ids: vec![fixture.firmware_id],
                expires_at_epoch: 1_000,
            },
            &fixture.authority,
        )
        .expect("certificate");
    let second_id = fixture
        .node
        .register_device(certificate, [62; 32], fixture.authority.verifying_key())
        .expect("register");
    fixture
        .node
        .revoke_device(&second_id, "test revocation".to_owned())
        .expect("revoke");
    let ticket = valid_submission(&fixture);
    fixture
        .node
        .submit_ticket(ticket, fixture.authority.verifying_key())
        .expect("ticket");
    let block = fixture
        .node
        .finalize_epoch(&fixture.validator)
        .expect("block");
    assert!(block.transactions.iter().any(|transaction| matches!(
        transaction,
        epdn_protocol::ChainTransaction::DeviceRevocation(_)
    )));
    assert!(block.transactions.iter().any(|transaction| matches!(
        transaction,
        epdn_protocol::ChainTransaction::RewardDistribution(_)
    )));
    assert_eq!(block.header.protocol_version, EPDN_PROTOCOL_VERSION);
}

#[test]
fn winner_and_block_are_independent_of_ticket_arrival_order() {
    let mut fixture = fixture();
    let mut devices = vec![(fixture.device.clone(), fixture.device_id)];
    for (key_byte, reward_byte) in [(91_u8, 92_u8), (93_u8, 94_u8)] {
        let device = key(key_byte);
        let certificate = fixture
            .node
            .issue_certificate(
                Enrollment {
                    device_public_key: compressed_public_key(&device),
                    platform: "esp32".to_owned(),
                    board_family: "esp32-generic".to_owned(),
                    security_class: SecurityClass::L2NativeHardwareIdentity,
                    provisioned_at_unix_seconds: 1_700_000_100 + u64::from(key_byte),
                    chip_revision: None,
                    batch_id: None,
                    manufacturer: None,
                    allowed_firmware_ids: vec![fixture.firmware_id],
                    expires_at_epoch: 1_000,
                },
                &fixture.authority,
            )
            .expect("certificate");
        let device_id = fixture
            .node
            .register_device(
                certificate,
                [reward_byte; 32],
                fixture.authority.verifying_key(),
            )
            .expect("registration");
        devices.push((device, device_id));
    }
    let submissions = devices
        .iter()
        .map(|(device, device_id)| {
            let challenge = fixture
                .node
                .challenge_for(*device_id, fixture.firmware_id)
                .expect("challenge");
            TicketSubmission::create(challenge, device).expect("submission")
        })
        .collect::<Vec<_>>();
    let mut forward = fixture.node.clone();
    let mut reverse = fixture.node;
    for submission in &submissions {
        forward
            .submit_ticket(submission.clone(), fixture.authority.verifying_key())
            .expect("forward ticket");
    }
    for submission in submissions.iter().rev() {
        reverse
            .submit_ticket(submission.clone(), fixture.authority.verifying_key())
            .expect("reverse ticket");
    }

    let forward_block = forward
        .finalize_epoch(&fixture.validator)
        .expect("forward block");
    let reverse_block = reverse
        .finalize_epoch(&fixture.validator)
        .expect("reverse block");
    assert_eq!(
        forward_block.header.winning_device_public_key_hash,
        reverse_block.header.winning_device_public_key_hash
    );
    assert_eq!(forward_block.block_hash, reverse_block.block_hash);
}
