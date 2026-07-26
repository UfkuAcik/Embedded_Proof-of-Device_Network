use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use epdn_node::{router, AppState, Enrollment, JournalStore, NodeConfig, NodeCore};
use epdn_protocol::{
    hash_domain, hex_lower, EpochChallenge, SecurityClass, SignedTransfer, TicketSubmission,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use tower::ServiceExt;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).expect("valid key")
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON response")
    };
    (status, body)
}

fn json_request(method: &str, uri: &str, body: Value, admin_token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = admin_token {
        builder = builder.header("x-epdn-admin-token", token);
    }
    builder.body(Body::from(body.to_string())).expect("request")
}

#[test]
fn wildcard_cors_configuration_is_rejected() {
    let result = AppState::with_cors_origins(
        NodeCore::new(NodeConfig::local_testnet()),
        key(68),
        key(69),
        "test-token",
        JournalStore::new("unused-api-test.journal"),
        vec!["*".to_owned()],
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn persistence_failure_does_not_mutate_live_state() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let unwritable_journal = std::env::temp_dir().join(format!(
        "epdn-api-directory-as-journal-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&unwritable_journal).expect("create directory at journal path");

    let config = NodeConfig::local_testnet();
    let firmware_id = *config
        .approved_firmware_ids
        .iter()
        .next()
        .expect("firmware");
    let authority = key(65);
    let validator = key(66);
    let device = key(67);
    let mut core = NodeCore::new(config);
    let certificate = core
        .issue_certificate(
            Enrollment {
                device_public_key: device
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                platform: "esp32".to_owned(),
                board_family: "esp32-generic".to_owned(),
                security_class: SecurityClass::L2NativeHardwareIdentity,
                provisioned_at_unix_seconds: 1_700_000_000,
                chip_revision: None,
                batch_id: None,
                manufacturer: None,
                allowed_firmware_ids: vec![firmware_id],
                expires_at_epoch: 100,
            },
            &authority,
        )
        .expect("certificate");
    let device_id = core
        .register_device(certificate, [68; 32], authority.verifying_key())
        .expect("register");
    let state = AppState::new(
        core,
        authority,
        validator,
        "test-admin-token",
        JournalStore::new(&unwritable_journal),
    );
    let core_handle = state.core();
    let app = router(state);

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            &format!("/api/v1/miners/{}/commands", hex_lower(&device_id)),
            json!({"command": "pause"}),
            Some("test-admin-token"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], "persistence_failed");
    assert!(!core_handle.read().await.is_paused(&device_id));

    std::fs::remove_dir(unwritable_journal).expect("remove directory");
}

#[tokio::test]
async fn admin_auth_gateway_challenge_duplicate_and_revocation_contract() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let journal_path = std::env::temp_dir().join(format!(
        "epdn-api-test-{}-{nonce}.journal",
        std::process::id()
    ));
    let config = NodeConfig::local_testnet();
    let firmware_id = *config
        .approved_firmware_ids
        .iter()
        .next()
        .expect("firmware");
    let authority = key(71);
    let validator = key(72);
    let device = key(73);
    let wallet = key(74);
    let wallet_address = hash_domain(
        b"EPDN_WALLET_ADDRESS_V1",
        &[wallet.verifying_key().to_encoded_point(true).as_bytes()],
    );
    let state = AppState::new(
        NodeCore::new(config),
        authority,
        validator,
        "test-admin-token",
        JournalStore::new(&journal_path),
    );
    let mut events = state.subscribe_events();
    let app = router(state);

    let (status, _) = send(
        &app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let allowed_cors = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("origin", "http://localhost:3000")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        allowed_cors
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("http://localhost:3000")
    );
    let disallowed_cors = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("origin", "https://attacker.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert!(disallowed_cors
        .headers()
        .get("access-control-allow-origin")
        .is_none());

    let public_key_hex = hex_lower(device.verifying_key().to_encoded_point(true).as_bytes());
    let enrollment = json!({
        "device_public_key_sec1_hex": public_key_hex,
        "platform": "esp32",
        "board_family": "esp32-generic",
        "security_class": "L2_NATIVE_HARDWARE_IDENTITY",
        "provisioned_at_unix_seconds": 1_700_000_000_u64,
        "chip_revision": "v3.1",
        "batch_id": "api-test",
        "manufacturer": null,
        "allowed_firmware_ids": [hex_lower(&firmware_id)],
        "expires_at_epoch": 1000,
    });
    let (status, body) = send(
        &app,
        json_request("POST", "/api/v1/admin/enroll", enrollment.clone(), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "admin_auth_required");

    let (status, enrollment_response) = send(
        &app,
        json_request(
            "POST",
            "/api/v1/admin/enroll",
            enrollment,
            Some("test-admin-token"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let certificate_hex = enrollment_response["certificate_hex"]
        .as_str()
        .expect("certificate")
        .to_owned();
    let device_id = enrollment_response["device_public_id"]
        .as_str()
        .expect("device ID")
        .to_owned();

    let (status, _) = send(
        &app,
        json_request(
            "POST",
            "/api/v1/admin/register",
            json!({
                "certificate_hex": certificate_hex,
                "reward_address": hex_lower(&wallet_address),
            }),
            Some("test-admin-token"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let challenge_uri = format!(
        "/api/v1/epochs/current/{}/{}",
        device_id,
        hex_lower(&firmware_id)
    );
    let (status, challenge_response) = send(
        &app,
        Request::builder()
            .uri(challenge_uri)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(challenge_response["encoding"], "EPDN_BINARY_V1_HEX");
    let challenge = EpochChallenge::decode(
        &hex::decode(
            challenge_response["challenge_hex"]
                .as_str()
                .expect("challenge"),
        )
        .expect("hex"),
    )
    .expect("canonical challenge");
    let submission = TicketSubmission::create(challenge, &device).expect("signed submission");
    let submission_bytes = submission.canonical_bytes().expect("submission bytes");

    let (status, _) = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/tickets")
            .header("content-type", "application/octet-stream")
            .body(Body::from(submission_bytes.clone()))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, duplicate) = send(
        &app,
        json_request(
            "POST",
            "/api/v1/tickets",
            json!({"submission_hex": hex_lower(&submission_bytes)}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(duplicate["error"], "duplicate_submission");

    let (status, _) = send(
        &app,
        json_request(
            "POST",
            "/api/v1/admin/epochs/finalize",
            Value::Null,
            Some("test-admin-token"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let transfer = SignedTransfer::create(
        "epdn-local-testnet-v1".to_owned(),
        [82; 32],
        20,
        1,
        0,
        &wallet,
    )
    .expect("transfer");
    let (status, transfer_response) = send(
        &app,
        json_request(
            "POST",
            "/api/v1/transactions",
            json!({
                "transaction_hex": hex_lower(
                    &transfer.canonical_bytes().expect("transfer bytes")
                )
            }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let transaction_hash = transfer_response["transaction_hash"]
        .as_str()
        .expect("transaction hash");
    let (status, _) = send(
        &app,
        Request::builder()
            .uri(format!("/api/v1/transactions/{transaction_hash}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, history) = send(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/address/{}/transactions",
                hex_lower(&wallet_address)
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(history
        .as_array()
        .is_some_and(|transactions| transactions.len() >= 2));

    let revoke_uri = format!("/api/v1/admin/miners/{device_id}/revoke");
    let (status, _) = send(
        &app,
        json_request(
            "POST",
            &revoke_uri,
            json!({"reason": "api test"}),
            Some("test-admin-token"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    while events.try_recv().is_ok() {}
    let (status, management_block) = send(
        &app,
        json_request(
            "POST",
            "/api/v1/admin/epochs/finalize",
            Value::Null,
            Some("test-admin-token"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(management_block["reward"]["amount"], 0);
    let event_kinds = std::iter::from_fn(|| events.try_recv().ok())
        .map(|event| event.kind())
        .collect::<Vec<_>>();
    assert!(event_kinds.contains(&"new_block"));
    assert!(event_kinds.contains(&"certificate_revoked"));
    assert!(event_kinds.contains(&"new_epoch"));
    assert!(!event_kinds.contains(&"reward"));

    let challenge_uri = format!(
        "/api/v1/epochs/current/{}/{}",
        device_id,
        hex_lower(&firmware_id)
    );
    let (status, revoked) = send(
        &app,
        Request::builder()
            .uri(challenge_uri)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(revoked["error"], "revoked_device");

    std::fs::remove_file(journal_path).expect("remove journal");
}
