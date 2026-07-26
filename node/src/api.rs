use std::{convert::Infallible, sync::Arc};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    },
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use epdn_protocol::{
    hash_domain, hex_lower, parse_hex_32, Block, DeviceCertificate, EpochContext, Hash32,
    LedgerError, RegisteredDevice, SecurityClass, SignedTransfer, TicketSubmission,
    TicketValidationError, TransactionError, ValidatedTicket, EPDN_PROTOCOL_VERSION,
    MAX_SUBMISSION_BYTES, MAX_TRANSACTION_BYTES,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    core::{Enrollment, NodeCore, NodeError, TransactionRecord},
    store::{JournalStore, StoreError},
};

const ADMIN_TOKEN_HEADER: &str = "x-epdn-admin-token";
const MAX_API_BODY_BYTES: usize = (MAX_SUBMISSION_BYTES * 2) + 1_024;

#[derive(Debug, Clone)]
pub struct AppState {
    core: Arc<RwLock<NodeCore>>,
    authority_key: Arc<SigningKey>,
    validator_key: Arc<SigningKey>,
    admin_token_hash: Hash32,
    store: JournalStore,
    events: broadcast::Sender<ApiEvent>,
    cors_origins: Arc<Vec<HeaderValue>>,
}

#[derive(Debug, Error)]
pub enum CorsConfigError {
    #[error("CORS origin allowlist must not be empty")]
    Empty,
    #[error("wildcard CORS origins are forbidden")]
    Wildcard,
    #[error("invalid CORS origin: {0}")]
    InvalidOrigin(String),
}

impl AppState {
    #[must_use]
    pub fn new(
        core: NodeCore,
        authority_key: SigningKey,
        validator_key: SigningKey,
        admin_token: &str,
        store: JournalStore,
    ) -> Self {
        Self::with_cors_origins(
            core,
            authority_key,
            validator_key,
            admin_token,
            store,
            vec![
                "http://localhost:3000".to_owned(),
                "http://127.0.0.1:3000".to_owned(),
            ],
        )
        .expect("static local CORS origins are valid")
    }

    pub fn with_cors_origins(
        core: NodeCore,
        authority_key: SigningKey,
        validator_key: SigningKey,
        admin_token: &str,
        store: JournalStore,
        origins: Vec<String>,
    ) -> Result<Self, CorsConfigError> {
        if origins.is_empty() {
            return Err(CorsConfigError::Empty);
        }
        let mut cors_origins = Vec::with_capacity(origins.len());
        for origin in origins {
            if origin.contains('*') {
                return Err(CorsConfigError::Wildcard);
            }
            let uri = origin
                .parse::<Uri>()
                .map_err(|_| CorsConfigError::InvalidOrigin(origin.clone()))?;
            if !matches!(uri.scheme_str(), Some("http" | "https"))
                || uri.authority().is_none()
                || uri.path() != "/"
                || uri.query().is_some()
            {
                return Err(CorsConfigError::InvalidOrigin(origin));
            }
            cors_origins.push(
                origin
                    .parse::<HeaderValue>()
                    .map_err(|_| CorsConfigError::InvalidOrigin(origin))?,
            );
        }
        let (events, _) = broadcast::channel(128);
        Ok(Self {
            core: Arc::new(RwLock::new(core)),
            authority_key: Arc::new(authority_key),
            validator_key: Arc::new(validator_key),
            admin_token_hash: hash_domain(b"EPDN_ADMIN_TOKEN_V1", &[admin_token.as_bytes()]),
            store,
            events,
            cors_origins: Arc::new(cors_origins),
        })
    }

    #[must_use]
    pub fn core(&self) -> Arc<RwLock<NodeCore>> {
        Arc::clone(&self.core)
    }

    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<ApiEvent> {
        self.events.subscribe()
    }

    async fn mutate_and_persist<T>(
        &self,
        mutation: impl FnOnce(&mut NodeCore) -> Result<T, NodeError>,
    ) -> Result<T, ApiError> {
        let mut current = self.core.write().await;
        let mut candidate = current.clone();
        let output = mutation(&mut candidate)?;
        self.store.save(&candidate, &self.validator_key)?;
        *current = candidate;
        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiEvent {
    kind: &'static str,
    payload: Value,
}

impl ApiEvent {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(code: &'static str, error: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: error.to_string(),
        }
    }

    fn not_found(resource: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: format!("{resource} was not found"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl From<NodeError> for ApiError {
    fn from(error: NodeError) -> Self {
        let (status, code) = match &error {
            NodeError::NoTickets => (StatusCode::CONFLICT, "epoch_has_no_tickets"),
            NodeError::Ticket(TicketValidationError::DuplicateDeviceEpoch) => {
                (StatusCode::CONFLICT, "duplicate_device_epoch")
            }
            NodeError::Ticket(TicketValidationError::DuplicateTicket) => {
                (StatusCode::CONFLICT, "duplicate_ticket")
            }
            NodeError::Ticket(TicketValidationError::DuplicateSubmission) => {
                (StatusCode::CONFLICT, "duplicate_submission")
            }
            NodeError::Ticket(TicketValidationError::RevokedDevice) => {
                (StatusCode::FORBIDDEN, "revoked_device")
            }
            NodeError::DeviceRevoked => (StatusCode::FORBIDDEN, "revoked_device"),
            NodeError::DevicePaused => (StatusCode::FORBIDDEN, "paused_device"),
            NodeError::Ticket(TicketValidationError::UnregisteredDevice) => {
                (StatusCode::FORBIDDEN, "unregistered_device")
            }
            NodeError::DeviceNotRegistered => (StatusCode::NOT_FOUND, "unregistered_device"),
            NodeError::Ticket(TicketValidationError::StaleEpoch { .. }) => {
                (StatusCode::CONFLICT, "stale_epoch_replay")
            }
            NodeError::Ticket(TicketValidationError::FutureEpoch { .. }) => {
                (StatusCode::CONFLICT, "future_epoch")
            }
            NodeError::Ticket(TicketValidationError::WrongChain { .. }) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "wrong_chain")
            }
            NodeError::TransactionReplay => (StatusCode::CONFLICT, "transaction_replay"),
            NodeError::Ledger(LedgerError::WrongNonce { .. }) => {
                (StatusCode::CONFLICT, "wrong_nonce")
            }
            NodeError::Ledger(LedgerError::InsufficientBalance) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "insufficient_balance")
            }
            NodeError::Ledger(LedgerError::Transaction(TransactionError::WrongChain {
                ..
            }))
            | NodeError::Transaction(TransactionError::WrongChain { .. }) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "wrong_network")
            }
            NodeError::Ledger(LedgerError::Transaction(TransactionError::InvalidSignature))
            | NodeError::Transaction(TransactionError::InvalidSignature) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "invalid_signature")
            }
            NodeError::Ticket(_) | NodeError::Registry(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "node_rejected")
            }
            _ => (StatusCode::BAD_REQUEST, "node_rejected"),
        };
        Self {
            status,
            code,
            message: error.to_string(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "persistence_failed",
            message: error.to_string(),
        }
    }
}

pub fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(state.cors_origins.as_ref().clone()))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            HeaderName::from_static(ADMIN_TOKEN_HEADER),
        ]);
    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/network/status", get(network_status))
        .route("/api/v1/epochs/current", get(current_epoch))
        .route("/api/v1/epochs/:epoch", get(epoch))
        .route(
            "/api/v1/epochs/current/:public_id/:firmware_id",
            get(current_device_challenge),
        )
        .route("/api/v1/events", get(events))
        .route("/api/v1/tickets", post(submit_ticket))
        .route("/api/v1/transactions", post(submit_transaction))
        .route("/api/v1/transactions/:hash", get(transaction))
        .route("/api/v1/blocks", get(blocks))
        .route("/api/v1/blocks/:height_or_hash", get(block))
        .route("/api/v1/address/:address", get(address))
        .route(
            "/api/v1/address/:address/transactions",
            get(address_transactions),
        )
        .route("/api/v1/miners", get(miners))
        .route("/api/v1/miners/:public_id", get(miner))
        .route("/api/v1/miners/:public_id/stats", get(miner_stats))
        .route("/api/v1/miners/:public_id/rewards", get(miner_rewards))
        .route("/api/v1/miners/:public_id/commands", post(miner_command))
        .route("/api/v1/admin/enroll", post(enroll))
        .route("/api/v1/admin/register", post(register))
        .route("/api/v1/admin/miners/:public_id/revoke", post(revoke))
        .route("/api/v1/admin/epochs/finalize", post(finalize_epoch))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .layer(cors)
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "protocol_version": EPDN_PROTOCOL_VERSION,
    }))
}

async fn network_status(State(state): State<AppState>) -> Json<Value> {
    let core = state.core.read().await;
    Json(json!({
        "protocol_version": EPDN_PROTOCOL_VERSION,
        "chain_id": core.config().chain_id,
        "network_mode": core.config().network_mode,
        "height": core.chain_height(),
        "current_epoch": core.current_epoch().epoch_number,
        "registered_devices": core.registry().len(),
        "accepted_tickets": core.ticket_pool().len(),
        "randomness_source": "insecure_single_node_development",
    }))
}

async fn current_epoch(State(state): State<AppState>) -> Json<EpochContext> {
    Json(state.core.read().await.current_epoch().clone())
}

async fn epoch(
    State(state): State<AppState>,
    Path(epoch_number): Path<u64>,
) -> Result<Json<Value>, ApiError> {
    let core = state.core.read().await;
    if epoch_number == core.current_epoch().epoch_number {
        return Ok(Json(json!({
            "status": "open",
            "context": core.current_epoch(),
        })));
    }
    let block = core
        .blocks()
        .iter()
        .find(|block| block.header.epoch_number == epoch_number)
        .ok_or(ApiError::not_found("epoch"))?;
    Ok(Json(json!({
        "status": "finalized",
        "block": block,
    })))
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    encoding: &'static str,
    challenge_hex: String,
    challenge_hash: String,
}

async fn current_device_challenge(
    State(state): State<AppState>,
    Path((public_id, firmware_id)): Path<(String, String)>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let device_id = parse_hex_32("public_id", &public_id)
        .map_err(|error| ApiError::bad_request("invalid_public_id", error))?;
    let firmware_id = parse_hex_32("firmware_id", &firmware_id)
        .map_err(|error| ApiError::bad_request("invalid_firmware_id", error))?;
    let challenge = state
        .core
        .read()
        .await
        .challenge_for(device_id, firmware_id)?;
    let encoded = challenge
        .canonical_bytes()
        .map_err(|error| ApiError::bad_request("challenge_encoding_failed", error))?;
    Ok(Json(ChallengeResponse {
        encoding: "EPDN_BINARY_V1_HEX",
        challenge_hex: hex_lower(&encoded),
        challenge_hash: hex_lower(&hash_domain(b"EPDN_CHALLENGE_ID_V1", &[&encoded])),
    }))
}

async fn events(
    State(state): State<AppState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = state.events.subscribe();
    let stream = async_stream::stream! {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event)
                        .unwrap_or_else(|_| "{\"kind\":\"serialization_error\"}".to_owned());
                    yield Ok(Event::default().event(event.kind).data(data));
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    let data = json!({"skipped": skipped}).to_string();
                    yield Ok(Event::default().event("lagged").data(data));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    device_public_key_sec1_hex: String,
    platform: String,
    board_family: String,
    security_class: SecurityClass,
    provisioned_at_unix_seconds: u64,
    chip_revision: Option<String>,
    batch_id: Option<String>,
    manufacturer: Option<String>,
    allowed_firmware_ids: Vec<String>,
    expires_at_epoch: u64,
}

#[derive(Debug, Serialize)]
struct EnrollResponse {
    certificate_hex: String,
    device_public_id: String,
}

async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    require_admin(&state, &headers)?;
    let public_key = parse_p256_public_key(&request.device_public_key_sec1_hex)?;
    let allowed_firmware_ids = request
        .allowed_firmware_ids
        .iter()
        .map(|value| {
            parse_hex_32("allowed_firmware_id", value)
                .map_err(|error| ApiError::bad_request("invalid_firmware_id", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certificate = state.core.read().await.issue_certificate(
        Enrollment {
            device_public_key: public_key,
            platform: request.platform,
            board_family: request.board_family,
            security_class: request.security_class,
            provisioned_at_unix_seconds: request.provisioned_at_unix_seconds,
            chip_revision: request.chip_revision,
            batch_id: request.batch_id,
            manufacturer: request.manufacturer,
            allowed_firmware_ids,
            expires_at_epoch: request.expires_at_epoch,
        },
        &state.authority_key,
    )?;
    let certificate_hex = hex_lower(
        &certificate
            .canonical_bytes()
            .map_err(|error| ApiError::bad_request("invalid_certificate", error))?,
    );
    Ok(Json(EnrollResponse {
        certificate_hex,
        device_public_id: hex_lower(&certificate.device_public_key_hash()),
    }))
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    certificate_hex: String,
    reward_address: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    device_public_id: String,
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    require_admin(&state, &headers)?;
    let certificate_bytes = hex::decode(&request.certificate_hex)
        .map_err(|error| ApiError::bad_request("invalid_certificate_hex", error))?;
    let certificate = DeviceCertificate::decode(&certificate_bytes)
        .map_err(|error| ApiError::bad_request("malformed_certificate", error))?;
    let reward_address = parse_hex_32("reward_address", &request.reward_address)
        .map_err(|error| ApiError::bad_request("invalid_reward_address", error))?;
    let device_id = state
        .mutate_and_persist(|core| {
            core.register_device(
                certificate,
                reward_address,
                state.authority_key.verifying_key(),
            )
        })
        .await?;
    emit(
        &state,
        ApiEvent {
            kind: "miner_registered",
            payload: json!({"public_id": hex_lower(&device_id)}),
        },
    );
    Ok(Json(RegisterResponse {
        device_public_id: hex_lower(&device_id),
    }))
}

#[derive(Debug, Serialize)]
struct TicketResponse {
    accepted: bool,
    submission_hash: String,
    score: String,
}

async fn submit_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TicketResponse>, ApiError> {
    let consensus_bytes = if headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"))
    {
        let envelope: TicketEnvelope = serde_json::from_slice(&body)
            .map_err(|error| ApiError::bad_request("malformed_submission_envelope", error))?;
        hex::decode(envelope.submission_hex)
            .map_err(|error| ApiError::bad_request("invalid_submission_hex", error))?
    } else {
        body.to_vec()
    };
    let submission = TicketSubmission::decode(&consensus_bytes)
        .map_err(|error| ApiError::bad_request("malformed_submission", error))?;
    let accepted = state
        .mutate_and_persist(|core| {
            core.submit_ticket(submission, state.authority_key.verifying_key())
        })
        .await?;
    emit_ticket(&state, &accepted);
    Ok(Json(TicketResponse {
        accepted: true,
        submission_hash: hex_lower(&accepted.submission_hash),
        score: hex_lower(&accepted.score),
    }))
}

#[derive(Debug, Deserialize)]
struct TicketEnvelope {
    /// JSON is transport only; this field contains canonical EPDN binary V1.
    submission_hex: String,
}

#[derive(Debug, Deserialize)]
struct TransactionEnvelope {
    /// JSON is transport only; this field contains canonical EPDN binary V1.
    transaction_hex: String,
}

#[derive(Debug, Serialize)]
struct TransactionResponse {
    accepted: bool,
    transaction_hash: String,
}

async fn submit_transaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TransactionResponse>, ApiError> {
    let consensus_bytes = if headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"))
    {
        let envelope: TransactionEnvelope = serde_json::from_slice(&body)
            .map_err(|error| ApiError::bad_request("malformed_transaction_envelope", error))?;
        hex::decode(envelope.transaction_hex)
            .map_err(|error| ApiError::bad_request("invalid_transaction_hex", error))?
    } else {
        body.to_vec()
    };
    if consensus_bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ApiError {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "transaction_oversized",
            message: format!("transaction exceeds {MAX_TRANSACTION_BYTES} bytes"),
        });
    }
    let transfer = SignedTransfer::decode(&consensus_bytes)
        .map_err(|error| ApiError::bad_request("malformed_transaction", error))?;
    let transaction_hash = state
        .mutate_and_persist(|core| core.submit_transfer(transfer))
        .await?;
    emit(
        &state,
        ApiEvent {
            kind: "transaction_accepted",
            payload: json!({"hash": hex_lower(&transaction_hash)}),
        },
    );
    Ok(Json(TransactionResponse {
        accepted: true,
        transaction_hash: hex_lower(&transaction_hash),
    }))
}

async fn transaction(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<TransactionRecord>, ApiError> {
    let hash = parse_hex_32("transaction_hash", &hash)
        .map_err(|error| ApiError::bad_request("invalid_transaction_hash", error))?;
    state
        .core
        .read()
        .await
        .transaction(&hash)
        .cloned()
        .map(Json)
        .ok_or(ApiError::not_found("transaction"))
}

async fn blocks(State(state): State<AppState>) -> Json<Vec<Block>> {
    Json(state.core.read().await.blocks().to_vec())
}

async fn block(
    State(state): State<AppState>,
    Path(height_or_hash): Path<String>,
) -> Result<Json<Block>, ApiError> {
    let core = state.core.read().await;
    let found = if let Ok(height) = height_or_hash.parse::<u64>() {
        core.block_by_height(height)
    } else {
        let hash = parse_hex_32("block_hash", &height_or_hash)
            .map_err(|error| ApiError::bad_request("invalid_block_id", error))?;
        core.block_by_hash(&hash)
    };
    found.cloned().map(Json).ok_or(ApiError::not_found("block"))
}

async fn address(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let address = parse_hex_32("address", &address)
        .map_err(|error| ApiError::bad_request("invalid_address", error))?;
    let core = state.core.read().await;
    Ok(Json(json!({
        "address": hex_lower(&address),
        "balance": core.balance(&address),
        "next_nonce": core.next_nonce(&address),
    })))
}

async fn address_transactions(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Vec<TransactionRecord>>, ApiError> {
    let address = parse_hex_32("address", &address)
        .map_err(|error| ApiError::bad_request("invalid_address", error))?;
    let core = state.core.read().await;
    Ok(Json(
        core.address_transactions(&address)
            .into_iter()
            .cloned()
            .collect(),
    ))
}

#[derive(Debug, Serialize)]
struct MinerView {
    public_id: String,
    platform: String,
    board_family: String,
    security_class: SecurityClass,
    reward_address: String,
    certificate_serial: String,
    certificate_expires_at_epoch: u64,
    revoked: bool,
    paused: bool,
    revocation_reason: Option<String>,
}

fn miner_view(device_id: &Hash32, device: &RegisteredDevice, paused: bool) -> MinerView {
    MinerView {
        public_id: hex_lower(device_id),
        platform: device.certificate.payload.platform.clone(),
        board_family: device.certificate.payload.board_family.clone(),
        security_class: device.certificate.payload.security_class,
        reward_address: hex_lower(&device.reward_address),
        certificate_serial: hex_lower(&device.certificate.payload.serial),
        certificate_expires_at_epoch: device.certificate.payload.expires_at_epoch,
        revoked: device.revocation.is_some(),
        paused,
        revocation_reason: device
            .revocation
            .as_ref()
            .map(|revocation| revocation.reason.clone()),
    }
}

async fn miners(State(state): State<AppState>) -> Json<Vec<MinerView>> {
    let core = state.core.read().await;
    Json(
        core.registry()
            .iter()
            .map(|(device_id, device)| miner_view(device_id, device, core.is_paused(device_id)))
            .collect(),
    )
}

async fn miner(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> Result<Json<MinerView>, ApiError> {
    let device_id = parse_hex_32("public_id", &public_id)
        .map_err(|error| ApiError::bad_request("invalid_public_id", error))?;
    let core = state.core.read().await;
    core.registry()
        .get(&device_id)
        .map(|device| Json(miner_view(&device_id, device, core.is_paused(&device_id))))
        .ok_or(ApiError::not_found("miner"))
}

async fn miner_stats(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let device_id = parse_hex_32("public_id", &public_id)
        .map_err(|error| ApiError::bad_request("invalid_public_id", error))?;
    let core = state.core.read().await;
    if core.registry().get(&device_id).is_none() {
        return Err(ApiError::not_found("miner"));
    }
    let blocks_won = core
        .blocks()
        .iter()
        .filter(|block| block.header.winning_device_public_key_hash == device_id)
        .count();
    let rewards = core.device_rewards(&device_id);
    let total_reward = rewards.iter().fold(0_u64, |total, record| {
        if let epdn_protocol::ChainTransaction::RewardDistribution(reward) = &record.transaction {
            total.saturating_add(reward.amount)
        } else {
            total
        }
    });
    let accepted_current_epoch = core
        .ticket_pool()
        .iter()
        .any(|ticket| ticket.device_id == device_id);
    Ok(Json(json!({
        "public_id": public_id,
        "blocks_won": blocks_won,
        "total_reward": total_reward,
        "accepted_current_epoch": accepted_current_epoch,
        "paused": core.is_paused(&device_id),
    })))
}

async fn miner_rewards(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> Result<Json<Vec<TransactionRecord>>, ApiError> {
    let device_id = parse_hex_32("public_id", &public_id)
        .map_err(|error| ApiError::bad_request("invalid_public_id", error))?;
    let core = state.core.read().await;
    if core.registry().get(&device_id).is_none() {
        return Err(ApiError::not_found("miner"));
    }
    Ok(Json(
        core.device_rewards(&device_id)
            .into_iter()
            .cloned()
            .collect(),
    ))
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MinerCommand {
    Pause,
    Resume,
    Revoke,
}

#[derive(Debug, Deserialize)]
struct MinerCommandRequest {
    command: MinerCommand,
    reason: Option<String>,
}

async fn miner_command(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<MinerCommandRequest>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers)?;
    let device_id = parse_hex_32("public_id", &public_id)
        .map_err(|error| ApiError::bad_request("invalid_public_id", error))?;
    let revocation_reason = if matches!(request.command, MinerCommand::Revoke) {
        request.reason.ok_or_else(|| {
            ApiError::bad_request("revocation_reason_required", "reason is required")
        })?
    } else {
        String::new()
    };
    let event_kind = state
        .mutate_and_persist(|core| match request.command {
            MinerCommand::Pause => {
                core.pause_device(&device_id)?;
                Ok("miner_paused")
            }
            MinerCommand::Resume => {
                core.resume_device(&device_id)?;
                Ok("miner_resumed")
            }
            MinerCommand::Revoke => {
                core.revoke_device(&device_id, revocation_reason)?;
                Ok("certificate_revocation_queued")
            }
        })
        .await?;
    emit(
        &state,
        ApiEvent {
            kind: event_kind,
            payload: json!({"public_id": public_id}),
        },
    );
    Ok(Json(json!({"accepted": true, "command": event_kind})))
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    reason: String,
}

async fn revoke(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RevokeRequest>,
) -> Result<StatusCode, ApiError> {
    require_admin(&state, &headers)?;
    let device_id = parse_hex_32("public_id", &public_id)
        .map_err(|error| ApiError::bad_request("invalid_public_id", error))?;
    let transaction_hash = state
        .mutate_and_persist(|core| core.revoke_device(&device_id, request.reason))
        .await?;
    emit(
        &state,
        ApiEvent {
            kind: "certificate_revocation_queued",
            payload: json!({
                "public_id": public_id,
                "transaction_hash": hex_lower(&transaction_hash),
            }),
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn finalize_epoch(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Block>, ApiError> {
    require_admin(&state, &headers)?;
    let block = state
        .mutate_and_persist(|core| core.finalize_epoch(&state.validator_key))
        .await?;
    emit(
        &state,
        ApiEvent {
            kind: "new_block",
            payload: json!({
                "height": block.header.height,
                "hash": hex_lower(&block.block_hash),
            }),
        },
    );
    for transaction in &block.transactions {
        if let epdn_protocol::ChainTransaction::DeviceRevocation(revocation) = transaction {
            emit(
                &state,
                ApiEvent {
                    kind: "certificate_revoked",
                    payload: json!({
                        "public_id": hex_lower(&revocation.device_id),
                        "block_height": block.header.height,
                    }),
                },
            );
        }
    }
    if !block.is_revocation_only() {
        emit(
            &state,
            ApiEvent {
                kind: "reward",
                payload: json!({
                    "address": hex_lower(&block.reward.address),
                    "amount": block.reward.amount,
                    "winning_device_id": hex_lower(&block.reward.winning_device_id),
                    "block_height": block.header.height,
                }),
            },
        );
    }
    emit(
        &state,
        ApiEvent {
            kind: "new_epoch",
            payload: json!({
                "epoch": block.header.epoch_number.saturating_add(1),
                "previous_block_hash": hex_lower(&block.block_hash),
            }),
        },
    );
    Ok(Json(block))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let core = state.core.read().await;
    let body = format!(
        concat!(
            "# TYPE epdn_chain_height gauge\n",
            "epdn_chain_height {}\n",
            "# TYPE epdn_current_epoch gauge\n",
            "epdn_current_epoch {}\n",
            "# TYPE epdn_registered_devices gauge\n",
            "epdn_registered_devices {}\n",
            "# TYPE epdn_accepted_tickets gauge\n",
            "epdn_accepted_tickets {}\n",
        ),
        core.chain_height(),
        core.current_epoch().epoch_number,
        core.registry().len(),
        core.ticket_pool().len(),
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let provided = headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided_hash = hash_domain(b"EPDN_ADMIN_TOKEN_V1", &[provided.as_bytes()]);
    if bool::from(provided_hash.ct_eq(&state.admin_token_hash)) {
        Ok(())
    } else {
        Err(ApiError {
            status: StatusCode::UNAUTHORIZED,
            code: "admin_auth_required",
            message: format!("valid {ADMIN_TOKEN_HEADER} header required"),
        })
    }
}

fn parse_p256_public_key(value: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(value)
        .map_err(|error| ApiError::bad_request("invalid_public_key_hex", error))?;
    if bytes.len() != 33 {
        return Err(ApiError::bad_request(
            "invalid_public_key",
            "P-256 public key must be 33-byte compressed SEC1",
        ));
    }
    VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|error| ApiError::bad_request("invalid_public_key", error))?;
    Ok(bytes)
}

fn emit(state: &AppState, event: ApiEvent) {
    let _ignored_no_subscribers = state.events.send(event);
}

fn emit_ticket(state: &AppState, ticket: &ValidatedTicket) {
    emit(
        state,
        ApiEvent {
            kind: "ticket_accepted",
            payload: json!({
                "device_public_id": hex_lower(&ticket.device_id),
                "submission_hash": hex_lower(&ticket.submission_hash),
                "score": hex_lower(&ticket.score),
            }),
        },
    );
}
