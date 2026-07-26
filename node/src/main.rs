use std::{env, error::Error, io, net::SocketAddr, path::PathBuf};

use epdn_node::{router, AppState, JournalStore, NodeConfig, NodeCore};
use epdn_protocol::{hash_domain, hex_lower};
use p256::ecdsa::SigningKey;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_BIND: &str = "127.0.0.1:8745";
const DEFAULT_ADMIN_TOKEN: &str = "epdn-local-admin-change-me";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("epdn_node=info,tower_http=info")),
        )
        .json()
        .init();

    let bind_address: SocketAddr = env::var("EPDN_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()
        .map_err(|error| invalid_input(format!("invalid EPDN_BIND_ADDR: {error}")))?;
    let configured_admin_token = env::var("EPDN_ADMIN_TOKEN").ok();
    let configured_cors_origins = env::var("EPDN_CORS_ORIGINS").ok();
    validate_bind_security(
        bind_address,
        configured_admin_token.as_deref(),
        configured_cors_origins.as_deref(),
        env::var_os("EPDN_DEV_CA_PRIVATE_KEY_HEX").is_some(),
        env::var_os("EPDN_VALIDATOR_PRIVATE_KEY_HEX").is_some(),
    )?;
    let cors_origins = configured_cors_origins
        .as_deref()
        .map(|origins| {
            origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                "http://localhost:3000".to_owned(),
                "http://127.0.0.1:3000".to_owned(),
            ]
        });
    let admin_token = configured_admin_token
        .as_deref()
        .unwrap_or(DEFAULT_ADMIN_TOKEN);
    if configured_admin_token.is_none() {
        warn!(
            "using the documented local-development admin token; set EPDN_ADMIN_TOKEN before shared use"
        );
    }

    let config = NodeConfig::local_testnet();
    let authority_key = load_or_derive_key(
        "EPDN_DEV_CA_PRIVATE_KEY_HEX",
        b"EPDN_INSECURE_LOCAL_CA_KEY_V1",
        &config.chain_id,
    )?;
    let validator_key = load_or_derive_key(
        "EPDN_VALIDATOR_PRIVATE_KEY_HEX",
        b"EPDN_INSECURE_LOCAL_VALIDATOR_KEY_V1",
        &config.chain_id,
    )?;
    if authority_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        == validator_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
    {
        return Err(invalid_input(
            "EPDN_DEV_CA_PRIVATE_KEY_HEX and EPDN_VALIDATOR_PRIVATE_KEY_HEX must be distinct",
        )
        .into());
    }
    let state_path = env::var_os("EPDN_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".epdn").join("node-state.journal"));
    let store = JournalStore::new(state_path);
    let core = match store.load(validator_key.verifying_key())? {
        Some(core) => {
            core.validate_loaded(
                &config,
                authority_key.verifying_key(),
                validator_key.verifying_key(),
            )?;
            core
        }
        None => {
            let core = NodeCore::new(config);
            store.save(&core, &validator_key)?;
            core
        }
    };

    let authority_public = authority_key.verifying_key().to_encoded_point(true);
    let validator_public = validator_key.verifying_key().to_encoded_point(true);
    info!(
        bind_address = %bind_address,
        state_path = %store.path().display(),
        authority_id = %hex_lower(&hash_domain(
            b"EPDN_AUTHORITY_ID_V1",
            &[authority_public.as_bytes()],
        )),
        validator_id = %hex_lower(&hash_domain(
            b"EPDN_VALIDATOR_ID_V1",
            &[validator_public.as_bytes()],
        )),
        "starting EPDN local testnet node"
    );

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    let app = router(AppState::with_cors_origins(
        core,
        authority_key,
        validator_key,
        admin_token,
        store,
        cors_origins,
    )?);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn load_or_derive_key(
    environment_variable: &str,
    development_domain: &[u8],
    chain_id: &str,
) -> Result<SigningKey, io::Error> {
    if let Some(value) = env::var_os(environment_variable) {
        let value = value
            .into_string()
            .map_err(|_| invalid_input(format!("{environment_variable} is not valid UTF-8")))?;
        let bytes = hex::decode(&value)
            .map_err(|error| invalid_input(format!("{environment_variable}: {error}")))?;
        if bytes.len() != 32 {
            return Err(invalid_input(format!(
                "{environment_variable} must contain exactly 32 bytes"
            )));
        }
        return SigningKey::from_slice(&bytes).map_err(|error| {
            invalid_input(format!(
                "{environment_variable} is not a valid P-256 key: {error}"
            ))
        });
    }

    warn!(
        variable = environment_variable,
        "using a deterministic, insecure local-development signing key"
    );
    for counter in 0_u32..=u32::MAX {
        let candidate = hash_domain(
            development_domain,
            &[chain_id.as_bytes(), &counter.to_be_bytes()],
        );
        if let Ok(key) = SigningKey::from_slice(&candidate) {
            return Ok(key);
        }
    }
    Err(invalid_input("could not derive a valid P-256 signing key"))
}

fn validate_bind_security(
    bind_address: SocketAddr,
    admin_token: Option<&str>,
    cors_origins: Option<&str>,
    has_authority_key: bool,
    has_validator_key: bool,
) -> Result<(), io::Error> {
    if admin_token.is_some_and(str::is_empty) {
        return Err(invalid_input("EPDN_ADMIN_TOKEN must not be empty"));
    }
    if bind_address.ip().is_loopback() {
        return Ok(());
    }
    let token = admin_token.ok_or_else(|| {
        invalid_input("EPDN_ADMIN_TOKEN is required when binding outside loopback")
    })?;
    if token.len() < 32 {
        return Err(invalid_input(
            "EPDN_ADMIN_TOKEN must contain at least 32 bytes when binding outside loopback",
        ));
    }
    if cors_origins.is_none() {
        return Err(invalid_input(
            "EPDN_CORS_ORIGINS is required when binding outside loopback",
        ));
    }
    if !has_authority_key {
        return Err(invalid_input(
            "EPDN_DEV_CA_PRIVATE_KEY_HEX is required when binding outside loopback",
        ));
    }
    if !has_validator_key {
        return Err(invalid_input(
            "EPDN_VALIDATOR_PRIVATE_KEY_HEX is required when binding outside loopback",
        ));
    }
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to install Ctrl+C shutdown handler");
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(value: &str) -> SocketAddr {
        value.parse().expect("valid test socket address")
    }

    #[test]
    fn loopback_allows_documented_development_defaults() {
        validate_bind_security(address("127.0.0.1:8745"), None, None, false, false)
            .expect("loopback development configuration");
    }

    #[test]
    fn shared_bind_requires_strong_complete_configuration() {
        let shared = address("0.0.0.0:8745");
        assert!(validate_bind_security(shared, None, None, false, false).is_err());
        assert!(validate_bind_security(
            shared,
            Some("short"),
            Some("https://app.test"),
            true,
            true
        )
        .is_err());
        assert!(validate_bind_security(
            shared,
            Some("0123456789abcdef0123456789abcdef"),
            None,
            true,
            true,
        )
        .is_err());
        assert!(validate_bind_security(
            shared,
            Some("0123456789abcdef0123456789abcdef"),
            Some("https://app.test"),
            false,
            true,
        )
        .is_err());
        validate_bind_security(
            shared,
            Some("0123456789abcdef0123456789abcdef"),
            Some("https://app.test"),
            true,
            true,
        )
        .expect("complete shared-bind configuration");
    }

    #[test]
    fn explicitly_empty_token_is_always_rejected() {
        assert!(
            validate_bind_security(address("127.0.0.1:8745"), Some(""), None, false, false,)
                .is_err()
        );
    }
}
