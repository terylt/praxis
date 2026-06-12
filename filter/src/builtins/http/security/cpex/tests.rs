// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the CPEX security filter.
//!
//! Uses HMAC (HS256) JWTs throughout for setup simplicity — the
//! identity validation pipeline is symmetric across signing
//! algorithms, and HS256 lets us skip RSA keypair generation. Real
//! deployments use RS256 with JWKS endpoints; the YAML schema
//! supports both via the `decoding_key.kind` discriminant.

use http::{HeaderValue, Method};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tempfile::TempDir;

use super::config::CpexFilterConfig;
use super::filter::CpexFilter;
use crate::FilterAction;
use crate::filter::HttpFilter;
use crate::test_utils::{make_filter_context, make_request};

// =====================================================================
// Fixtures
// =====================================================================

const TEST_SECRET: &str = "praxis-cpex-test-secret-not-for-production-use";
const TEST_ISSUER: &str = "https://idp.test.local";
const TEST_AUDIENCE: &str = "test-api";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should not be before unix epoch")
        .as_secs()
}

/// Mint an HS256 JWT signed with [`TEST_SECRET`].
fn mint_jwt(claims: &serde_json::Value) -> String {
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(TEST_SECRET.as_bytes());
    encode(&header, claims, &key).expect("sign JWT")
}

/// Standard token claims: test issuer + audience, fresh `exp`.
fn standard_claims(subject: &str) -> serde_json::Value {
    json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": subject,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    })
}

/// Claims for a workload / agent token. Includes `azp` (authorized
/// party) so the `client`-role claim mapper can populate the
/// caller-workload identity slot.
fn agent_claims(client_id: &str) -> serde_json::Value {
    json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": client_id,
        "azp": client_id,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    })
}

/// Write a single-plugin CPEX YAML referencing the HS256 test secret.
fn write_single_plugin_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
          leeway_seconds: 60
      claim_mapper: standard
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Write a CPEX YAML with two identity plugins, each reading its own
/// header. Demonstrates the multi-source agentic identity story PR1
/// targets — one request can carry user + agent JWTs simultaneously,
/// both validated, both contributing to a typed `Extensions` context.
#[allow(
    clippy::too_many_lines,
    reason = "test fixture — the YAML literal is the bulk; splitting helpers would obscure the shape under test"
)]
fn write_multi_source_config() -> (TempDir, String) {
    let dir = TempDir::new().expect("create tempdir");
    let cfg_path = dir.path().join("cpex.yaml");

    let yaml = format!(
        r#"plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 10
    on_error: fail
    config:
      header: Authorization
      role: user
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
      claim_mapper: standard
  - name: jwt-agent
    kind: identity/jwt
    hooks:
      - identity.resolve
    mode: sequential
    priority: 20
    on_error: fail
    config:
      header: X-Agent-Token
      role: client
      trusted_issuers:
        - issuer: "{TEST_ISSUER}"
          audiences: ["{TEST_AUDIENCE}"]
          algorithms: ["HS256"]
          decoding_key:
            kind: secret
            secret: "{TEST_SECRET}"
      claim_mapper: standard
"#
    );

    std::fs::write(&cfg_path, yaml).expect("write cpex.yaml");
    let path_str = cfg_path.to_str().expect("utf8 path").to_owned();
    (dir, path_str)
}

/// Build a `CpexFilter` from a YAML config path.
fn build_filter(config_path: String) -> CpexFilter {
    let cfg = CpexFilterConfig {
        config_path,
        body_access: super::config::BodyAccessMode::ReadOnly,
    };
    CpexFilter::new(cfg).expect("filter should construct")
}

// =====================================================================
// Config parsing
// =====================================================================

#[test]
fn config_parses_minimal_yaml() {
    let yaml = "config_path: /etc/praxis/cpex.yaml";
    let cfg: CpexFilterConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.config_path, "/etc/praxis/cpex.yaml");
}

#[test]
fn config_requires_config_path() {
    let yaml = "{}";
    let res: Result<CpexFilterConfig, _> = serde_yaml::from_str(yaml);
    assert!(res.is_err(), "config_path is mandatory");
}

// =====================================================================
// Identity-resolution scenarios
// =====================================================================

/// A YAML config carrying a single identity plugin should construct
/// without error. Pins the schema we ship — any drift in the
/// identity/jwt plugin's config shape will surface here.
#[tokio::test(flavor = "multi_thread")]
async fn filter_constructs_from_valid_yaml() {
    let (_dir, path) = write_single_plugin_config();
    let _filter = build_filter(path);
}

/// A request with no `Authorization` header has no token for the JWT
/// plugin to validate; the identity hook chain denies and the filter
/// emits HTTP 401.
#[tokio::test(flavor = "multi_thread")]
async fn request_without_auth_header_rejects_401() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.expect("filter ran");

    match action {
        FilterAction::Reject(rej) => assert_eq!(rej.status, 401),
        other => panic!("expected Reject(401); got {other:?}"),
    }
}

/// A valid HS256 JWT in the configured header passes the identity
/// chain and the filter emits Continue.
#[tokio::test(flavor = "multi_thread")]
async fn valid_hs256_jwt_continues() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let token = mint_jwt(&standard_claims("alice"));
    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "expected Continue; got {action:?}"
    );
}

/// A JWT whose signature byte has been flipped fails verification and
/// the filter emits HTTP 401.
#[tokio::test(flavor = "multi_thread")]
async fn tampered_jwt_signature_rejects_401() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    // Flip the final character of the signature segment.
    let mut token = mint_jwt(&standard_claims("alice"));
    let last = token.pop().unwrap_or('A');
    token.push(if last == 'A' { 'B' } else { 'A' });

    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("header value"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    assert!(
        matches!(&action, FilterAction::Reject(rej) if rej.status == 401),
        "expected Reject(401); got {action:?}"
    );
}

/// Auth rejections must carry the MCP-spec-required
/// `WWW-Authenticate: Bearer` header so MCP clients know to retry
/// with credentials, plus our `X-Cpex-Violation` diagnostic header.
#[tokio::test(flavor = "multi_thread")]
async fn auth_rejection_carries_diagnostic_headers() {
    let (_dir, path) = write_single_plugin_config();
    let filter = build_filter(path);

    let req = make_request(Method::POST, "/");
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    let FilterAction::Reject(rej) = action else {
        panic!("expected Reject; got {action:?}");
    };

    let www_auth = rej
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("WWW-Authenticate"));
    assert!(www_auth.is_some(), "WWW-Authenticate header is required");

    let violation = rej
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("X-Cpex-Violation"));
    assert!(violation.is_some(), "X-Cpex-Violation header is expected");
}

/// The PR1 multi-source story: one request carries a user JWT in
/// `Authorization` and an agent JWT in `X-Agent-Token`. Both plugins
/// validate their respective headers and the request passes.
#[tokio::test(flavor = "multi_thread")]
async fn multi_source_both_identities_continue() {
    let (_dir, path) = write_multi_source_config();
    let filter = build_filter(path);

    let user_token = mint_jwt(&standard_claims("alice"));
    let agent_token = mint_jwt(&agent_claims("agent-007"));

    let mut req = make_request(Method::POST, "/");
    req.headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {user_token}")).expect("header"),
    );
    req.headers.insert(
        "X-Agent-Token",
        HeaderValue::from_str(&format!("Bearer {agent_token}")).expect("header"),
    );
    let mut ctx = make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.expect("filter ran");
    assert!(
        matches!(action, FilterAction::Continue),
        "expected Continue with both identities; got {action:?}"
    );
}
