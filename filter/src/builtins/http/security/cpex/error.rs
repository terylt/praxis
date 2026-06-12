// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Maps CPEX `PluginViolation`s to praxis `Rejection`s.

use bytes::Bytes;
use cpex_core::error::PluginViolation;

use crate::Rejection;

// -----------------------------------------------------------------------------
// auth_rejection (transport-level deny — HTTP 401)
// -----------------------------------------------------------------------------

/// JSON-RPC error code for gateway-side denials. Lives in the
/// implementation-defined `-32000` to `-32099` range carved out by the
/// JSON-RPC 2.0 spec for server errors. One code covers all of
/// `apl.policy`, `cedar.*`, `pii.*`, `delegation.*`, etc. — the
/// specific violation goes in `data.violation` so MCP clients can
/// switch on a single code while still seeing the underlying reason.
const MCP_GATEWAY_DENIED_CODE: i64 = -32001;

/// Build an HTTP 401 rejection for transport-level authentication
/// failures (missing / invalid / wrong-audience JWT). Per the MCP
/// Authorization spec, identity failures are reported as HTTP 401
/// with a `WWW-Authenticate` header — clients are expected to react
/// to the status + header, not parse the body. The body is included
/// only as a short human-readable diagnostic.
///
/// The violation's `code` is also surfaced via an `X-Cpex-Violation`
/// response header so middleware (audit, logging, downstream proxies)
/// can classify denials without parsing the body.
///
/// TODO: once the gateway exposes its own `OAuth` Protected Resource
/// Metadata document, the `WWW-Authenticate` header should point at
/// it per RFC 9728 (`Bearer resource_metadata="..."`). Today we send
/// the minimum-compliant header.
pub(super) fn auth_rejection(violation: Option<&PluginViolation>) -> Rejection {
    let (code, reason) = match violation {
        Some(v) => (v.code.clone(), v.reason.clone()),
        None => (
            "auth.unknown".to_owned(),
            "authentication required".to_owned(),
        ),
    };
    let body = format!("{code}: {reason}");
    Rejection::status(401)
        .with_header("WWW-Authenticate", "Bearer")
        .with_header("X-Cpex-Violation", code)
        .with_body(Bytes::from(body.into_bytes()))
}

// -----------------------------------------------------------------------------
// mcp_error_rejection (application-level deny — HTTP 200 + JSON-RPC error)
// -----------------------------------------------------------------------------

/// Build an MCP-compliant JSON-RPC error envelope for application-level
/// denials (policy / PDP / PII / delegation failure / internal errors)
/// that the gateway catches BEFORE the upstream tool runs.
///
/// Per the MCP Tools spec ("Error Handling"), these are *protocol*
/// errors reported via JSON-RPC error envelopes inside an HTTP 200
/// response — not HTTP 4xx — so MCP clients can correlate the failure
/// to the original request `id` and surface the violation through
/// their normal error UI.
///
/// Shape (matches the JSON-RPC 2.0 schema referenced by MCP):
///
/// ```json
/// {
///   "jsonrpc": "2.0",
///   "id": <request id, preserving original type>,
///   "error": {
///     "code": -32001,
///     "message": "<human reason from the violation>",
///     "data": { "violation": "<violation code>" }
///   }
/// }
/// ```
pub(super) fn mcp_error_rejection(
    violation: Option<&PluginViolation>,
    request_id: &serde_json::Value,
) -> Rejection {
    let (violation_code, reason) = match violation {
        Some(v) => (v.code.clone(), v.reason.clone()),
        None => (
            "gateway.unknown".to_owned(),
            "denied by gateway".to_owned(),
        ),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": MCP_GATEWAY_DENIED_CODE,
            "message": reason,
            "data": { "violation": violation_code },
        }
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    Rejection::status(200)
        .with_header("Content-Type", "application/json")
        .with_header("X-Cpex-Violation", violation_code)
        .with_body(Bytes::from(bytes))
}
