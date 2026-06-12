// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `CpexFilter` — embeds the CPEX runtime in-process to resolve and
//! validate identity, evaluate APL routes, optionally mint delegated
//! credentials, scan for PII, emit audit records, and optionally
//! rewrite request/response bodies.

// The orchestration functions in this module (`on_request_body`,
// `on_response_body`, `new`) coordinate identity resolution, CMF
// dispatch, delegated-token attachment, and body re-serialization in
// linear steps. Splitting them to satisfy `too_many_lines` /
// `cognitive_complexity` would obscure the request/response phase
// flow without reducing real complexity.
#![allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "orchestration functions; splitting obscures phase flow"
)]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cpex_core::{
    cmf::{CmfHook, Message, MessagePayload, Role},
    error::PluginError,
    hooks::Extensions,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource},
    manager::PluginManager,
};

use super::{
    cmf::{entity_for_mcp_method, entity_for_mcp_method_post},
    config::{BodyAccessMode, CpexFilterConfig},
    error::{auth_rejection, mcp_error_rejection},
    factories::{register_apl_visitor, register_builtin_factories},
    json_rpc::{
        build_content_for_method, build_response_content_for_method, json_rpc_id, json_rpc_id_value,
        reserialize_json_rpc_body, reserialize_json_rpc_response_body,
    },
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// CpexFilter
// -----------------------------------------------------------------------------

/// Filter that runs the CPEX identity + APL pipeline against each
/// request.
///
/// A single request can carry multiple identity sources — user JWT in
/// `Authorization`, agent JWT in `X-Agent-Token`, workload JWT in
/// `X-Workload-Token`, etc. Each registered identity plugin reads its
/// own configured header and contributes to a typed `Extensions`
/// context.
///
/// On the body phase, the filter consumes praxis's `mcp` filter
/// metadata to dispatch the matching CMF hook chain. APL routes
/// (declared in the CPEX YAML) gate the tool/prompt/resource call by
/// role, attribute, or Cedar PDP decision. `delegate(...)` steps mint
/// audience-scoped tokens (RFC 8693) that the allow path attaches as
/// upstream headers.
///
/// `body_access: read_write` enables the JSON-RPC re-serialization
/// round-trip so APL field mutators (`redact()`, `assign()`) rewrite
/// the upstream request body and the downstream response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: cpex
/// config:
///   config_path: /etc/praxis/cpex.yaml
///   body_access: read_write   # optional; default read_only
/// ```
pub struct CpexFilter {
    /// CPEX plugin manager — owns the loaded plugin instances and
    /// dispatches hook chains. Shared via `Arc` so the async
    /// `HttpFilter` methods can clone references cheaply.
    mgr: Arc<PluginManager>,
    /// Filter-level configuration parsed from the YAML block. Held so
    /// `request_body_access` / `request_body_mode` / their response
    /// counterparts can branch on `body_access` per request.
    cfg: CpexFilterConfig,
}

impl CpexFilter {
    /// Construct a filter from a parsed config. Loads the CPEX YAML
    /// referenced by `cfg.config_path`, registers bundled plugin
    /// factories, wires the APL visitor, and initializes the manager.
    /// Errors abort filter chain construction at server startup —
    /// failing fast is what we want for misconfigured policy.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the referenced YAML cannot be read,
    /// the policy document fails to parse, or plugin initialization
    /// fails (e.g., a JWKS endpoint is unreachable).
    pub fn new(cfg: CpexFilterConfig) -> Result<Self, FilterError> {
        let yaml = std::fs::read_to_string(&cfg.config_path).map_err(|e| -> FilterError {
            format!("cpex: failed to read config_path {}: {e}", cfg.config_path).into()
        })?;

        let mgr = Arc::new(PluginManager::default());
        register_builtin_factories(&mgr);
        register_apl_visitor(&mgr);

        mgr.load_config_yaml(&yaml)
            .map_err(|e: Box<PluginError>| -> FilterError {
                format!("cpex: load_config_yaml failed: {e}").into()
            })?;

        // `initialize()` is async. The praxis filter-factory signature
        // is sync, so we drive init to completion here. We spawn a
        // dedicated OS thread to build a single-threaded runtime and
        // call `block_on` there — running `block_on` on the current
        // thread would panic if any caller (notably `#[tokio::test]`)
        // already has a runtime attached. Production startup has no
        // caller runtime; tests do; the thread hop is correct in both.
        let mgr_for_init = Arc::clone(&mgr);
        let init: Result<(), String> = std::thread::spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("cpex: failed to build init runtime: {e}"))?;
            rt.block_on(mgr_for_init.initialize()).map_err(
                |e: Box<PluginError>| format!("cpex: PluginManager::initialize failed: {e}"),
            )
        })
        .join()
        .map_err(|panic| {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<no panic message>".to_owned());
            format!("cpex: PluginManager::initialize panicked in init thread: {msg}")
        })?;
        init.map_err(|s: String| -> FilterError { s.into() })?;

        Ok(Self { mgr, cfg })
    }

    /// Praxis-side factory hook, wired via `register_http` in
    /// `filter/src/registry.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config block fails to parse
    /// as a [`CpexFilterConfig`] or filter construction fails.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CpexFilterConfig = parse_filter_config("cpex", config)?;
        let filter = Self::new(cfg)?;
        Ok(Box::new(filter))
    }

    /// Snapshot the request's HTTP headers into a case-normalized
    /// map. Each registered identity plugin reads its own configured
    /// header from this map.
    ///
    /// Keys are normalized to ASCII lowercase. HTTP header names are
    /// case-insensitive (RFC 7230 §3.2) but the `HashMap` lookup is
    /// case-sensitive; plugins lowercase their configured header
    /// before lookup to match.
    fn snapshot_headers(ctx: &HttpFilterContext<'_>) -> std::collections::HashMap<String, String> {
        ctx.request
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect()
    }

    /// Build a fresh `IdentityPayload` from request headers. `raw_token`
    /// is left empty: each registered identity plugin reads its own
    /// configured header from `headers` instead.
    fn identity_payload(ctx: &HttpFilterContext<'_>) -> IdentityPayload {
        IdentityPayload::new(String::new(), TokenSource::Bearer)
            .with_headers(Self::snapshot_headers(ctx))
    }

    /// Build the `Extensions` to feed CMF dispatch. Re-resolves
    /// identity (cheap — the JWT verifier hits its in-process key
    /// cache), applies the resolved subject / roles / claims /
    /// raw-credentials, and stamps `MetaExtension.entity_type` /
    /// `entity_name` so route resolution in cpex-core picks the right
    /// route annotation.
    async fn build_cmf_extensions(
        &self,
        ctx: &HttpFilterContext<'_>,
        entity_type: &str,
        entity_name: &str,
    ) -> Result<Extensions, Rejection> {
        let (id_result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                Self::identity_payload(ctx),
                Extensions::default(),
                None,
            )
            .await;
        if !id_result.continue_processing {
            return Err(auth_rejection(id_result.violation.as_ref()));
        }

        let identity = IdentityPayload::from_pipeline_result(&id_result).ok_or_else(|| {
            Rejection::status(500).with_body(Bytes::from_static(
                b"cpex: identity result missing modified payload",
            ))
        })?;
        let mut ext = identity.apply_to_extensions(Extensions::default());

        let mut meta = ext
            .meta
            .as_ref()
            .map(|arc| (**arc).clone())
            .unwrap_or_default();
        meta.entity_type = Some(entity_type.to_owned());
        meta.entity_name = Some(entity_name.to_owned());
        ext.meta = Some(Arc::new(meta));

        Ok(ext)
    }
}

#[async_trait]
impl HttpFilter for CpexFilter {
    fn name(&self) -> &'static str {
        "cpex"
    }

    fn request_body_access(&self) -> BodyAccess {
        // `ReadOnly` is the minimum that gets us into `on_request_body`
        // (we need the body phase to fire so we can dispatch CMF after
        // the `mcp` filter populates its metadata). Operators opt into
        // `ReadWrite` via `body_access: read_write` when they want APL
        // field mutators (`redact()` / `assign()` on `args.<field>`) to
        // rewrite the upstream body. Chain-level scoping keeps non-CPEX
        // traffic out of this filter so the buffering cost is bounded
        // either way.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly,
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite,
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        // In `ReadWrite` mode we MUST buffer the whole body before the
        // filter runs — otherwise praxis would stream chunks upstream
        // as they arrive, and a body rewrite at end-of-stream would
        // race against an already-finished upstream write.
        // `StreamBuffer` accumulates chunks, calls our filter exactly
        // once at EOS with the full body, and forwards whatever we put
        // back into `body`. `ReadOnly` inherits the default `Stream`.
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyMode::Stream,
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer { max_bytes: None },
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyAccess::ReadOnly,
            BodyAccessMode::ReadWrite => BodyAccess::ReadWrite,
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        match self.cfg.body_access {
            BodyAccessMode::ReadOnly => BodyMode::Stream,
            BodyAccessMode::ReadWrite => BodyMode::StreamBuffer { max_bytes: None },
        }
    }

    async fn on_request(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        // Early identity gate. Saves the per-request body-buffer cost
        // on un-auth'd traffic — if there's no valid token, we never
        // reach `on_request_body` and the body never gets buffered.
        let (result, _bg) = self
            .mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                Self::identity_payload(ctx),
                Extensions::default(),
                None,
            )
            .await;

        if !result.continue_processing {
            tracing::debug!(target: "cpex.filter", "identity deny (on_request)");
            return Ok(FilterAction::Reject(auth_rejection(result.violation.as_ref())));
        }

        tracing::trace!(target: "cpex.filter", "identity allow (on_request)");
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        // CMF dispatch only fires once the full body has been seen
        // (so praxis's `mcp` filter has finished parsing and writing
        // its metadata). For streaming chunks we just pass.
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        // Pull MCP-derived entity coords from durable filter_metadata.
        // If the operator hasn't wired `mcp` upstream of us, or the
        // request isn't an entity-bearing MCP method, we have nothing
        // to dispatch and just allow.
        let Some(method) = ctx.get_metadata("mcp.method").map(str::to_owned) else {
            tracing::trace!(target: "cpex.filter", "no mcp.method in metadata; no CMF dispatch");
            return Ok(FilterAction::BodyDone);
        };
        let Some((entity_type, hook_name)) = entity_for_mcp_method(&method) else {
            tracing::trace!(
                target: "cpex.filter",
                mcp_method = %method,
                "MCP method has no entity binding; no CMF dispatch",
            );
            return Ok(FilterAction::BodyDone);
        };
        let Some(entity_name) = ctx.get_metadata("mcp.name").map(str::to_owned) else {
            tracing::debug!(
                target: "cpex.filter",
                mcp_method = %method,
                "MCP method missing mcp.name metadata; skipping CMF dispatch",
            );
            return Ok(FilterAction::BodyDone);
        };

        // Build `Extensions` with re-resolved identity + entity coords.
        let extensions = match self.build_cmf_extensions(ctx, entity_type, &entity_name).await {
            Ok(ext) => ext,
            Err(rej) => return Ok(FilterAction::Reject(rej)),
        };

        // Parse the JSON-RPC body to build the typed CMF content part.
        // praxis's `mcp` filter already parsed once but only stashed
        // method/name in `filter_metadata`, not the `params.arguments`
        // that APL `args.*` predicates need. We re-parse here. The
        // body is already in memory; the duplicate parse is
        // microseconds.
        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let id = json_rpc_id(&body_bytes);
        let content = build_content_for_method(&method, &entity_name, &id, &body_bytes);

        // Dispatch the CMF hook. The route annotation (installed by
        // the APL visitor at config-load time) drives policy
        // evaluation; if no APL route matches, the hook is a no-op.
        let payload = MessagePayload {
            message: Message::with_content(Role::User, content),
        };
        let (cmf_result, _bg) = self
            .mgr
            .invoke_named::<CmfHook>(hook_name, payload, extensions, None)
            .await;

        if !cmf_result.continue_processing {
            let request_id = json_rpc_id_value(&body_bytes);
            tracing::debug!(
                target: "cpex.filter",
                hook = %hook_name,
                entity = %entity_name,
                "CMF deny",
            );
            return Ok(FilterAction::Reject(mcp_error_rejection(
                cmf_result.violation.as_ref(),
                &request_id,
            )));
        }

        // Allow path. If APL `delegate(...)` steps minted any outbound
        // tokens, the delegators wrote them into
        // `modified_extensions.raw_credentials.delegated_tokens`.
        // Attach each one to the upstream request as the configured
        // header.
        let attached = attach_delegated_tokens(ctx, cmf_result.modified_extensions.as_ref());
        if attached > 0 {
            tracing::debug!(
                target: "cpex.filter",
                count = attached,
                "attached delegated tokens to upstream request",
            );
        }

        // If body_access is ReadWrite AND APL mutated the payload
        // (a `redact()` / `assign()` step fired), re-serialize the
        // mutated `MessagePayload` back into the JSON-RPC body so the
        // upstream service receives the rewritten args.
        if matches!(self.cfg.body_access, BodyAccessMode::ReadWrite)
            && let Some(mp) = cmf_result.modified_payload.as_ref()
            && let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>()
        {
            let original = body.as_ref().cloned().unwrap_or_else(Bytes::new);
            if let Some(new_bytes) =
                reserialize_json_rpc_body(&original, &method, &updated.message)
            {
                // praxis exposes header mutations only from the request
                // phase, and Transfer-Encoding is stripped as hop-by-hop
                // on the upstream hop. The inbound `Content-Length`
                // governs upstream body length — if the rewrite shrinks
                // the body, pad with trailing ASCII spaces (which every
                // JSON parser ignores) so the wire length still matches
                // Content-Length. Rewrites that grow the body are not
                // supported in this mode; the cmf executor's mutators
                // (`redact()`) either shrink or are length-neutral
                // today.
                let final_bytes = match new_bytes.len().cmp(&original.len()) {
                    std::cmp::Ordering::Less => {
                        let mut padded = Vec::with_capacity(original.len());
                        padded.extend_from_slice(&new_bytes);
                        padded.resize(original.len(), b' ');
                        Bytes::from(padded)
                    }
                    std::cmp::Ordering::Equal => new_bytes,
                    std::cmp::Ordering::Greater => {
                        tracing::warn!(
                            target: "cpex.filter",
                            method = %method,
                            new_len = new_bytes.len(),
                            original_len = original.len(),
                            "rewritten body larger than original; sending without pad — upstream may see truncation",
                        );
                        new_bytes
                    }
                };
                tracing::debug!(
                    target: "cpex.filter",
                    method = %method,
                    new_len = final_bytes.len(),
                    original_len = original.len(),
                    "rewriting upstream body from mutated MessagePayload",
                );
                *body = Some(final_bytes);
            }
        }

        tracing::trace!(
            target: "cpex.filter",
            hook = %hook_name,
            entity = %entity_name,
            "CMF allow",
        );
        Ok(FilterAction::BodyDone)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        // No point doing anything if the operator hasn't opted into
        // response rewriting.
        if !matches!(self.cfg.body_access, BodyAccessMode::ReadWrite) {
            return Ok(FilterAction::Continue);
        }

        // praxis's `mcp` filter stashes method/name during the request
        // phase and praxis preserves `filter_metadata` across phases,
        // so we can route the post-phase hook without re-parsing the
        // body.
        let Some(method) = ctx.get_metadata("mcp.method").map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };
        let Some((entity_type, hook_name)) = entity_for_mcp_method_post(&method) else {
            return Ok(FilterAction::Continue);
        };
        let Some(entity_name) = ctx.get_metadata("mcp.name").map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };

        let body_bytes = body.as_ref().cloned().unwrap_or_else(Bytes::new);
        let id_str = json_rpc_id(&body_bytes);

        // praxis's `on_response_body` is sync (the Pingora response_body
        // callback can't be awaited). We're on a tokio worker so
        // `block_in_place` lets us drive the async CMF dispatch without
        // stalling other tasks.
        let extensions = match tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.build_cmf_extensions(ctx, entity_type, &entity_name).await
            })
        }) {
            Ok(e) => e,
            Err(_rej) => {
                tracing::debug!(
                    target: "cpex.filter",
                    "post-phase identity rebuild failed; skipping response rewrite",
                );
                return Ok(FilterAction::Continue);
            }
        };

        let content =
            build_response_content_for_method(&method, &entity_name, &id_str, &body_bytes);
        if content.is_empty() {
            return Ok(FilterAction::Continue);
        }
        let payload = MessagePayload {
            message: Message::with_content(Role::Assistant, content),
        };
        let mgr = Arc::clone(&self.mgr);
        let cmf_result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (r, _bg) = mgr
                    .invoke_named::<CmfHook>(hook_name, payload, extensions, None)
                    .await;
                r
            })
        });

        // A post-phase deny is unusual but plausible (the upstream
        // returned something the operator wants suppressed). For v0
        // we log it; replacing the response stream with a synthetic
        // error envelope here would require rewriting the upstream's
        // headers too, which praxis doesn't expose from
        // `on_response_body`.
        if !cmf_result.continue_processing {
            tracing::warn!(
                target: "cpex.filter",
                method = %method,
                entity = %entity_name,
                violation = ?cmf_result.violation,
                "post-phase deny surfaced as a log; response body still flows downstream",
            );
            return Ok(FilterAction::Continue);
        }

        if let Some(mp) = cmf_result.modified_payload.as_ref()
            && let Some(updated) = mp.as_any().downcast_ref::<MessagePayload>()
        {
            let original = body.as_ref().cloned().unwrap_or_else(Bytes::new);
            if let Some(new_bytes) =
                reserialize_json_rpc_response_body(&original, &method, &updated.message)
            {
                let final_bytes = match new_bytes.len().cmp(&original.len()) {
                    std::cmp::Ordering::Less => {
                        let mut padded = Vec::with_capacity(original.len());
                        padded.extend_from_slice(&new_bytes);
                        padded.resize(original.len(), b' ');
                        Bytes::from(padded)
                    }
                    std::cmp::Ordering::Equal => new_bytes,
                    std::cmp::Ordering::Greater => {
                        tracing::warn!(
                            target: "cpex.filter",
                            method = %method,
                            new_len = new_bytes.len(),
                            original_len = original.len(),
                            "rewritten response body larger than original; sending without pad — client may see truncation",
                        );
                        new_bytes
                    }
                };
                tracing::debug!(
                    target: "cpex.filter",
                    method = %method,
                    new_len = final_bytes.len(),
                    original_len = original.len(),
                    "rewriting downstream response body from mutated MessagePayload",
                );
                *body = Some(final_bytes);
            }
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// attach_delegated_tokens
// -----------------------------------------------------------------------------

/// Walk the minted delegated tokens on the resolved `Extensions` and
/// push them as upstream request headers. Returns the count attached
/// (0 when no delegation ran or no extensions were returned). Each
/// token's `outbound_header` field decides where it goes; the value
/// is `Bearer <token>` (RFC 6750 wire format — what every audience
/// expects). Uses `request_headers_to_set` rather than
/// `extra_request_headers` because authorization tokens are
/// overwrites, not appends.
fn attach_delegated_tokens(
    ctx: &mut HttpFilterContext<'_>,
    extensions: Option<&Extensions>,
) -> usize {
    let Some(ext) = extensions else { return 0; };
    let Some(raw) = ext.raw_credentials.as_ref() else {
        return 0;
    };

    let mut attached_outbound: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut count = 0;
    for tok in raw.delegated_tokens.values() {
        let Ok(name) = http::header::HeaderName::try_from(tok.outbound_header.as_str()) else {
            tracing::warn!(
                target: "cpex.filter",
                header = %tok.outbound_header,
                "delegated token outbound_header is not a valid HTTP header name; skipping",
            );
            continue;
        };
        let Ok(value) = http::header::HeaderValue::try_from(format!("Bearer {}", tok.token.as_str()))
        else {
            tracing::warn!(
                target: "cpex.filter",
                audience = %tok.audience,
                "minted token bytes are not a valid HTTP header value; skipping",
            );
            continue;
        };
        attached_outbound.insert(tok.outbound_header.to_ascii_lowercase());
        ctx.request_headers_to_set.push((name, value));
        count += 1;
    }

    // Strip the inbound credential headers — but only when we
    // actually attached delegated tokens, and only headers that are
    // NOT also being set by an outbound (collision case —
    // `request_headers_to_set` overwrites, no remove needed).
    if count > 0 {
        for inbound in raw.inbound_tokens.values() {
            let normalized = inbound.source_header.to_ascii_lowercase();
            if attached_outbound.contains(&normalized) {
                continue;
            }
            if let Ok(n) = http::header::HeaderName::try_from(inbound.source_header.as_str()) {
                ctx.request_headers_to_remove.push(n);
            } else {
                tracing::warn!(
                    target: "cpex.filter",
                    header = %inbound.source_header,
                    "inbound source_header is not a valid HTTP header name; cannot strip",
                );
            }
        }
    }

    count
}
