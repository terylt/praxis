// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! MCP method → CMF (Common Message Format) entity-coords mapping.
//!
//! Praxis's built-in `mcp` filter parses MCP JSON-RPC bodies and
//! stashes `mcp.method` / `mcp.name` in `ctx.filter_metadata`. This
//! module consumes that metadata and resolves the matching CMF
//! hook name + entity-type discriminator so APL routes annotated to
//! `tools/<x>`, `prompts/<x>`, or `resources/<x>` get evaluated
//! against the right pre/post hook.

use cpex_core::cmf::constants::{
    ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL, HOOK_CMF_PROMPT_POST_INVOKE,
    HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH,
    HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
};

// -----------------------------------------------------------------------------
// Pre-phase
// -----------------------------------------------------------------------------

/// Map an MCP method to `(entity_type, pre_hook_name)` for the
/// request-phase CMF dispatch. Returns `None` for methods that don't
/// carry an entity (`tools/list`, `initialize`, `prompts/list`, etc.) —
/// in those cases identity still runs but CMF dispatch is skipped.
pub(super) fn entity_for_mcp_method(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "tools/call" => Some((ENTITY_TOOL, HOOK_CMF_TOOL_PRE_INVOKE)),
        "prompts/get" => Some((ENTITY_PROMPT, HOOK_CMF_PROMPT_PRE_INVOKE)),
        "resources/read" => Some((ENTITY_RESOURCE, HOOK_CMF_RESOURCE_PRE_FETCH)),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Post-phase
// -----------------------------------------------------------------------------

/// Post-phase mirror of [`entity_for_mcp_method`]. Maps the same
/// methods to the CMF `*_post_invoke` / `*_post_fetch` hook names so
/// `on_response_body` can dispatch APL `result:` pipelines.
///
/// The method is read from `ctx.filter_metadata` — praxis's `mcp`
/// filter stashes it during the request phase and it persists across
/// the request/response lifecycle in the same context object.
pub(super) fn entity_for_mcp_method_post(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "tools/call" => Some((ENTITY_TOOL, HOOK_CMF_TOOL_POST_INVOKE)),
        "prompts/get" => Some((ENTITY_PROMPT, HOOK_CMF_PROMPT_POST_INVOKE)),
        "resources/read" => Some((ENTITY_RESOURCE, HOOK_CMF_RESOURCE_POST_FETCH)),
        _ => None,
    }
}
