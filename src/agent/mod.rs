//! SrcWranglr as the agent itself: it runs the model loop in-app, using
//! its own tools directly (no opencode, no MCP), so an assessment is one
//! click. The model does the static work — recon, triage, harness
//! drafting, rule drafting — through the same tools the MCP server
//! exposes; building and running harnesses or scanners stays outside, as
//! it must (SrcWranglr never runs the audited code).

// Built up over several steps; the HTTP client and pane that consume
// these land next. Remove once they do.
#![allow(dead_code)]

pub mod llm;
pub mod session;
