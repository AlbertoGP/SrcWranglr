//! The agent's tools. Each is a plain function from the workspace and its
//! arguments to the answer's text (or why there is none), so the server
//! stays a thin layer and the running app can serve the same tools.

pub mod flow;
pub mod graph;
pub mod lists;
pub mod notes;
pub mod overview;
pub mod records;
pub mod research;
pub mod symbols;
pub mod verdicts;
