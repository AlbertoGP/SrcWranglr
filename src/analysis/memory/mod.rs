//! Intraprocedural use-after-free and double-free detection. A walk of each
//! function body tracks every pointer's lifetime invariant (allocated →
//! freed → used) — the "invariant matrix" for one function — and reports a
//! use or a second free of an already-freed pointer (CWE-416 / CWE-415).
//! Data races and the visual matrix view build on this engine later.

mod names;
mod state;
mod walk;

pub use walk::{findings, lifetimes, Lifetimes, PointKind};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
