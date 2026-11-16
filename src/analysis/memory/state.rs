//! The pointer-lifetime invariant the walk tracks per variable — the
//! "invariant matrix" for a single function. Only freed variables are
//! tracked: a use of one is a use-after-free, a second free a double-free.

/// A freed variable's state at a point in the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freed {
    /// Freed on every path that reaches here (1-based line of the free).
    Always(u32),
    /// Freed on some path only — after a branch where another path did not
    /// free it. A use of this is a lower-confidence lead.
    Maybe(u32),
}

impl Freed {
    /// The line the (first) free is on.
    pub fn line(self) -> u32 {
        match self {
            Freed::Always(line) | Freed::Maybe(line) => line,
        }
    }

    /// Whether the variable is freed on every path (not just some).
    pub fn is_certain(self) -> bool {
        matches!(self, Freed::Always(_))
    }

    /// This state carried past a branch where the other path left the
    /// variable live: certainty drops to "maybe".
    pub fn demote(self) -> Freed {
        Freed::Maybe(self.line())
    }
}

/// Merge the same variable's state from two branches into its state after
/// the join: freed on both paths stays certain, freed on one becomes maybe.
pub fn merge(a: Option<Freed>, b: Option<Freed>) -> Option<Freed> {
    match (a, b) {
        (Some(Freed::Always(line)), Some(Freed::Always(_))) => Some(Freed::Always(line)),
        (Some(freed), _) | (_, Some(freed)) => Some(freed.demote()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_branch_states_keeps_certainty_only_when_both_free() {
        // Freed on both paths: still certain.
        assert_eq!(
            merge(Some(Freed::Always(3)), Some(Freed::Always(9))),
            Some(Freed::Always(3))
        );
        // Freed on one path only: maybe.
        assert_eq!(merge(Some(Freed::Always(3)), None), Some(Freed::Maybe(3)));
        assert_eq!(merge(None, Some(Freed::Always(5))), Some(Freed::Maybe(5)));
        // Live on both: live.
        assert_eq!(merge(None, None), None);
    }
}
