//! Which calls free a pointer, for the use-after-free walk. A built-in set
//! covers libc and common kernel/glib names; project-specific free
//! functions are a future extension (via the dangerous-functions list).

/// Functions that free their pointer argument.
const FREE: &[&str] = &[
    "free", "cfree", "kfree", "kvfree", "vfree", "g_free", "xfree",
];

/// Whether a call to `name` frees its argument.
pub fn is_free(name: &str) -> bool {
    FREE.contains(&bare(name))
}

/// The call name without a namespace, e.g. `std::free` → `free`.
fn bare(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name).trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frees_are_recognised_bare_or_namespaced() {
        assert!(is_free("free"));
        assert!(is_free("g_free"));
        assert!(is_free("std::free"));
        assert!(!is_free("malloc"));
        assert!(!is_free("process"));
    }
}
