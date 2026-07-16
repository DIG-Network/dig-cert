//! `dig-cert` — the single source of truth for DIG local-TLS material.
//!
//! Scaffold commit (issue #622). The name-constrained CA, leaf issuance, renewal manager, and
//! reloadable rustls loader land in the following commits (spec-first, see `SPEC.md`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Placeholder until the CA/leaf/renewal modules land. Kept trivial so the release-gate CI
/// (fmt/clippy/build/coverage) is green from the first commit.
#[doc(hidden)]
pub const fn crate_ready() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_is_ready() {
        assert!(crate_ready());
    }
}
