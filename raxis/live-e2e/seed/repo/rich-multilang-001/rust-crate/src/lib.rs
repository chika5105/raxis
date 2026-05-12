//! `rust-crate` — fixture crate for the rich-multilang-001 seed.
//!
//! The crate exposes a single conceptual operation ("greet a named
//! user") so the cross-file refactor scenario can rename it across
//! the multi-language tree.

pub mod greeting;

pub use greeting::render_greeting;

/// Convenience entry point used by `scripts/check.sh` smoke runs.
#[must_use]
pub fn default_greeting() -> String {
    render_greeting("World")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_greeting_matches_world() {
        assert_eq!(default_greeting(), "Hello, World!");
    }

    #[test]
    fn render_greeting_handles_empty_name() {
        assert_eq!(render_greeting(""), "Hello, friend!");
    }
}
