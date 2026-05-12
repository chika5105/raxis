//! Greeting rendering — the conceptual operation that is mirrored
//! across the multi-language tree. A rename here must propagate to
//! `ts-pkg/src/greet.ts` and `py-pkg/src/sample_py/greet.py`.

/// Render a greeting for the supplied name. An empty name is
/// rendered as the literal "friend" so callers don't have to
/// special-case unauthenticated paths.
#[must_use]
pub fn render_greeting(name: &str) -> String {
    let trimmed = name.trim();
    let who = if trimmed.is_empty() { "friend" } else { trimmed };
    format!("Hello, {who}!")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_greeting_trims_whitespace() {
        assert_eq!(render_greeting("  Ada  "), "Hello, Ada!");
    }

    #[test]
    fn render_greeting_handles_unicode() {
        assert_eq!(render_greeting("Ada Lovelace"), "Hello, Ada Lovelace!");
    }
}
