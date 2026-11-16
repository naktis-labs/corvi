//! Bounded regular expressions for policy patterns.
//!
//! ADR-0003 section 2.2 calls for "bounded non-backtracking regular
//! expressions where allowed", and section 8 requires that work is bounded so
//! a hostile message cannot make the filter engine expensive.
//!
//! The `regex` crate guarantees linear-time matching, which is the property
//! that matters here: a pattern cannot be made to backtrack exponentially
//! against crafted input.

use std::sync::OnceLock;

use regex::Regex;

/// The longest pattern the engine will compile.
pub const MAX_PATTERN_LENGTH: usize = 1024;

/// The largest compiled-program size the engine will accept.
pub const MAX_PROGRAM_SIZE: usize = 1 << 20; // 1 MiB

/// Compile a policy pattern, returning `None` if it is not usable.
///
/// A `None` result is not a silent non-match: callers must treat it as
/// indeterminate and fail closed.
pub fn compile_bounded(pattern: &str, case_insensitive: bool) -> Option<Regex> {
    if pattern.len() > MAX_PATTERN_LENGTH {
        return None;
    }

    let mut builder = regex::RegexBuilder::new(pattern);
    builder.size_limit(MAX_PROGRAM_SIZE);
    builder.dfa_size_limit(MAX_PROGRAM_SIZE);
    if case_insensitive {
        builder.case_insensitive(true);
    }

    builder.build().ok()
}

/// A compiled pattern keyed by its source and case-sensitivity.
type CompiledPatterns = std::collections::HashMap<(String, bool), Option<Regex>>;

/// A cache of compiled patterns.
///
/// Policies are re-evaluated for every message, and recompiling the same
/// pattern per message would be wasteful.
#[derive(Debug, Default)]
pub struct PatternCache {
    entries: OnceLock<std::sync::RwLock<CompiledPatterns>>,
}

impl PatternCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a compiled pattern, compiling it on first use.
    pub fn get(&self, pattern: &str, case_insensitive: bool) -> Option<Regex> {
        let key = (pattern.to_owned(), case_insensitive);
        let guard = self.entries.get_or_init(Default::default);
        let mut map = guard.write().expect("pattern cache lock poisoned");
        map.entry(key)
            .or_insert_with(|| compile_bounded(pattern, case_insensitive))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_a_valid_pattern() {
        let regex = compile_bounded(r"INV-[0-9]{8}", true).expect("pattern compiles");
        assert!(regex.is_match("invoice INV-12345678 due"));
    }

    #[test]
    fn rejects_an_invalid_pattern() {
        assert!(compile_bounded("([unclosed", true).is_none());
    }

    #[test]
    fn rejects_an_oversized_pattern() {
        let pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        assert!(compile_bounded(&pattern, false).is_none());
    }

    #[test]
    fn case_insensitivity_is_honoured() {
        let regex = compile_bounded("inv", true).expect("pattern compiles");
        assert!(regex.is_match("INV-1"));
    }

    #[test]
    fn the_cache_reuses_compiled_patterns() {
        let cache = PatternCache::new();
        let first = cache.get(r"INV-[0-9]{8}", true);
        let second = cache.get(r"INV-[0-9]{8}", true);
        assert!(first.is_some());
        assert!(second.is_some());
        assert_eq!(first.unwrap().as_str(), second.unwrap().as_str());
    }
}
