//! The caps that stop a hostile `.torrent` from exhausting memory or stack
//! (spec T1). Everything the parser refuses to do for size reasons is a
//! number in this one struct, so the whole policy is readable at a glance.

/// Hard limits applied while parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input we will look at at all. Spec: 10 MiB for a `.torrent`.
    pub max_input: usize,
    /// Deepest nesting of lists and dictionaries. Spec: 64.
    ///
    /// The parser is recursive, so this is also the stack-overflow guard.
    pub max_depth: u32,
    /// Most entries in ONE list or dictionary.
    pub max_items: usize,
    /// Most values in the WHOLE document.
    ///
    /// Without this, 10 MiB of `le` pairs becomes millions of `Value`
    /// structs: a large memory amplification from a small file.
    pub max_total_items: usize,
    /// Most digits in an integer. Spec: 20. (An `i64` needs at most 19.)
    pub max_int_digits: usize,
    /// Longest byte string. Also always capped by the remaining input.
    pub max_string: usize,
}

impl Limits {
    /// The profile for parsing a `.torrent` file.
    pub const TORRENT: Limits = Limits {
        max_input: 10 * 1024 * 1024,
        max_depth: 64,
        max_items: 100_000,
        max_total_items: 1_000_000,
        max_int_digits: 20,
        max_string: 10 * 1024 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::TORRENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_the_spec() {
        let l = Limits::default();
        assert_eq!(l.max_input, 10 * 1024 * 1024);
        assert_eq!(l.max_depth, 64);
        assert_eq!(l.max_int_digits, 20);
        assert_eq!(l.max_items, 100_000);
        assert_eq!(l.max_total_items, 1_000_000);
        assert_eq!(l.max_string, 10 * 1024 * 1024);
    }

    #[test]
    fn limits_can_be_tightened_for_tests_and_other_callers() {
        let tight = Limits {
            max_depth: 4,
            ..Limits::TORRENT
        };
        assert_eq!(tight.max_depth, 4);
        assert_eq!(tight.max_input, Limits::TORRENT.max_input);
    }
}
