# Phase 1 — Bounded, Hardened Bencode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `crates/bencode`: a zero-copy, allocation-bounded, panic-free bencode parser and canonical encoder that records the byte span of every value, so a hostile `.torrent` file cannot crash, hang or exhaust the client (threat T1).

**Architecture:** A recursive-descent parser over a `&[u8]` cursor. Every byte string is *borrowed* from the input rather than copied, so a 10 MiB torrent costs 10 MiB plus a small tree of `Value` nodes. Every container carries a hard cap (depth, items per container, items in total) and every length is checked against the bytes that actually remain *before* anything is allocated. Each `Value` remembers its `Span` in the original buffer, which is how Phase 2 will SHA-1 the raw `info` dictionary for the `info_hash`. The encoder is separate and always emits canonical (key-sorted) output.

**Tech Stack:** Rust stable 1.98 (edition 2024), no runtime dependencies. `proptest` as a dev-dependency for property tests. `cargo-fuzz` + `libfuzzer-sys` for fuzzing, run on Linux in CI only.

**Spec:** `docs/superpowers/specs/2026-09-21-secure-bittorrent-client-design.md` (rev. 2) — §4.1 workspace, §5 crate policy, §5 T1, §7 testing and phase gate, §8 Phase 1.

## Global Constraints

- **Zero runtime dependencies** in `crates/bencode`. Dev-dependencies are allowed and must pass `cargo deny check`.
- `unsafe_code = "forbid"` (inherited from the workspace). No `unwrap`, `expect`, `panic!`, `todo!`, `unreachable!` or `a[i]` indexing in non-test code — clippy denies all of them. Use `.get()`, `.ok_or()`, `.unwrap_or()` and `match`.
- **Every length is checked against a cap AND against the remaining input before allocating.** (spec §5 crate policy)
- T1 caps, exact values from the spec: input ≤ 10 MiB, depth ≤ 64, integer digits ≤ 20. Item caps are ours: ≤ 100 000 per container, ≤ 1 000 000 in the whole document.
- Strict integer grammar: no `-0`, no leading zeros, no empty integer. Same rule for byte-string lengths.
- Duplicate dict keys are **rejected**. Unsorted dict keys are **tolerated** and recorded in a `canonical` flag.
- Trailing bytes after the top-level value are **rejected**.
- Errors carry a `kind` and a byte `at` offset and **never** any of the input bytes (spec T8).
- Test names for security controls start with their threat ID: `t1_...`, `t8_...`. Verified with `cargo test t1_`.
- Edition 2024, resolver 3, `publish = false`, toolchain pinned by `rust-toolchain.toml`, `Cargo.lock` committed.
- The user is a beginner. After **each** task: a plain-language explanation in chat **and** a section appended to `docs/learn/NOTES.md`.
- Commit messages are subject + body only. **No `Co-Authored-By` trailer** (user instruction, 2026-09-23).
- `git push` after each task's commit (user policy, 2026-09-23).
- `export PATH="/c/Users/krish/.cargo/bin:$PATH"` is needed in the Bash tool. `D:` is exFAT, so cargo prints a harmless "hard linking files in the incremental compilation cache failed" warning — ignore it.

## File map

| File | Responsibility |
|---|---|
| `crates/bencode/Cargo.toml` | Package + `proptest` dev-dependency (Task 7) |
| `crates/bencode/src/lib.rs` | Module wiring, public re-exports, `parse`, `parse_with`, `Parsed` |
| `crates/bencode/src/error.rs` | `ErrorKind`, `Error` (kind + byte offset), `Display`, `Result` alias |
| `crates/bencode/src/limits.rs` | `Limits` — every T1 cap in one place |
| `crates/bencode/src/value.rs` | `Span`, `Value`, `Kind`, `Dict`, accessors, redacting `Debug` |
| `crates/bencode/src/parser.rs` | The bounded cursor: integers, byte strings, lists, dicts |
| `crates/bencode/src/encode.rs` | Canonical (key-sorted) encoder |
| `crates/bencode/tests/parse.rs` | Public-API integration tests + a realistic sample torrent |
| `crates/bencode/tests/prop.rs` | `proptest` property tests |
| `fuzz/Cargo.toml` | Detached fuzz workspace (`cargo-fuzz`) |
| `fuzz/fuzz_targets/parse.rs` | libFuzzer target: parse → encode → re-parse |
| `fuzz/corpus/parse/*` | Committed seed corpus |
| `.github/workflows/ci.yml` | New `fuzz` job (Linux, nightly, 60 s) |
| `docs/FUZZING.md` | How to run it, corpus policy, crash triage (spec §7) |
| `docs/THREAT_MODEL.md` | T1 moves `planned` → `tested` |
| `docs/learn/NOTES.md` | Plain-language notes, one section per task |

## Reference: the bencode grammar

Four types, all ASCII-delimited, no whitespace anywhere:

| Type | Wire form | Example | Meaning |
|---|---|---|---|
| Integer | `i<digits>e` | `i42e`, `i-7e` | signed, we store `i64` |
| Byte string | `<len>:<bytes>` | `4:spam` | **bytes**, not text — may be invalid UTF-8 |
| List | `l<values>e` | `li1e4:spame` | ordered |
| Dictionary | `d<key><value>…e` | `d3:cow3:mooe` | keys are byte strings, sorted ascending |

---

### Task 1: Errors and limits

**Files:**
- Create: `crates/bencode/src/error.rs`
- Create: `crates/bencode/src/limits.rs`
- Modify: `crates/bencode/src/lib.rs` (replace the one-line stub)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub enum ErrorKind` — 18 unit variants, `Debug + Clone + Copy + PartialEq + Eq`, `#[non_exhaustive]`
  - `ErrorKind::message(self) -> &'static str`
  - `pub struct Error { pub kind: ErrorKind, pub at: usize }`, `Debug + Clone + Copy + PartialEq + Eq`, `Display`, `std::error::Error`
  - `pub(crate) fn Error::new(kind: ErrorKind, at: usize) -> Error`
  - `pub type Result<T> = std::result::Result<T, Error>`
  - `pub struct Limits { max_input, max_depth: u32, max_items, max_total_items, max_int_digits, max_string }` (all fields other than `max_depth` are `usize`), `Debug + Clone + Copy + PartialEq + Eq + Default`
  - `Limits::TORRENT` associated const

- [ ] **Step 1: Write the tests and the types**

Create `crates/bencode/src/error.rs`:

```rust
//! Errors for the bencode parser (spec T1).
//!
//! An error says WHAT went wrong and WHERE (a byte offset). It never carries
//! any of the input bytes, so an error can be logged safely even though the
//! input came from a stranger (spec T8).

use std::fmt;

/// What went wrong. One variant per rule the parser enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The whole input is larger than `Limits::max_input`.
    InputTooLarge,
    /// The input ended in the middle of a value.
    UnexpectedEnd,
    /// A byte appeared where no value can start.
    UnexpectedByte,
    /// The top-level value parsed, but bytes followed it.
    TrailingBytes,
    /// `ie` — an integer with no digits.
    IntEmpty,
    /// `i03e` — leading zeros are not allowed.
    IntLeadingZero,
    /// `i-0e` — negative zero is not allowed.
    IntNegativeZero,
    /// More digits than `Limits::max_int_digits`.
    IntTooManyDigits,
    /// The digits are a number, but it does not fit in an `i64`.
    IntOverflow,
    /// `01:a` — a string length with a leading zero.
    LengthLeadingZero,
    /// The declared string length does not fit in a `usize`.
    LengthOverflow,
    /// The declared string length runs past the end of the input.
    LengthBeyondInput,
    /// The declared string length is larger than `Limits::max_string`.
    StringTooLong,
    /// Nesting deeper than `Limits::max_depth`.
    DepthExceeded,
    /// One list or dict held more than `Limits::max_items` entries.
    TooManyItems,
    /// The document held more than `Limits::max_total_items` values.
    TooManyTotalItems,
    /// A dictionary key was not a byte string.
    DictKeyNotString,
    /// The same dictionary key appeared twice.
    DuplicateKey,
}

impl ErrorKind {
    /// A fixed sentence. Deliberately a `&'static str`: there is no way to
    /// splice attacker bytes into it, even by accident.
    pub fn message(self) -> &'static str {
        match self {
            ErrorKind::InputTooLarge => "input is larger than the allowed maximum",
            ErrorKind::UnexpectedEnd => "input ended in the middle of a value",
            ErrorKind::UnexpectedByte => "no value can start with this byte",
            ErrorKind::TrailingBytes => "extra bytes after the top-level value",
            ErrorKind::IntEmpty => "integer has no digits",
            ErrorKind::IntLeadingZero => "integer has a leading zero",
            ErrorKind::IntNegativeZero => "negative zero is not a valid integer",
            ErrorKind::IntTooManyDigits => "integer has too many digits",
            ErrorKind::IntOverflow => "integer does not fit in 64 bits",
            ErrorKind::LengthLeadingZero => "string length has a leading zero",
            ErrorKind::LengthOverflow => "string length does not fit in a usize",
            ErrorKind::LengthBeyondInput => "string length runs past the end of the input",
            ErrorKind::StringTooLong => "string is longer than the allowed maximum",
            ErrorKind::DepthExceeded => "nesting is deeper than the allowed maximum",
            ErrorKind::TooManyItems => "list or dictionary has too many entries",
            ErrorKind::TooManyTotalItems => "document has too many values in total",
            ErrorKind::DictKeyNotString => "dictionary key is not a byte string",
            ErrorKind::DuplicateKey => "dictionary key appears twice",
        }
    }
}

/// What went wrong, and at which byte of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Offset into the original input, in bytes.
    pub at: usize,
}

impl Error {
    // The parser (Task 3) is the real caller; until then only the tests use
    // this, so it is dead code in a non-test build and live code in a test
    // build. `expect` rather than `allow` so the compiler tells us to delete
    // this attribute the moment the parser lands.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the parser from Task 3 onwards")
    )]
    pub(crate) fn new(kind: ErrorKind, at: usize) -> Self {
        Error { kind, at }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bencode error at byte {}: {}", self.at, self.kind.message())
    }
}

impl std::error::Error for Error {}

/// Shorthand used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind we enforce. Kept here so the T8 test below covers all of them.
    const ALL: &[ErrorKind] = &[
        ErrorKind::InputTooLarge,
        ErrorKind::UnexpectedEnd,
        ErrorKind::UnexpectedByte,
        ErrorKind::TrailingBytes,
        ErrorKind::IntEmpty,
        ErrorKind::IntLeadingZero,
        ErrorKind::IntNegativeZero,
        ErrorKind::IntTooManyDigits,
        ErrorKind::IntOverflow,
        ErrorKind::LengthLeadingZero,
        ErrorKind::LengthOverflow,
        ErrorKind::LengthBeyondInput,
        ErrorKind::StringTooLong,
        ErrorKind::DepthExceeded,
        ErrorKind::TooManyItems,
        ErrorKind::TooManyTotalItems,
        ErrorKind::DictKeyNotString,
        ErrorKind::DuplicateKey,
    ];

    #[test]
    fn display_names_the_offset_and_the_problem() {
        let err = Error::new(ErrorKind::IntLeadingZero, 12);
        assert_eq!(
            err.to_string(),
            "bencode error at byte 12: integer has a leading zero"
        );
    }

    /// T8: an error is safe to log. It is an offset plus a fixed sentence, so
    /// it can never echo a peer's or a file's bytes back into the log.
    #[test]
    fn t8_error_text_is_only_offset_and_reason() {
        for &kind in ALL {
            let text = Error::new(kind, 7).to_string();
            assert!(text.starts_with("bencode error at byte 7: "), "{text}");
            assert!(!kind.message().is_empty());
            assert!(kind.message().is_ascii(), "{text}");
        }
    }

    #[test]
    fn errors_are_comparable_and_copyable() {
        let a = Error::new(ErrorKind::UnexpectedEnd, 3);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, Error::new(ErrorKind::UnexpectedEnd, 4));
    }

    #[test]
    fn error_implements_the_std_error_trait() {
        fn takes_std_error<E: std::error::Error>(_: &E) {}
        takes_std_error(&Error::new(ErrorKind::TrailingBytes, 0));
    }
}
```

Create `crates/bencode/src/limits.rs`:

```rust
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
```

Replace `crates/bencode/src/lib.rs` with:

```rust
//! Bounded, hardened bencode parser and encoder (spec T1).
//!
//! Everything in a `.torrent` file arrives from a stranger, and this crate is
//! the first code that looks at it. So the rules here are strict: no panics,
//! no unbounded allocation, no recursion without a cap, and no copying of the
//! input.

mod error;
mod limits;

pub use error::{Error, ErrorKind, Result};
pub use limits::Limits;
```

- [ ] **Step 2: Run the tests**

```bash
cargo test -p bencode
```

Expected: `test result: ok. 6 passed`. This task is pure data types with no
behaviour to get wrong, so there is nothing to watch fail first. Every parser
task after this one starts red.

- [ ] **Step 3: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0. If `fmt --check` fails, run `cargo fmt --all` and re-run.

Note: `Error::new` has no non-test caller until Task 3, so `-D warnings` fails
on `dead_code` without the `cfg_attr` above. Delete that attribute in Task 3;
`unfulfilled_lint_expectations` will remind you if you forget.

- [ ] **Step 4: Explain and write notes**

Append a `## Phase 1 — Task 1` section to `docs/learn/NOTES.md` covering: what an
error *enum* buys over an error *string*; why `message()` returns `&'static str`
(attacker bytes can never get in); why every cap lives in one struct; and
`..Limits::TORRENT` (struct update syntax). Then explain the same in chat, in
plain language.

- [ ] **Step 5: Commit and push**

```bash
git add crates/bencode docs/learn/NOTES.md && git commit -m "feat(bencode): error type and parse limits (T1)" && git push
```

---

### Task 2: `Value`, `Kind`, `Span` and `Dict`

**Files:**
- Create: `crates/bencode/src/value.rs`
- Modify: `crates/bencode/src/lib.rs` (add `mod value;` and the re-export)
- Test: inline `#[cfg(test)] mod tests` in `crates/bencode/src/value.rs`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `pub struct Span { pub start: usize, pub end: usize }` with `slice(&self, input: &'a [u8]) -> Option<&'a [u8]>`, `len`, `is_empty`
  - `pub struct Value<'a>` with `kind(&self) -> &Kind<'a>`, `span(&self) -> Span`, `as_int(&self) -> Option<i64>`, `as_bytes(&self) -> Option<&'a [u8]>`, `as_list(&self) -> Option<&[Value<'a>]>`, `as_dict(&self) -> Option<&Dict<'a>>`, `pub(crate) fn new(kind: Kind<'a>, span: Span) -> Value<'a>`
  - `pub enum Kind<'a> { Int(i64), Bytes(&'a [u8]), List(Vec<Value<'a>>), Dict(Dict<'a>) }`
  - `pub struct Dict<'a>` with `get(&self, key: &[u8]) -> Option<&Value<'a>>`, `contains_key`, `len`, `is_empty`, `iter(&self) -> std::slice::Iter<'_, (&'a [u8], Value<'a>)>`, `pub(crate) fn new()`, `pub(crate) fn push(&mut self, key: &'a [u8], value: Value<'a>)`, `pub(crate) fn last_key(&self) -> Option<&'a [u8]>`

- [ ] **Step 1: Write the failing tests**

Create `crates/bencode/src/value.rs` exactly as below — real tests, `todo!()`
bodies — so the first run is genuinely red:

```rust
//! The parsed shape of a bencode document.
//!
//! Values BORROW their bytes from the input (`&'a [u8]`); they never copy
//! them. That `'a` lifetime is the compiler enforcing "this `Value` may not
//! outlive the buffer it was parsed from" — the bug class that, in C, is
//! called use-after-free.

use std::fmt;

/// Where a value sits in the ORIGINAL input bytes.
///
/// BitTorrent's `info_hash` is the SHA-1 of the *raw bytes* of the `info`
/// dictionary, not of a re-encoded copy. Re-encoding could differ by a single
/// byte and every peer in the swarm would then reject us. So the parser
/// remembers where each value was, and Phase 2 hashes exactly those bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// The original bytes this value was parsed from.
    ///
    /// Returns `None` if `input` is not the buffer this span came from, so a
    /// mismatched buffer is a `None`, never a panic.
    pub fn slice<'a>(&self, input: &'a [u8]) -> Option<&'a [u8]> {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// One bencode value plus the byte range it came from.
#[derive(Clone)]
pub struct Value<'a> {
    pub(crate) kind: Kind<'a>,
    pub(crate) span: Span,
}

/// The four bencode types.
#[derive(Clone, PartialEq, Eq)]
pub enum Kind<'a> {
    Int(i64),
    /// Bencode strings are BYTES, not text. They are often not valid UTF-8,
    /// and `pieces` is a wall of raw SHA-1 hashes. Decoding to `String` here
    /// would either lose data or fail, so we do neither.
    Bytes(&'a [u8]),
    List(Vec<Value<'a>>),
    Dict(Dict<'a>),
}

/// Dictionary entries, kept in the order they appeared in the input.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Dict<'a> {
    entries: Vec<(&'a [u8], Value<'a>)>,
}

/// Two values are equal when they MEAN the same thing. Spans are provenance,
/// not identity, so they are deliberately left out of the comparison.
/// Dictionary entry ORDER is compared; use `encode` to compare canonically.
impl PartialEq for Value<'_> {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Eq for Value<'_> {}

impl<'a> Value<'a> {
    pub(crate) fn new(kind: Kind<'a>, span: Span) -> Self {
        Value { kind, span }
    }

    pub fn kind(&self) -> &Kind<'a> {
        todo!()
    }

    pub fn span(&self) -> Span {
        todo!()
    }

    pub fn as_int(&self) -> Option<i64> {
        todo!()
    }

    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        todo!()
    }

    pub fn as_list(&self) -> Option<&[Value<'a>]> {
        todo!()
    }

    pub fn as_dict(&self) -> Option<&Dict<'a>> {
        todo!()
    }
}

impl<'a> Dict<'a> {
    pub(crate) fn new() -> Self {
        Dict {
            entries: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, key: &'a [u8], value: Value<'a>) {
        todo!()
    }

    /// The key most recently pushed. The parser uses it to notice unsorted keys.
    pub(crate) fn last_key(&self) -> Option<&'a [u8]> {
        todo!()
    }

    /// Dictionaries in a torrent hold a handful of entries, so a linear scan
    /// beats hashing and costs no allocation.
    pub fn get(&self, key: &[u8]) -> Option<&Value<'a>> {
        todo!()
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, (&'a [u8], Value<'a>)> {
        todo!()
    }
}

/// How many bytes of a byte string `Debug` will print.
const DEBUG_BYTES_SHOWN: usize = 16;

impl fmt::Debug for Kind<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl fmt::Debug for Dict<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: &[u8] = b"d3:cow3:mooe";

    fn bytes(value: &'static [u8], start: usize, end: usize) -> Value<'static> {
        Value::new(Kind::Bytes(value), Span { start, end })
    }

    #[test]
    fn span_slices_the_original_bytes() {
        let span = Span { start: 1, end: 6 };
        assert_eq!(span.slice(INPUT), Some(b"3:cow".as_slice()));
        assert_eq!(span.len(), 5);
        assert!(!span.is_empty());
    }

    #[test]
    fn span_returns_none_for_a_buffer_it_does_not_fit() {
        let span = Span { start: 1, end: 6 };
        assert_eq!(span.slice(b"tiny".as_slice()), None);
    }

    #[test]
    fn accessors_return_none_for_the_wrong_kind() {
        let v = Value::new(Kind::Int(42), Span { start: 0, end: 4 });
        assert_eq!(v.as_int(), Some(42));
        assert_eq!(v.as_bytes(), None);
        assert!(v.as_list().is_none());
        assert!(v.as_dict().is_none());
        assert_eq!(v.span(), Span { start: 0, end: 4 });
        assert!(matches!(v.kind(), Kind::Int(42)));
    }

    #[test]
    fn dict_finds_entries_by_key_and_reports_misses() {
        let mut d = Dict::new();
        d.push(b"cow", bytes(b"moo", 6, 11));
        assert_eq!(d.len(), 1);
        assert!(!d.is_empty());
        assert!(d.contains_key(b"cow"));
        assert_eq!(
            d.get(b"cow").and_then(Value::as_bytes),
            Some(b"moo".as_slice())
        );
        assert!(d.get(b"pig").is_none());
        assert_eq!(d.last_key(), Some(b"cow".as_slice()));
        assert_eq!(d.iter().count(), 1);
    }

    #[test]
    fn equality_compares_meaning_and_ignores_spans() {
        let a = Value::new(Kind::Int(7), Span { start: 0, end: 3 });
        let b = Value::new(Kind::Int(7), Span { start: 99, end: 102 });
        let c = Value::new(Kind::Int(8), Span { start: 0, end: 3 });
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// T8: `Debug` must not dump megabytes of a torrent's `pieces` field into
    /// a log line. It prints the length and a short prefix instead.
    #[test]
    fn t8_debug_truncates_long_byte_strings() {
        let long = vec![b'A'; 4096];
        let v = Value::new(Kind::Bytes(&long), Span { start: 0, end: 0 });
        let text = format!("{v:?}");
        assert!(text.starts_with("Bytes(4096 bytes: AAAA"), "{text}");
        assert!(text.ends_with("\u{2026})"), "{text}");
        assert!(text.len() < 64, "debug output must stay short: {text}");
    }

    #[test]
    fn debug_shows_short_byte_strings_in_full() {
        let v = bytes(b"moo", 0, 5);
        assert_eq!(format!("{v:?}"), "Bytes(3 bytes: moo)");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p bencode value::
```

Expected: the 7 `value::tests::*` tests FAIL, each panicking at a `todo!()`
("not yet implemented").

- [ ] **Step 3: Write the implementation**

Replace every `todo!()` body in `crates/bencode/src/value.rs` with:

```rust
impl Span {
    pub fn slice<'a>(&self, input: &'a [u8]) -> Option<&'a [u8]> {
        // `.get(range)` instead of `input[range]`: a bad range is a `None`,
        // never a panic. Clippy's `indexing_slicing` lint enforces this.
        input.get(self.start..self.end)
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PartialEq for Value<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl<'a> Value<'a> {
    pub fn kind(&self) -> &Kind<'a> {
        &self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn as_int(&self) -> Option<i64> {
        match self.kind {
            Kind::Int(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self.kind {
            Kind::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value<'a>]> {
        match &self.kind {
            Kind::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dict<'a>> {
        match &self.kind {
            Kind::Dict(d) => Some(d),
            _ => None,
        }
    }
}

impl<'a> Dict<'a> {
    pub(crate) fn push(&mut self, key: &'a [u8], value: Value<'a>) {
        self.entries.push((key, value));
    }

    pub(crate) fn last_key(&self) -> Option<&'a [u8]> {
        self.entries.last().map(|(k, _)| *k)
    }

    pub fn get(&self, key: &[u8]) -> Option<&Value<'a>> {
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, (&'a [u8], Value<'a>)> {
        self.entries.iter()
    }
}

impl fmt::Debug for Kind<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Int(n) => write!(f, "Int({n})"),
            Kind::Bytes(b) => {
                // A torrent's `pieces` field is megabytes of raw hashes.
                // Printing it would flood the log and leak content (spec T8).
                let shown = b.get(..DEBUG_BYTES_SHOWN).unwrap_or(b);
                let ellipsis = if b.len() > DEBUG_BYTES_SHOWN {
                    "\u{2026}"
                } else {
                    ""
                };
                write!(
                    f,
                    "Bytes({} bytes: {}{})",
                    b.len(),
                    shown.escape_ascii(),
                    ellipsis
                )
            }
            Kind::List(items) => f.debug_list().entries(items).finish(),
            Kind::Dict(d) => fmt::Debug::fmt(d, f),
        }
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.kind, f)
    }
}

impl fmt::Debug for Dict<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (key, value) in self.entries.iter() {
            map.entry(&Kind::Bytes(key), value);
        }
        map.finish()
    }
}
```

Add `mod value;` to `crates/bencode/src/lib.rs` after `mod limits;`, and add
this re-export after the existing ones:

```rust
pub use value::{Dict, Kind, Span, Value};
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p bencode
```

Expected: `test result: ok. 13 passed` (6 from Task 1, 7 here).

- [ ] **Step 5: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 2` to `docs/learn/NOTES.md`: what `'a` means on
`Value<'a>` and why borrowing beats copying here; why bencode strings are bytes
and not `String`; what a `Span` is for (`info_hash`); why `PartialEq` is written
by hand instead of derived; and why `Debug` truncates. Explain the same in chat.

- [ ] **Step 7: Commit and push**

```bash
git add crates/bencode docs/learn/NOTES.md && git commit -m "feat(bencode): value tree with byte spans" && git push
```

---

### Task 3: Parser core — the cursor, integers and byte strings

**Files:**
- Create: `crates/bencode/src/parser.rs`
- Modify: `crates/bencode/src/lib.rs` (add `mod parser;` — no re-export, the parser stays private)
- Test: inline `#[cfg(test)] mod tests` in `crates/bencode/src/parser.rs`

**Interfaces:**
- Consumes: `Error`, `ErrorKind`, `Result` (Task 1); `Limits` (Task 1); `Kind`, `Span`, `Value`, `Dict` (Task 2).
- Produces:
  - `pub(crate) struct Parser<'a, 'l>` with `pub(crate) fn new(input: &'a [u8], limits: &'l Limits) -> Parser<'a, 'l>`, `pub(crate) fn pos(&self) -> usize`, `pub(crate) fn canonical(&self) -> bool`, `pub(crate) fn parse_value(&mut self, depth: u32) -> Result<Value<'a>>`
  - Private: `fn parse_int`, `fn parse_bytes`, `fn parse_byte_string(&mut self) -> Result<(&'a [u8], Span)>`, `fn take_until`, and free functions `fn parse_int_digits(raw: &[u8], at: usize, max_digits: usize) -> Result<i64>`, `fn parse_length(raw: &[u8], at: usize) -> Result<usize>`

- [ ] **Step 1: Write the failing tests**

Create `crates/bencode/src/parser.rs`. Write the whole file below, but with
`todo!()` as the body of `parse_value`, `parse_int`, `parse_byte_string`,
`take_until`, `parse_int_digits` and `parse_length`:

```rust
//! The bounded cursor that turns bytes into `Value`s (spec T1).
//!
//! Rules that hold everywhere in this file:
//!   * never index (`input[i]`) — always `.get(..)`, so a bad offset is a
//!     `None` and not a crash;
//!   * never add or multiply without `checked_*` or `saturating_*`;
//!   * never scan forward without a limit;
//!   * never allocate before the size has been checked.

use crate::error::{Error, ErrorKind, Result};
use crate::limits::Limits;
use crate::value::{Dict, Kind, Span, Value};
use std::collections::HashSet;

/// A byte-string length can never usefully have more digits than this.
/// `usize::MAX` on 64-bit is 20 digits, so 20 is generous already.
const MAX_LENGTH_DIGITS: usize = 20;

pub(crate) struct Parser<'a, 'l> {
    input: &'a [u8],
    pos: usize,
    limits: &'l Limits,
    /// Values produced so far, across the WHOLE document.
    total_items: usize,
    /// Set to false the first time a dictionary's keys are out of order.
    canonical: bool,
}

impl<'a, 'l> Parser<'a, 'l> {
    pub(crate) fn new(input: &'a [u8], limits: &'l Limits) -> Self {
        Parser {
            input,
            pos: 0,
            limits,
            total_items: 0,
            canonical: true,
        }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn canonical(&self) -> bool {
        self.canonical
    }

    fn err(&self, kind: ErrorKind) -> Error {
        Error::new(kind, self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// Read bytes up to but not including `stop`, leaving `pos` on `stop`.
    ///
    /// Gives up after `max` bytes. Without that, `i` followed by nine
    /// megabytes of digits would make us walk the whole file looking for a
    /// terminator that is not there.
    fn take_until(&mut self, stop: u8, max: usize, too_long: ErrorKind) -> Result<&'a [u8]> {
        todo!()
    }

    /// `i<digits>e`. Called with `pos` on the `i`.
    fn parse_int(&mut self) -> Result<Value<'a>> {
        todo!()
    }

    /// `<len>:<bytes>`. Called with `pos` on the first digit.
    /// Returns the borrowed bytes and the span covering `<len>:<bytes>`.
    fn parse_byte_string(&mut self) -> Result<(&'a [u8], Span)> {
        todo!()
    }

    fn parse_bytes(&mut self) -> Result<Value<'a>> {
        let (bytes, span) = self.parse_byte_string()?;
        Ok(Value::new(Kind::Bytes(bytes), span))
    }

    /// Parse one value. `depth` is how many containers we are inside.
    pub(crate) fn parse_value(&mut self, depth: u32) -> Result<Value<'a>> {
        todo!()
    }
}

/// Turn the digits between `i` and `e` into an `i64`, strictly.
fn parse_int_digits(raw: &[u8], at: usize, max_digits: usize) -> Result<i64> {
    todo!()
}

/// Turn the digits before `:` into a length, strictly.
fn parse_length(raw: &[u8], at: usize) -> Result<usize> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse one value from `input` and return it together with how many
    /// bytes were consumed.
    fn one(input: &[u8]) -> Result<(Value<'_>, usize)> {
        let limits = Limits::TORRENT;
        let mut p = Parser::new(input, &limits);
        let v = p.parse_value(0)?;
        let pos = p.pos();
        Ok((v, pos))
    }

    /// The error kind `input` is rejected with, or `None` if it parsed.
    /// Returning an `Option` keeps `panic!` out of the tests, which the
    /// workspace lints forbid.
    fn kind_of(input: &[u8]) -> Option<ErrorKind> {
        one(input).err().map(|e| e.kind)
    }

    #[test]
    fn parses_integers() {
        let (v, used) = one(b"i42e").expect("i42e parses");
        assert_eq!(v.as_int(), Some(42));
        assert_eq!(used, 4);
        assert_eq!(v.span(), Span { start: 0, end: 4 });
        assert_eq!(one(b"i0e").map(|(v, _)| v.as_int()).ok(), Some(Some(0)));
        assert_eq!(one(b"i-7e").map(|(v, _)| v.as_int()).ok(), Some(Some(-7)));
    }

    #[test]
    fn parses_the_extremes_of_i64() {
        assert_eq!(
            one(b"i9223372036854775807e").map(|(v, _)| v.as_int()).ok(),
            Some(Some(i64::MAX))
        );
        // i64::MIN has no positive counterpart, so this is the case a naive
        // "parse the digits then negate" implementation gets wrong.
        assert_eq!(
            one(b"i-9223372036854775808e").map(|(v, _)| v.as_int()).ok(),
            Some(Some(i64::MIN))
        );
    }

    #[test]
    fn parses_byte_strings_including_empty_and_non_utf8() {
        let (v, used) = one(b"4:spam").expect("4:spam parses");
        assert_eq!(v.as_bytes(), Some(b"spam".as_slice()));
        assert_eq!(used, 6);
        assert_eq!(one(b"0:").map(|(v, _)| v.as_bytes()).ok(), Some(Some(b"".as_slice())));
        let raw = b"2:\xff\xfe";
        assert_eq!(
            one(raw).map(|(v, _)| v.as_bytes()).ok(),
            Some(Some(b"\xff\xfe".as_slice()))
        );
    }

    #[test]
    fn t1_rejects_empty_integer() {
        assert_eq!(kind_of(b"ie"), Some(ErrorKind::IntEmpty));
    }

    #[test]
    fn t1_rejects_leading_zero() {
        assert_eq!(kind_of(b"i03e"), Some(ErrorKind::IntLeadingZero));
        assert_eq!(kind_of(b"i-03e"), Some(ErrorKind::IntLeadingZero));
    }

    #[test]
    fn t1_rejects_negative_zero() {
        assert_eq!(kind_of(b"i-0e"), Some(ErrorKind::IntNegativeZero));
    }

    #[test]
    fn t1_rejects_too_many_digits() {
        // 21 digits: over the spec's cap of 20.
        assert_eq!(kind_of(b"i123456789012345678901e"), Some(ErrorKind::IntTooManyDigits));
    }

    #[test]
    fn t1_rejects_integer_overflow() {
        // 19 digits, under the digit cap, but one past i64::MAX. The digit
        // cap alone is NOT enough; the checked arithmetic is what catches it.
        assert_eq!(kind_of(b"i9223372036854775808e"), Some(ErrorKind::IntOverflow));
        assert_eq!(kind_of(b"i-9223372036854775809e"), Some(ErrorKind::IntOverflow));
    }

    #[test]
    fn t1_rejects_unterminated_integer() {
        assert_eq!(kind_of(b"i42"), Some(ErrorKind::UnexpectedEnd));
        assert_eq!(kind_of(b"i"), Some(ErrorKind::UnexpectedEnd));
    }

    #[test]
    fn t1_rejects_non_digits_inside_an_integer() {
        assert_eq!(kind_of(b"i4x2e"), Some(ErrorKind::UnexpectedByte));
    }

    /// The single most important check in the crate: a 6-byte file must not
    /// be able to claim a 4 GiB string and make us allocate for it.
    #[test]
    fn t1_rejects_length_beyond_input() {
        assert_eq!(kind_of(b"9:ab"), Some(ErrorKind::LengthBeyondInput));
        // A length under `max_string` but past the end of the buffer.
        assert_eq!(kind_of(b"1048576:x"), Some(ErrorKind::LengthBeyondInput));
    }

    #[test]
    fn t1_rejects_length_leading_zero() {
        assert_eq!(kind_of(b"01:a"), Some(ErrorKind::LengthLeadingZero));
    }

    #[test]
    fn t1_rejects_length_overflow() {
        // 20 nines is larger than usize::MAX on 64-bit.
        assert_eq!(kind_of(b"99999999999999999999:a"), Some(ErrorKind::LengthOverflow));
    }

    #[test]
    fn t1_rejects_string_longer_than_the_limit() {
        let limits = Limits {
            max_string: 2,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"4:spam", &limits);
        assert_eq!(p.parse_value(0).map(|_| ()), Err(Error::new(ErrorKind::StringTooLong, 0)));
    }

    #[test]
    fn t1_rejects_unterminated_byte_string() {
        assert_eq!(kind_of(b"4"), Some(ErrorKind::UnexpectedEnd));
    }

    #[test]
    fn t1_rejects_a_byte_that_starts_nothing() {
        assert_eq!(kind_of(b"x"), Some(ErrorKind::UnexpectedByte));
        assert_eq!(kind_of(b"-1:a"), Some(ErrorKind::UnexpectedByte));
        assert_eq!(kind_of(b""), Some(ErrorKind::UnexpectedEnd));
    }

    #[test]
    fn t1_rejects_too_many_total_items() {
        let limits = Limits {
            max_total_items: 0,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"i1e", &limits);
        assert_eq!(
            p.parse_value(0).map(|_| ()),
            Err(Error::new(ErrorKind::TooManyTotalItems, 0))
        );
    }

    #[test]
    fn t1_rejects_depth_past_the_limit() {
        let limits = Limits {
            max_depth: 2,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"i1e", &limits);
        assert_eq!(
            p.parse_value(3).map(|_| ()),
            Err(Error::new(ErrorKind::DepthExceeded, 0))
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p bencode parser::
```

Expected: all 16 `parser::tests::*` tests FAIL at a `todo!()`.

- [ ] **Step 3: Write the implementation**

Replace the `todo!()` bodies in `crates/bencode/src/parser.rs`:

```rust
    fn take_until(&mut self, stop: u8, max: usize, too_long: ErrorKind) -> Result<&'a [u8]> {
        let start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.err(ErrorKind::UnexpectedEnd)),
                Some(b) if b == stop => {
                    return self
                        .input
                        .get(start..self.pos)
                        .ok_or_else(|| self.err(ErrorKind::UnexpectedEnd));
                }
                Some(_) => {
                    if self.pos.saturating_sub(start) >= max {
                        return Err(self.err(too_long));
                    }
                    self.bump();
                }
            }
        }
    }

    fn parse_int(&mut self) -> Result<Value<'a>> {
        let start = self.pos;
        self.bump(); // past the 'i'
        let digits_at = self.pos;
        // +1 so a leading '-' still fits inside the scan window.
        let scan_max = self.limits.max_int_digits.saturating_add(1);
        let raw = self.take_until(b'e', scan_max, ErrorKind::IntTooManyDigits)?;
        self.bump(); // past the 'e'
        let n = parse_int_digits(raw, digits_at, self.limits.max_int_digits)?;
        Ok(Value::new(
            Kind::Int(n),
            Span {
                start,
                end: self.pos,
            },
        ))
    }

    fn parse_byte_string(&mut self) -> Result<(&'a [u8], Span)> {
        let start = self.pos;
        let raw_len = self.take_until(b':', MAX_LENGTH_DIGITS, ErrorKind::LengthOverflow)?;
        let len = parse_length(raw_len, start)?;
        self.bump(); // past the ':'
        if len > self.limits.max_string {
            return Err(Error::new(ErrorKind::StringTooLong, start));
        }
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| self.err(ErrorKind::LengthOverflow))?;
        // The declared length must fit in what is ACTUALLY left. This check
        // runs BEFORE anything is allocated, and because the bytes are
        // borrowed rather than copied, nothing is allocated at all.
        let bytes = self
            .input
            .get(self.pos..end)
            .ok_or_else(|| self.err(ErrorKind::LengthBeyondInput))?;
        self.pos = end;
        Ok((
            bytes,
            Span {
                start,
                end: self.pos,
            },
        ))
    }

    pub(crate) fn parse_value(&mut self, depth: u32) -> Result<Value<'a>> {
        if depth > self.limits.max_depth {
            return Err(self.err(ErrorKind::DepthExceeded));
        }
        self.total_items = self.total_items.saturating_add(1);
        if self.total_items > self.limits.max_total_items {
            return Err(self.err(ErrorKind::TooManyTotalItems));
        }
        match self.peek() {
            None => Err(self.err(ErrorKind::UnexpectedEnd)),
            Some(b'i') => self.parse_int(),
            Some(b'0'..=b'9') => self.parse_bytes(),
            Some(_) => Err(self.err(ErrorKind::UnexpectedByte)),
        }
    }
```

and the two free functions:

```rust
fn parse_int_digits(raw: &[u8], at: usize, max_digits: usize) -> Result<i64> {
    let err = |kind| Error::new(kind, at);
    let (negative, digits) = match raw.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, raw),
    };
    if digits.is_empty() {
        return Err(err(ErrorKind::IntEmpty));
    }
    if digits.len() > max_digits {
        return Err(err(ErrorKind::IntTooManyDigits));
    }
    // Canonical bencode: `0` is the only number that may start with `0`,
    // and there is no `-0`. Both rules exist so one number has exactly one
    // encoding — which matters because `info_hash` hashes raw bytes.
    if digits.first() == Some(&b'0') && digits.len() > 1 {
        return Err(err(ErrorKind::IntLeadingZero));
    }
    if negative && digits == b"0".as_slice() {
        return Err(err(ErrorKind::IntNegativeZero));
    }
    // Count DOWNWARDS, into the negative half of i64. i64::MIN is
    // -9223372036854775808 and its magnitude has no positive counterpart, so
    // building the number positively and negating at the end would overflow.
    let mut acc: i64 = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return Err(err(ErrorKind::UnexpectedByte));
        }
        let digit = i64::from(d - b'0');
        acc = acc
            .checked_mul(10)
            .and_then(|a| a.checked_sub(digit))
            .ok_or_else(|| err(ErrorKind::IntOverflow))?;
    }
    if negative {
        Ok(acc)
    } else {
        acc.checked_neg().ok_or_else(|| err(ErrorKind::IntOverflow))
    }
}

fn parse_length(raw: &[u8], at: usize) -> Result<usize> {
    let err = |kind| Error::new(kind, at);
    if raw.is_empty() {
        return Err(err(ErrorKind::UnexpectedByte));
    }
    if raw.first() == Some(&b'0') && raw.len() > 1 {
        return Err(err(ErrorKind::LengthLeadingZero));
    }
    let mut acc: usize = 0;
    for &d in raw {
        if !d.is_ascii_digit() {
            return Err(err(ErrorKind::UnexpectedByte));
        }
        acc = acc
            .checked_mul(10)
            .and_then(|a| a.checked_add(usize::from(d - b'0')))
            .ok_or_else(|| err(ErrorKind::LengthOverflow))?;
    }
    Ok(acc)
}
```

Add `mod parser;` to `crates/bencode/src/lib.rs`. Do **not** re-export it: the
cursor is an implementation detail, and keeping it private means the public
surface is just `parse`, `encode` and the value types.

Note: the `use crate::value::Dict;` and `use std::collections::HashSet;` lines
are unused until Task 4 and will warn. Leave them out for now and add them in
Task 4 — `cargo clippy -D warnings` will fail otherwise.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p bencode
```

Expected: `test result: ok. 29 passed` (13 + 16).

- [ ] **Step 5: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 3` to `docs/learn/NOTES.md`: what a cursor parser is;
why `.get()` everywhere; why `checked_mul`/`checked_sub`; the counting-downwards
trick for `i64::MIN`; why the digit cap alone does not stop overflow; and why
"the declared length must fit in what is actually left" is the most important
line in the file. Explain the same in chat.

- [ ] **Step 7: Commit and push**

```bash
git add crates/bencode docs/learn/NOTES.md && git commit -m "feat(bencode): strict integer and byte-string parsing (T1)" && git push
```

---

### Task 4: Lists and dictionaries — depth, item caps, duplicate keys

**Files:**
- Modify: `crates/bencode/src/parser.rs`
- Test: the existing inline `#[cfg(test)] mod tests` in `crates/bencode/src/parser.rs`

**Interfaces:**
- Consumes: everything from Task 3, plus `Dict` (Task 2).
- Produces: `Parser::parse_list(&mut self, depth: u32) -> Result<Value<'a>>` and `Parser::parse_dict(&mut self, depth: u32) -> Result<Value<'a>>` (both private); `parse_value` now also handles `l` and `d`; `Parser::canonical()` can now return `false`.

- [ ] **Step 1: Write the failing tests**

Append to the `mod tests` block in `crates/bencode/src/parser.rs`:

```rust
    /// Parse one value and also report whether the input was canonical.
    fn one_flagged(input: &[u8]) -> Result<(Value<'_>, bool)> {
        let limits = Limits::TORRENT;
        let mut p = Parser::new(input, &limits);
        let v = p.parse_value(0)?;
        let canonical = p.canonical();
        Ok((v, canonical))
    }

    #[test]
    fn parses_lists_including_the_empty_one() {
        let (v, used) = one(b"li1e4:spame").expect("list parses");
        let items = v.as_list().expect("is a list");
        assert_eq!(items.len(), 2);
        assert_eq!(items.first().and_then(Value::as_int), Some(1));
        assert_eq!(
            items.get(1).and_then(Value::as_bytes),
            Some(b"spam".as_slice())
        );
        assert_eq!(used, 11);
        assert_eq!(v.span(), Span { start: 0, end: 11 });

        let (empty, _) = one(b"le").expect("empty list parses");
        assert_eq!(empty.as_list().map(<[Value<'_>]>::len), Some(0));
    }

    #[test]
    fn parses_dictionaries_and_records_spans() {
        let input = b"d3:cow3:moo4:spam4:eggse";
        let (v, used) = one(input).expect("dict parses");
        assert_eq!(used, input.len());
        let d = v.as_dict().expect("is a dict");
        assert_eq!(d.len(), 2);
        assert_eq!(
            d.get(b"cow").and_then(Value::as_bytes),
            Some(b"moo".as_slice())
        );
        assert_eq!(
            d.get(b"spam").and_then(Value::as_bytes),
            Some(b"eggs".as_slice())
        );
        // The span of the value under "cow" covers exactly `3:moo`.
        let span = d.get(b"cow").map(Value::span).expect("cow is present");
        assert_eq!(span.slice(input), Some(b"3:moo".as_slice()));
    }

    #[test]
    fn parses_nested_containers() {
        let (v, _) = one(b"d4:listli1ei2eee").expect("nested parses");
        let inner = v
            .as_dict()
            .and_then(|d| d.get(b"list"))
            .and_then(Value::as_list)
            .expect("list under key");
        assert_eq!(inner.len(), 2);
    }

    #[test]
    fn sorted_keys_are_canonical() {
        let (_, canonical) = one_flagged(b"d1:ai1e1:bi2ee").expect("parses");
        assert!(canonical);
    }

    /// Plenty of real torrents have unsorted keys. Rejecting them would make
    /// the client useless, so we accept them and raise a flag instead.
    #[test]
    fn unsorted_keys_are_tolerated_but_flagged() {
        let (v, canonical) = one_flagged(b"d1:bi2e1:ai1ee").expect("parses");
        assert!(!canonical);
        let d = v.as_dict().expect("is a dict");
        assert_eq!(d.get(b"a").and_then(Value::as_int), Some(1));
        assert_eq!(d.get(b"b").and_then(Value::as_int), Some(2));
    }

    #[test]
    fn t1_rejects_duplicate_keys() {
        assert_eq!(kind_of(b"d1:ai1e1:ai2ee"), Some(ErrorKind::DuplicateKey));
    }

    /// A duplicate hidden by unsorted keys: b, a, b. Comparing only against
    /// the previous key would miss this, so the parser keeps a set.
    #[test]
    fn t1_rejects_duplicate_keys_hidden_by_unsorted_order() {
        assert_eq!(kind_of(b"d1:bi1e1:ai2e1:bi3ee"), Some(ErrorKind::DuplicateKey));
    }

    #[test]
    fn t1_rejects_non_string_dict_key() {
        assert_eq!(kind_of(b"di1ei2ee"), Some(ErrorKind::DictKeyNotString));
    }

    #[test]
    fn t1_rejects_dict_key_with_no_value() {
        assert_eq!(kind_of(b"d1:ae"), Some(ErrorKind::UnexpectedByte));
    }

    #[test]
    fn t1_rejects_unterminated_containers() {
        assert_eq!(kind_of(b"li1e"), Some(ErrorKind::UnexpectedEnd));
        assert_eq!(kind_of(b"d1:ai1e"), Some(ErrorKind::UnexpectedEnd));
        assert_eq!(kind_of(b"l"), Some(ErrorKind::UnexpectedEnd));
    }

    /// A "billion laughs" shaped attack: a few kilobytes of `l` would recurse
    /// thousands of frames deep and blow the stack. The depth cap stops it.
    #[test]
    fn t1_rejects_deep_nesting() {
        let mut deep = vec![b'l'; 100];
        deep.extend(std::iter::repeat_n(b'e', 100));
        assert_eq!(kind_of(&deep), Some(ErrorKind::DepthExceeded));
    }

    #[test]
    fn accepts_nesting_right_up_to_the_limit() {
        let limits = Limits {
            max_depth: 4,
            ..Limits::TORRENT
        };
        // 4 nested lists = depths 0,1,2,3 -> allowed.
        let mut p = Parser::new(b"lllleeee", &limits);
        assert!(p.parse_value(0).is_ok());
        // 5 nested lists reaches depth 4... still allowed (0..=4), 6 is not.
        let mut p = Parser::new(b"lllllleeeeee", &limits);
        assert_eq!(
            p.parse_value(0).map(|_| ()),
            Err(Error::new(ErrorKind::DepthExceeded, 5))
        );
    }

    #[test]
    fn t1_rejects_too_many_items_in_a_list() {
        let limits = Limits {
            max_items: 2,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"li1ei2ei3ee", &limits);
        assert_eq!(
            p.parse_value(0).map(|_| ()),
            Err(Error::new(ErrorKind::TooManyItems, 7))
        );
    }

    #[test]
    fn t1_rejects_too_many_items_in_a_dict() {
        let limits = Limits {
            max_items: 1,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"d1:ai1e1:bi2ee", &limits);
        assert_eq!(
            p.parse_value(0).map(|_| ()),
            Err(Error::new(ErrorKind::TooManyItems, 7))
        );
    }

    /// 10 MiB of `le` would become millions of `Value` structs. The
    /// document-wide cap bounds the memory a small file can cost us.
    #[test]
    fn t1_rejects_too_many_values_in_the_whole_document() {
        let limits = Limits {
            max_total_items: 3,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"li1ei2ei3ee", &limits);
        assert_eq!(p.parse_value(0).map(|_| ()).map_err(|e| e.kind), Err(ErrorKind::TooManyTotalItems));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p bencode parser::
```

Expected: the 14 new tests FAIL — the container ones with
`UnexpectedByte` (because `parse_value` does not know `l` or `d` yet), and
`one_flagged` may not compile until `canonical()` is reachable. Both are the
red state we want.

- [ ] **Step 3: Write the implementation**

In `crates/bencode/src/parser.rs`, restore the two imports that Task 3 left out:

```rust
use crate::value::{Dict, Kind, Span, Value};
use std::collections::HashSet;
```

Add two arms to `parse_value`, between the `b'0'..=b'9'` arm and the catch-all:

```rust
            Some(b'l') => self.parse_list(depth),
            Some(b'd') => self.parse_dict(depth),
```

Add the two methods to the `impl Parser` block:

```rust
    /// `l<values>e`. Called with `pos` on the `l`.
    fn parse_list(&mut self, depth: u32) -> Result<Value<'a>> {
        let start = self.pos;
        self.bump(); // past the 'l'
        let mut items: Vec<Value<'a>> = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.err(ErrorKind::UnexpectedEnd)),
                Some(b'e') => {
                    self.bump();
                    break;
                }
                Some(_) => {
                    if items.len() >= self.limits.max_items {
                        return Err(self.err(ErrorKind::TooManyItems));
                    }
                    // `depth + 1`: every container costs one level, and
                    // `parse_value` refuses to go past `max_depth`. That cap
                    // is the only reason this recursion cannot blow the stack.
                    let value = self.parse_value(depth.saturating_add(1))?;
                    items.push(value);
                }
            }
        }
        Ok(Value::new(
            Kind::List(items),
            Span {
                start,
                end: self.pos,
            },
        ))
    }

    /// `d<key><value>...e`. Called with `pos` on the `d`.
    fn parse_dict(&mut self, depth: u32) -> Result<Value<'a>> {
        let start = self.pos;
        self.bump(); // past the 'd'
        let mut dict = Dict::new();
        // Duplicate detection. A linear scan would be O(n^2) and, with
        // max_items at 100_000, that is itself a denial of service. The
        // standard library's hasher is randomly seeded per process, so an
        // attacker cannot pick keys that all collide either.
        let mut seen: HashSet<&'a [u8]> = HashSet::new();
        loop {
            match self.peek() {
                None => return Err(self.err(ErrorKind::UnexpectedEnd)),
                Some(b'e') => {
                    self.bump();
                    break;
                }
                Some(b'0'..=b'9') => {
                    if dict.len() >= self.limits.max_items {
                        return Err(self.err(ErrorKind::TooManyItems));
                    }
                    let key_at = self.pos;
                    let (key, _) = self.parse_byte_string()?;
                    if !seen.insert(key) {
                        return Err(Error::new(ErrorKind::DuplicateKey, key_at));
                    }
                    // Out of order is TOLERATED — real torrents do it — but
                    // remembered, because canonical bytes matter for hashing.
                    if let Some(previous) = dict.last_key()
                        && previous > key
                    {
                        self.canonical = false;
                    }
                    let value = self.parse_value(depth.saturating_add(1))?;
                    dict.push(key, value);
                }
                // Keys must be byte strings, so anything else is malformed.
                Some(_) => return Err(self.err(ErrorKind::DictKeyNotString)),
            }
        }
        Ok(Value::new(
            Kind::Dict(dict),
            Span {
                start,
                end: self.pos,
            },
        ))
    }
```

If the `let ... && ...` let-chain is rejected by the compiler, use the nested
form instead:

```rust
                    if let Some(previous) = dict.last_key() {
                        if previous > key {
                            self.canonical = false;
                        }
                    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p bencode
```

Expected: `test result: ok. 43 passed` (29 + 14).

If `accepts_nesting_right_up_to_the_limit` disagrees about the exact offset or
the exact number of `l`s allowed, fix the **test** to match the rule
`depth > max_depth` — do not loosen the rule.

- [ ] **Step 5: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 4` to `docs/learn/NOTES.md`: what recursion is and why
an unbounded one crashes; how the depth cap turns recursion into a safe
technique; the two different item caps and what each one stops; why duplicate
keys are rejected but unsorted ones are only flagged; and why a `HashSet` beats
a linear scan here. Explain the same in chat.

- [ ] **Step 7: Commit and push**

```bash
git add crates/bencode docs/learn/NOTES.md && git commit -m "feat(bencode): bounded lists and dicts, duplicate-key rejection (T1)" && git push
```

---

### Task 5: Public API — `parse`, `Parsed`, input cap, trailing bytes

**Files:**
- Modify: `crates/bencode/src/lib.rs`
- Create: `crates/bencode/tests/parse.rs`

**Interfaces:**
- Consumes: `Parser` (Tasks 3–4), `Error`/`ErrorKind` (Task 1), `Limits` (Task 1), `Value` (Task 2).
- Produces:
  - `pub struct Parsed<'a> { pub value: Value<'a>, pub canonical: bool }`, `Debug + Clone`
  - `pub fn parse(input: &[u8]) -> Result<Parsed<'_>>`
  - `pub fn parse_with<'a>(input: &'a [u8], limits: &Limits) -> Result<Parsed<'a>>`

`crates/bencode/tests/parse.rs` is an **integration test**: it is a separate
crate that can only see the public API. If something it needs is not `pub`, the
public API is wrong — that is the point of putting these tests there.

- [ ] **Step 1: Write the failing tests**

Create `crates/bencode/tests/parse.rs`:

```rust
//! Integration tests: these run against the public API only, exactly as the
//! `engine` crate will use it.

use bencode::{ErrorKind, Limits, Value};

/// A minimal but realistic single-file torrent. Keys are in sorted order at
/// both levels, so this input is canonical.
const TORRENT: &[u8] = b"d8:announce31:http://tracker.example/announce4:infod6:lengthi1024e4:name8:test.iso12:piece lengthi16384e6:pieces20:AAAAAAAAAAAAAAAAAAAAee";

fn kind_of(input: &[u8]) -> Option<ErrorKind> {
    bencode::parse(input).err().map(|e| e.kind)
}

#[test]
fn parses_a_small_torrent() {
    let parsed = bencode::parse(TORRENT).expect("the sample torrent should parse");
    assert!(parsed.canonical);

    let root = parsed.value.as_dict().expect("root is a dict");
    assert_eq!(root.len(), 2);
    assert_eq!(
        root.get(b"announce").and_then(Value::as_bytes),
        Some(b"http://tracker.example/announce".as_slice())
    );

    let info = root.get(b"info").expect("info key is present");
    let info_dict = info.as_dict().expect("info is a dict");
    assert_eq!(info_dict.get(b"length").and_then(Value::as_int), Some(1024));
    assert_eq!(
        info_dict.get(b"piece length").and_then(Value::as_int),
        Some(16384)
    );
    assert_eq!(
        info_dict.get(b"name").and_then(Value::as_bytes),
        Some(b"test.iso".as_slice())
    );
    // 20 bytes = exactly one SHA-1 piece hash.
    assert_eq!(
        info_dict
            .get(b"pieces")
            .and_then(Value::as_bytes)
            .map(<[u8]>::len),
        Some(20)
    );
}

/// The span of `info` is the exact byte range Phase 2 will SHA-1 to get the
/// `info_hash`. Getting this wrong means every peer in the swarm rejects us.
#[test]
fn the_info_span_is_the_raw_bytes_to_hash() {
    let parsed = bencode::parse(TORRENT).expect("parses");
    let info = parsed
        .value
        .as_dict()
        .and_then(|d| d.get(b"info"))
        .expect("info key is present");

    let raw = info.span().slice(TORRENT).expect("span is inside the input");
    assert!(raw.starts_with(b"d6:length"), "{:?}", &raw.get(..16));
    assert!(raw.ends_with(b"e"));
    // Re-parsing just those bytes must give the same dictionary back.
    let again = bencode::parse(raw).expect("the info span is a complete value");
    assert_eq!(&again.value, info);
}

#[test]
fn t1_rejects_trailing_bytes() {
    // Two values in a row. Accepting this would mean a `.torrent` could smuggle
    // a second document past anything that only inspected the first.
    assert_eq!(kind_of(b"i1ei2e"), Some(ErrorKind::TrailingBytes));
    assert_eq!(kind_of(b"lei1e"), Some(ErrorKind::TrailingBytes));
    // Even a single stray byte counts.
    assert_eq!(kind_of(b"i1e\n"), Some(ErrorKind::TrailingBytes));
}

#[test]
fn t1_rejects_empty_input() {
    assert_eq!(kind_of(b""), Some(ErrorKind::UnexpectedEnd));
}

#[test]
fn t1_rejects_oversized_input() {
    let limits = Limits {
        max_input: 4,
        ..Limits::TORRENT
    };
    let err = bencode::parse_with(b"i12345e", &limits).expect_err("too large");
    assert_eq!(err.kind, ErrorKind::InputTooLarge);
    assert_eq!(err.at, 0);
    // The cap is checked BEFORE parsing starts, so an oversized file costs
    // us one length comparison and nothing else.
}

#[test]
fn tolerates_unsorted_keys_and_says_so() {
    let parsed = bencode::parse(b"d4:zzzzi1e1:ai2ee").expect("parses");
    assert!(!parsed.canonical, "unsorted keys must clear the flag");
    let d = parsed.value.as_dict().expect("is a dict");
    assert_eq!(d.get(b"a").and_then(Value::as_int), Some(2));
    assert_eq!(d.get(b"zzzz").and_then(Value::as_int), Some(1));
}

#[test]
fn a_parsed_value_borrows_from_the_caller_s_buffer() {
    // `owned` must outlive `parsed`. This test exists to document the
    // lifetime: if the two were swapped, the code would not compile.
    let owned: Vec<u8> = b"4:spam".to_vec();
    let parsed = bencode::parse(&owned).expect("parses");
    assert_eq!(parsed.value.as_bytes(), Some(b"spam".as_slice()));
}

#[test]
fn the_default_limits_are_the_torrent_limits() {
    let strict = bencode::parse(b"i1e").expect("parses");
    let explicit = bencode::parse_with(b"i1e", &Limits::TORRENT).expect("parses");
    assert_eq!(strict.value, explicit.value);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p bencode --test parse
```

Expected: a COMPILE error — `bencode::parse`, `parse_with` and `Parsed` do not
exist yet. That is the red state for this task.

- [ ] **Step 3: Write the implementation**

Add to `crates/bencode/src/lib.rs`:

```rust
/// A successfully parsed document.
#[derive(Debug, Clone)]
pub struct Parsed<'a> {
    /// The top-level value.
    pub value: Value<'a>,
    /// `false` when at least one dictionary's keys were not in ascending byte
    /// order.
    ///
    /// BEP-3 says keys must be sorted, but plenty of real torrents in the
    /// wild are not, and refusing them would make the client useless. So we
    /// accept them and record the fact — anything that needs canonical bytes
    /// (hashing, re-encoding) can then decide for itself.
    pub canonical: bool,
}

/// Parse a complete bencode document using the `.torrent` limits.
///
/// The returned value BORROWS from `input`, so `input` must outlive it.
pub fn parse(input: &[u8]) -> Result<Parsed<'_>> {
    parse_with(input, &Limits::TORRENT)
}

/// Parse a complete bencode document with caller-chosen limits.
pub fn parse_with<'a>(input: &'a [u8], limits: &Limits) -> Result<Parsed<'a>> {
    // Checked first: an oversized file costs one comparison, not a parse.
    if input.len() > limits.max_input {
        return Err(Error::new(ErrorKind::InputTooLarge, 0));
    }
    let mut parser = parser::Parser::new(input, limits);
    let value = parser.parse_value(0)?;
    // Exactly one value, and nothing after it. A parser that stopped at the
    // first complete value would let a `.torrent` carry a second, different
    // document that other tools might read instead.
    if parser.pos() != input.len() {
        return Err(Error::new(ErrorKind::TrailingBytes, parser.pos()));
    }
    Ok(Parsed {
        value,
        canonical: parser.canonical(),
    })
}
```

`lib.rs` needs `Error`, `ErrorKind`, `Limits`, `Value` in scope; they already
are through the existing `pub use` lines.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p bencode
```

Expected: `test result: ok. 43 passed` for the unit tests and
`test result: ok. 8 passed` for `tests/parse.rs`.

If `parses_a_small_torrent` fails on a length, the `TORRENT` literal has a
miscounted prefix. Check it with:

```bash
python -c "d=open('crates/bencode/tests/parse.rs','rb').read(); print(d.count(b'A'))"
```

and count the string lengths by hand: `announce` = 8, the URL = 31,
`info` = 4, `length` = 6, `name` = 4, `test.iso` = 8, `piece length` = 12,
`pieces` = 6, the hash = 20.

- [ ] **Step 5: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 5` to `docs/learn/NOTES.md`: the difference between
unit tests (inside the file, can see private things) and integration tests
(outside, see only the public API, and so prove the API is usable); why trailing
bytes are rejected; why the size cap is checked before anything else; and what
the `info` span will be used for in Phase 2. Explain the same in chat.

- [ ] **Step 7: Commit and push**

```bash
git add crates/bencode docs/learn/NOTES.md && git commit -m "feat(bencode): public parse API, input cap, trailing-byte rejection (T1)" && git push
```

---

### Task 6: Canonical encoder

**Files:**
- Create: `crates/bencode/src/encode.rs`
- Modify: `crates/bencode/src/lib.rs` (add `mod encode;` and `pub use encode::encode;`)
- Modify: `crates/bencode/tests/parse.rs` (add the round-trip tests)

**Interfaces:**
- Consumes: `Dict`, `Kind`, `Value` (Task 2); `parse` (Task 5).
- Produces: `pub fn encode(value: &Value<'_>) -> Vec<u8>`

- [ ] **Step 1: Write the failing tests**

Append to `crates/bencode/tests/parse.rs`:

```rust
#[test]
fn encodes_each_of_the_four_types() {
    for input in [
        b"i42e".as_slice(),
        b"i-7e".as_slice(),
        b"i0e".as_slice(),
        b"0:".as_slice(),
        b"4:spam".as_slice(),
        b"le".as_slice(),
        b"li1e4:spame".as_slice(),
        b"de".as_slice(),
        b"d3:cow3:mooe".as_slice(),
    ] {
        let parsed = bencode::parse(input).expect("parses");
        assert_eq!(bencode::encode(&parsed.value), input, "{input:?}");
    }
}

#[test]
fn encodes_the_extremes_of_i64() {
    for input in [
        b"i9223372036854775807e".as_slice(),
        b"i-9223372036854775808e".as_slice(),
    ] {
        let parsed = bencode::parse(input).expect("parses");
        assert_eq!(bencode::encode(&parsed.value), input);
    }
}

/// The parser TOLERATES unsorted keys; the encoder never PRODUCES them.
#[test]
fn encoding_sorts_dictionary_keys() {
    let parsed = bencode::parse(b"d4:zzzzi1e1:ai2ee").expect("parses");
    assert!(!parsed.canonical);
    let encoded = bencode::encode(&parsed.value);
    assert_eq!(encoded, b"d1:ai2e4:zzzzi1ee");
    // And the result is now canonical when read back.
    assert!(bencode::parse(&encoded).expect("re-parses").canonical);
}

#[test]
fn the_sample_torrent_round_trips_byte_for_byte() {
    let parsed = bencode::parse(TORRENT).expect("parses");
    assert_eq!(bencode::encode(&parsed.value), TORRENT);
}

/// Nested dictionaries get sorted at every level, and encoding an already
/// canonical document changes nothing.
#[test]
fn encoding_is_idempotent_at_every_level() {
    let parsed = bencode::parse(b"d4:zzzzld1:bi1e1:ai2eee1:xi3ee").expect("parses");
    assert!(!parsed.canonical);
    let once = bencode::encode(&parsed.value);
    assert_eq!(once, b"d1:xi3e4:zzzzld1:ai2e1:bi1eeee");
    let twice = bencode::encode(&bencode::parse(&once).expect("re-parses").value);
    assert_eq!(once, twice);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p bencode --test parse
```

Expected: a COMPILE error — `bencode::encode` does not exist.

- [ ] **Step 3: Write the implementation**

Create `crates/bencode/src/encode.rs`:

```rust
//! Canonical bencode encoder.
//!
//! "Canonical" means dictionary keys come out in ascending byte order, which
//! is what BEP-3 requires. The parser TOLERATES unsorted input; the encoder
//! never PRODUCES it. One meaning therefore has exactly one encoding, which is
//! what makes hashes and comparisons trustworthy.
//!
//! Recursion here is safe for the same reason as in the parser: a `Value` can
//! only be built by `crate::parse`, which caps nesting at `Limits::max_depth`.
//! If a later phase adds a way to build values by hand, that builder must
//! carry the same cap.

use crate::value::{Dict, Kind, Value};

/// Encode a value as canonical bencode.
pub fn encode(value: &Value<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut Vec<u8>, value: &Value<'_>) {
    match value.kind() {
        Kind::Int(n) => {
            out.push(b'i');
            out.extend_from_slice(n.to_string().as_bytes());
            out.push(b'e');
        }
        Kind::Bytes(bytes) => write_bytes(out, bytes),
        Kind::List(items) => {
            out.push(b'l');
            for item in items {
                write_value(out, item);
            }
            out.push(b'e');
        }
        Kind::Dict(dict) => write_dict(out, dict),
    }
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}

fn write_dict(out: &mut Vec<u8>, dict: &Dict<'_>) {
    // Sort the KEYS, not the entries: `Value` has no ordering, and does not
    // need one. Keys are unique (the parser rejects duplicates), so the sort
    // is unambiguous.
    let mut keys: Vec<&[u8]> = dict.iter().map(|(key, _)| *key).collect();
    keys.sort_unstable();
    out.push(b'd');
    for key in keys {
        if let Some(value) = dict.get(key) {
            write_bytes(out, key);
            write_value(out, value);
        }
    }
    out.push(b'e');
}
```

Add to `crates/bencode/src/lib.rs`:

```rust
mod encode;
```

and to the re-exports:

```rust
pub use encode::encode;
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p bencode
```

Expected: `test result: ok. 43 passed` (unit) and `test result: ok. 13 passed`
(`tests/parse.rs`: 8 + 5).

- [ ] **Step 5: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 6` to `docs/learn/NOTES.md`: what "canonical" means
and why one meaning must have exactly one encoding; why the encoder sorts even
though the parser does not require sorting; and why `info_hash` still uses the
raw span rather than a re-encode. Explain the same in chat.

- [ ] **Step 7: Commit and push**

```bash
git add crates/bencode docs/learn/NOTES.md && git commit -m "feat(bencode): canonical encoder" && git push
```

---

### Task 7: Property tests

**Files:**
- Modify: `crates/bencode/Cargo.toml` (add a `[dev-dependencies]` section)
- Create: `crates/bencode/tests/prop.rs`
- Modify: `deny.toml` (only if the licence check demands it)

**Interfaces:**
- Consumes: `parse`, `encode` (Tasks 5–6).
- Produces: no new API. Four property tests.

A unit test checks one example you thought of. A **property test** states a rule
that must hold for *every* input, then throws thousands of random inputs at it
and, when one fails, shrinks it down to the smallest failing case. For a parser
facing hostile input, that is exactly the right tool.

`proptest` is the first third-party dependency in this project, so this task
also re-runs the supply-chain check.

- [ ] **Step 1: Add the dev-dependency**

Append to `crates/bencode/Cargo.toml`:

```toml
# Test-only. `dev-dependencies` are never compiled into the shipped binary,
# so this does not add attack surface to the client itself — but it is still
# code we pull from the internet, so cargo-deny still screens it.
[dev-dependencies]
proptest = "1"
```

- [ ] **Step 2: Write the failing tests**

Create `crates/bencode/tests/prop.rs`:

```rust
//! Property tests (spec §7). A unit test checks one example; a property test
//! states a rule and lets the machine hunt for a counter-example.

use proptest::prelude::*;

proptest! {
    /// T1, the single most important property in this crate: whatever bytes
    /// arrive, `parse` RETURNS. It never panics, never loops forever and
    /// never runs away with memory. A `.torrent` comes from a stranger, so
    /// "returns an error" is the worst thing that may happen.
    #[test]
    fn t1_parse_never_panics_on_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = bencode::parse(&data);
    }

    /// Random bytes are almost never valid bencode, so they mostly exercise
    /// the first few lines of the parser. Drawing only from the characters
    /// bencode actually uses produces inputs that reach much deeper.
    #[test]
    fn t1_parse_never_panics_on_bencode_shaped_bytes(
        data in proptest::collection::vec(
            prop::sample::select(b"dile0123456789:-".as_slice()),
            0..512,
        )
    ) {
        let _ = bencode::parse(&data);
    }

    /// Anything we accept, we can re-encode; and our own output always parses.
    /// A parser that accepts something its encoder cannot reproduce has a
    /// hole in it.
    #[test]
    fn accepted_input_can_always_be_re_encoded(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Ok(first) = bencode::parse(&data) {
            let once = bencode::encode(&first.value);
            let second = bencode::parse(&once).expect("our own output must parse");
            prop_assert_eq!(bencode::encode(&second.value), once);
            prop_assert!(second.canonical, "our own output must be canonical");
        }
    }

    /// Canonical input survives a round trip byte for byte. This is the
    /// property `info_hash` depends on.
    #[test]
    fn canonical_input_round_trips_unchanged(
        data in proptest::collection::vec(
            prop::sample::select(b"dile0123456789:-".as_slice()),
            0..512,
        )
    ) {
        if let Ok(parsed) = bencode::parse(&data) {
            if parsed.canonical {
                prop_assert_eq!(bencode::encode(&parsed.value), data);
            }
        }
    }
}
```

- [ ] **Step 3: Run the tests**

```bash
cargo test -p bencode --test prop
```

Expected: `test result: ok. 4 passed`. Each one ran 256 generated cases.

If one FAILS, proptest prints a shrunk minimal input and writes it to
`crates/bencode/proptest-regressions/prop.txt`. **Commit that file** — it turns
the counter-example into a permanent unit test. Then fix the parser, not the
property.

- [ ] **Step 4: Re-run the supply-chain check**

```bash
cargo deny check 2>&1 | tail -20
```

Expected: `advisories ok, bans ok, licenses ok, sources ok`.

If `licenses` fails, read which crate and which licence. Add the licence to the
`allow` list in `deny.toml` **only** if it is a permissive OSI licence
(`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`,
`Unicode-3.0`, `Apache-2.0 WITH LLVM-exception`). If anything copyleft or
unknown shows up, stop and tell the user before adding it.

- [ ] **Step 5: Check lints and formatting**

```bash
cargo clippy -p bencode --all-targets -- -D warnings && cargo fmt --all --check
```

Expected: both exit 0.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 7` to `docs/learn/NOTES.md`: what a property test is
and how shrinking works; the four properties in plain words; why "never panics"
is a security property and not just a robustness one; why a dev-dependency is
lower risk than a real dependency but still gets screened. Explain the same in
chat.

- [ ] **Step 7: Commit and push**

```bash
git add crates/bencode Cargo.lock deny.toml docs/learn/NOTES.md && git commit -m "test(bencode): property tests for parse and encode (T1)" && git push
```

---

### Task 8: Fuzzing

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/parse.rs`
- Create: `fuzz/corpus/parse/{torrent,list,dict,int,string}` (seed inputs)
- Create: `fuzz/.gitignore`
- Create: `docs/FUZZING.md`
- Modify: `Cargo.toml` (root — add `exclude = ["fuzz"]`)
- Modify: `.github/workflows/ci.yml` (add the `fuzz` job)

**Interfaces:**
- Consumes: `parse`, `encode` (Tasks 5–6).
- Produces: one libFuzzer target named `parse`. No API change.

A property test throws *random* inputs at the code. A **fuzzer** watches which
branches each input reaches and mutates the inputs that reach new ones, so it
steers itself towards the code you have not covered. It is the standard way to
find parser bugs, and the spec requires it before any public release (§7).

libFuzzer needs a nightly compiler and Linux, so this runs in CI only — the
user's Windows machine is not touched.

- [ ] **Step 1: Create the fuzz crate**

Create `fuzz/Cargo.toml`:

```toml
# A SEPARATE workspace (note the empty `[workspace]` at the bottom). The fuzz
# target needs a nightly compiler and libFuzzer, neither of which should leak
# into the main build.
[package]
name = "bencode-fuzz"
version = "0.0.0"
edition = "2024"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
bencode = { path = "../crates/bencode" }

[[bin]]
name = "parse"
path = "fuzz_targets/parse.rs"
test = false
doc = false
bench = false

[workspace]
```

Create `fuzz/fuzz_targets/parse.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Reaching the end of this closure is a pass. A panic, a hang, a crash or
    // an out-of-memory is a FINDING, and libFuzzer saves the input that
    // caused it into fuzz/artifacts/parse/.
    if let Ok(parsed) = bencode::parse(data) {
        let encoded = bencode::encode(&parsed.value);
        let again = bencode::parse(&encoded).expect("our own output must parse");
        assert_eq!(
            bencode::encode(&again.value),
            encoded,
            "encoding must be stable"
        );
    }
});
```

Create `fuzz/.gitignore`:

```gitignore
target/
artifacts/
coverage/
```

Add to the root `Cargo.toml`, inside the `[workspace]` table:

```toml
exclude = ["fuzz"]
```

- [ ] **Step 2: Create the seed corpus**

The fuzzer starts from these and mutates them. Good seeds cut the time to
interesting inputs from hours to seconds.

```bash
mkdir -p fuzz/corpus/parse
printf 'i42e' > fuzz/corpus/parse/int
printf '4:spam' > fuzz/corpus/parse/string
printf 'li1e4:spamde' > fuzz/corpus/parse/list
printf 'd3:cow3:moo4:spam4:eggse' > fuzz/corpus/parse/dict
printf 'd8:announce31:http://tracker.example/announce4:infod6:lengthi1024e4:name8:test.iso12:piece lengthi16384e6:pieces20:AAAAAAAAAAAAAAAAAAAAee' > fuzz/corpus/parse/torrent
```

Note: `printf` writes no trailing newline. A trailing newline would make every
seed a `TrailingBytes` error and waste the corpus. Verify:

```bash
wc -c fuzz/corpus/parse/*
```

Expected: `int` 4, `string` 6, `list` 12, `dict` 24, `torrent` 137.

- [ ] **Step 3: Add the CI job**

Append to `.github/workflows/ci.yml`, at the same indentation as the existing
`rust`, `deny` and `secrets` jobs:

```yaml
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install a nightly compiler
        # libFuzzer's instrumentation is nightly-only. The `+nightly` below
        # overrides the stable version pinned in rust-toolchain.toml.
        run: rustup toolchain install nightly --profile minimal
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked
      - name: Fuzz the bencode parser
        # 60 seconds per push. Long campaigns are run by hand before a
        # release; see docs/FUZZING.md.
        run: cargo +nightly fuzz run parse -- -max_total_time=60 -max_len=16384
```

- [ ] **Step 4: Document it**

Create `docs/FUZZING.md`:

```markdown
# Fuzzing

Fuzzing feeds mutated inputs to a parser and watches for panics, hangs and
out-of-memory. It is the acceptance gate for every parser in this project
(spec §7). Unlike our unit and property tests, a fuzzer is *coverage-guided*:
it keeps the inputs that reach new branches and mutates those.

## Targets

| Target | Code under test | Threat |
|---|---|---|
| `parse` | `bencode::parse` + `bencode::encode` round trip | T1 |

More targets arrive with their phases: `metainfo` (T14), peer messages (T3),
tracker responses (T7), blocklist and config.

## Running it

libFuzzer needs a nightly compiler and Linux, so on Windows use WSL.

    rustup toolchain install nightly
    cargo install cargo-fuzz --locked
    cargo +nightly fuzz run parse

Stop it with Ctrl-C. A longer campaign before a release:

    cargo +nightly fuzz run parse -- -max_total_time=3600 -max_len=65536

## Corpus

`fuzz/corpus/parse/` holds committed seed inputs — one per bencode type, plus a
realistic torrent. The fuzzer adds more while it runs; those are **not**
committed, because the seeds are what make a fresh clone useful.

## Duration

| When | Duration |
|---|---|
| Every push (CI) | 60 s |
| Before a release | 1 h minimum per target, no new crashes |

## Crash triage

A finding is written to `fuzz/artifacts/parse/crash-<hash>`. Then:

1. Reproduce it: `cargo +nightly fuzz run parse fuzz/artifacts/parse/crash-<hash>`
2. Shrink it: `cargo +nightly fuzz tmin parse fuzz/artifacts/parse/crash-<hash>`
3. Turn the shrunk input into a **named unit test** in `crates/bencode`,
   using the threat id it belongs to (`t1_...`).
4. Fix the code. Never relax the property to make the crash go away.
5. Commit the test and the fix together, and record the finding in
   `docs/THREAT_MODEL.md` if it changes a status.
```

- [ ] **Step 5: Verify the target builds**

`cargo fuzz` cannot run on the user's Windows machine, but the crate must at
least be syntactically sound. Check the manifest parses and that the main
workspace is unaffected:

```bash
cargo metadata --manifest-path fuzz/Cargo.toml --no-deps --format-version 1 > /dev/null && echo "fuzz manifest ok" && cargo test --workspace 2>&1 | tail -5
```

Expected: `fuzz manifest ok`, and the workspace tests still pass unchanged.

The real verification is the CI job. After the push in Step 7, check the
Actions tab: the `fuzz` job must be green.

- [ ] **Step 6: Explain and write notes**

Append `## Phase 1 — Task 8` to `docs/learn/NOTES.md`: what a fuzzer is and how
"coverage-guided" differs from random; why it needs nightly and Linux; what a
seed corpus is for; and what happens when it finds something (shrink → named
test → fix). Explain the same in chat.

- [ ] **Step 7: Commit and push**

```bash
git add fuzz Cargo.toml .github/workflows/ci.yml docs/FUZZING.md docs/learn/NOTES.md && git commit -m "test(bencode): cargo-fuzz target, seed corpus and CI job (T1)" && git push
```

- [ ] **Step 8: Check the CI result**

Open `https://github.com/krishothaman/ironseed/actions` and confirm all four
jobs are green. If `fuzz` found a crash, follow the triage steps in
`docs/FUZZING.md` before moving on — a Phase 1 with an unresolved fuzz crash
does not pass its gate.

---

### Task 9: Threat-model update, notes and the Phase 1 gate

**Files:**
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/learn/NOTES.md`
- Modify: `docs/superpowers/plans/2026-09-24-phase-1-bencode.md` (tick the boxes, add the status line)

- [ ] **Step 1: Run the gate**

Spec §7: a phase must compile, pass its tests, get a threat review, get a commit
and get a plain-language explanation.

```bash
echo "=== BUILD ===" && cargo build --workspace 2>&1 | grep -v "hard link" | tail -3 && \
echo "=== TESTS ===" && cargo test --workspace 2>&1 | grep "test result" && \
echo "=== T1 TESTS ===" && cargo test --workspace t1_ 2>&1 | grep "test result" && \
echo "=== CLIPPY ===" && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -2 && \
echo "=== FMT ===" && cargo fmt --all --check && echo "fmt clean" && \
echo "=== DENY ===" && cargo deny check 2>&1 | tail -3
```

Every line must be clean. Record the numbers — they go in the notes.

- [ ] **Step 2: Update the threat model**

In `docs/THREAT_MODEL.md`, change the T1 row to:

```markdown
| T1 | Malicious bencode | 1 | tested | `crates/bencode`; tests `t1_*`; fuzz target `fuzz/fuzz_targets/parse.rs` |
```

Change the T5 row to record the partial credit the parse-time caps earn:

```markdown
| T5 | Resource exhaustion | 4–5 | partial | `bencode::Limits` caps input, depth and item counts; network limits are Phase 4–5 (lesson: `learn::ex05` `MAX_PEERS`) |
```

Extend the T8 evidence to mention the two new privacy behaviours:

```markdown
| T8 | Privacy / network failure | 0b, 8 | partial | `engine::redact`, tests `t8_*`; `bencode::Error` carries no input bytes; `bencode` `Debug` truncates byte strings |
```

Add a row to the **Project-wide defences** table:

```markdown
| Coverage-guided fuzzing | `fuzz/`, CI `fuzz` job | Every push runs 60 s of mutated input against the parser |
```

`tested` is claimed only because the T1 tests genuinely fail if the defence is
removed. Spot-check one: delete the `if len > self.limits.max_string` line in
`parser.rs`, run `cargo test -p bencode t1_rejects_string_longer_than_the_limit`,
watch it fail, then put the line back and watch it pass.

- [ ] **Step 3: Write the Phase 1 wrap-up notes**

Append a `# Phase 1 complete` section to `docs/learn/NOTES.md`: what exists now
(a parser the rest of the client can trust), the list of T1 controls with the
test that proves each one, the test counts from Step 1, and what Phase 2 is
(metainfo + storage, threats T2, T13, T14 — turning the parsed dictionary into a
validated `Metainfo`, computing `info_hash` from the `info` span, and writing
files to disk without letting a torrent escape the download folder).

- [ ] **Step 4: Close out the plan**

In this plan file, change every `- [ ]` to `- [x]` and add a status line
directly under the title:

```markdown
**Status: COMPLETE (YYYY-MM-DD).** All 9 tasks done; phase gate passed.
```

- [ ] **Step 5: Explain in chat**

Give the user the plain-language wrap-up: what the bencode parser is, the list
of tricks a hostile `.torrent` could try and what stops each one, and what
Phase 2 will build on top of it.

- [ ] **Step 6: Commit and push**

```bash
git add docs && git commit -m "docs: T1 tested, phase 1 learning notes and gate" && git push
```

---

## Self-review

Checked after writing, against the spec.

**Spec coverage (T1 controls, §5):**

| Spec control | Where | Test |
|---|---|---|
| input ≤ 10 MiB | `Limits::max_input`, checked in `parse_with` | `t1_rejects_oversized_input` |
| depth ≤ 64 | `Limits::max_depth`, checked in `parse_value` | `t1_rejects_deep_nesting`, `accepts_nesting_right_up_to_the_limit` |
| item count per list/dict | `Limits::max_items` | `t1_rejects_too_many_items_in_a_list`, `..._in_a_dict` |
| string length ≤ remaining input | `parse_byte_string` `.get(pos..end)` | `t1_rejects_length_beyond_input` |
| integer digits ≤ 20 | `Limits::max_int_digits` | `t1_rejects_too_many_digits` |
| no `-0` | `parse_int_digits` | `t1_rejects_negative_zero` |
| no leading zeros | `parse_int_digits`, `parse_length` | `t1_rejects_leading_zero`, `t1_rejects_length_leading_zero` |
| no empty integer | `parse_int_digits` | `t1_rejects_empty_integer` |
| duplicate keys rejected | `parse_dict` `HashSet` | `t1_rejects_duplicate_keys`, `..._hidden_by_unsorted_order` |
| unsorted keys tolerated + flagged | `Parser::canonical`, `Parsed::canonical` | `unsorted_keys_are_tolerated_but_flagged`, `tolerates_unsorted_keys_and_says_so` |
| trailing bytes rejected | `parse_with` | `t1_rejects_trailing_bytes` |
| byte span of every value | `Span` on `Value` | `the_info_span_is_the_raw_bytes_to_hash` |
| no `unsafe` | workspace lint | compile-time |
| no `unwrap`/`expect` on fallible paths | workspace lint | `cargo clippy -D warnings` |
| every length checked before allocating | `parse_byte_string`; strings are borrowed, never allocated | `t1_rejects_length_beyond_input` |
| fuzzing (§7) | `fuzz/fuzz_targets/parse.rs`, CI job | CI |
| property tests (§7) | `crates/bencode/tests/prop.rs` | 4 properties |
| no dependencies (§4.1) | zero runtime deps; `proptest` is dev-only | `cargo deny check` |

**Beyond the spec, deliberately:** `max_total_items` (10 MiB of `le` would
otherwise become millions of `Value` structs), a `HashSet` rather than a linear
scan for duplicate keys (a linear scan at 100 000 entries is itself a DoS), a
truncating `Debug` (T8), and errors that carry no input bytes (T8).

**Type consistency:** `Value`/`Kind`/`Dict`/`Span` are defined in Task 2 and used
unchanged in Tasks 3–8. `parse_value(&mut self, depth: u32)` keeps the same
signature from Task 3 to Task 4. `Parser::canonical()` is declared in Task 3 and
first returns `false` in Task 4. `parse`, `parse_with`, `Parsed` and `encode` are
defined in Tasks 5–6 and used unchanged in Tasks 7–8.

**Known gap, recorded on purpose:** there is no public way to *build* a `Value`
by hand, so `encode`'s recursion is bounded only because every `Value` came from
a bounded parse. Phase 3 needs a builder for tracker requests; when it lands, it
must carry the same depth cap. This is written in the header comment of
`encode.rs` so it cannot be missed.
