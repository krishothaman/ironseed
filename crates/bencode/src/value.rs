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
        self.kind == other.kind
    }
}

impl Eq for Value<'_> {}

impl<'a> Value<'a> {
    pub(crate) fn new(kind: Kind<'a>, span: Span) -> Self {
        Value { kind, span }
    }

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
    pub(crate) fn new() -> Self {
        Dict {
            entries: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, key: &'a [u8], value: Value<'a>) {
        self.entries.push((key, value));
    }

    /// The key most recently pushed. The parser uses it to notice unsorted keys.
    pub(crate) fn last_key(&self) -> Option<&'a [u8]> {
        self.entries.last().map(|(k, _)| *k)
    }

    /// Dictionaries in a torrent hold a handful of entries, so a linear scan
    /// beats hashing and costs no allocation.
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

/// How many bytes of a byte string `Debug` will print.
const DEBUG_BYTES_SHOWN: usize = 16;

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
        let b = Value::new(
            Kind::Int(7),
            Span {
                start: 99,
                end: 102,
            },
        );
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
