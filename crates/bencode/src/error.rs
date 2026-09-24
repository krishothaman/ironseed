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
        write!(
            f,
            "bencode error at byte {}: {}",
            self.at,
            self.kind.message()
        )
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
