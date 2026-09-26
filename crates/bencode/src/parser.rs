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
use crate::value::{Kind, Span, Value};

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

    /// `i<digits>e`. Called with `pos` on the `i`.
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

    /// `<len>:<bytes>`. Called with `pos` on the first digit.
    /// Returns the borrowed bytes and the span covering `<len>:<bytes>`.
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

    fn parse_bytes(&mut self) -> Result<Value<'a>> {
        let (bytes, span) = self.parse_byte_string()?;
        Ok(Value::new(Kind::Bytes(bytes), span))
    }

    /// Parse one value. `depth` is how many containers we are inside.
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
}

/// Turn the digits between `i` and `e` into an `i64`, strictly.
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

/// Turn the digits before `:` into a length, strictly.
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
        assert_eq!(
            one(b"0:").map(|(v, _)| v.as_bytes()).ok(),
            Some(Some(b"".as_slice()))
        );
        let raw = b"2:\xff\xfe";
        assert_eq!(
            one(raw).map(|(v, _)| v.as_bytes()).ok(),
            Some(Some(b"\xff\xfe".as_slice()))
        );
    }

    /// Only dictionaries can be out of order, so integers and strings must
    /// never clear the flag.
    #[test]
    fn scalars_never_clear_the_canonical_flag() {
        let limits = Limits::TORRENT;
        let mut p = Parser::new(b"4:spam", &limits);
        assert!(p.parse_value(0).is_ok());
        assert!(p.canonical());
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
        assert_eq!(
            kind_of(b"i123456789012345678901e"),
            Some(ErrorKind::IntTooManyDigits)
        );
    }

    #[test]
    fn t1_rejects_integer_overflow() {
        // 19 digits, under the digit cap, but one past i64::MAX. The digit
        // cap alone is NOT enough; the checked arithmetic is what catches it.
        assert_eq!(
            kind_of(b"i9223372036854775808e"),
            Some(ErrorKind::IntOverflow)
        );
        assert_eq!(
            kind_of(b"i-9223372036854775809e"),
            Some(ErrorKind::IntOverflow)
        );
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
        assert_eq!(
            kind_of(b"99999999999999999999:a"),
            Some(ErrorKind::LengthOverflow)
        );
    }

    #[test]
    fn t1_rejects_string_longer_than_the_limit() {
        let limits = Limits {
            max_string: 2,
            ..Limits::TORRENT
        };
        let mut p = Parser::new(b"4:spam", &limits);
        assert_eq!(
            p.parse_value(0).map(|_| ()),
            Err(Error::new(ErrorKind::StringTooLong, 0))
        );
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
