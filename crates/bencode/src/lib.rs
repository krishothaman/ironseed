//! Bounded, hardened bencode parser and encoder (spec T1).
//!
//! Everything in a `.torrent` file arrives from a stranger, and this crate is
//! the first code that looks at it. So the rules here are strict: no panics,
//! no unbounded allocation, no recursion without a cap, and no copying of the
//! input.

mod error;
mod limits;
// Private: the cursor is an implementation detail behind `parse()`.
mod parser;
mod value;

pub use error::{Error, ErrorKind, Result};
pub use limits::Limits;
pub use value::{Dict, Kind, Span, Value};

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
