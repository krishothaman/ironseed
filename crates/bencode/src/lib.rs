//! Bounded, hardened bencode parser and encoder (spec T1).
//!
//! Everything in a `.torrent` file arrives from a stranger, and this crate is
//! the first code that looks at it. So the rules here are strict: no panics,
//! no unbounded allocation, no recursion without a cap, and no copying of the
//! input.

mod error;
mod limits;
// Private: the cursor is an implementation detail. Nothing outside this crate
// calls it until `parse()` wraps it in Task 5.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into parse() in Task 5"))]
mod parser;
mod value;

pub use error::{Error, ErrorKind, Result};
pub use limits::Limits;
pub use value::{Dict, Kind, Span, Value};
