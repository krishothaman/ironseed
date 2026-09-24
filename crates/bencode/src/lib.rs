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
