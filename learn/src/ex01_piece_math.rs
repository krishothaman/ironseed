//! ex01: how many pieces, how long is the last one, where does piece N start?
//! Security lesson: never trust sizes, and never let arithmetic overflow silently.

/// Number of pieces for `total_len` bytes split into `piece_len`-byte pieces.
/// `None` if `piece_len` is 0 (division by zero would crash).
pub fn piece_count(total_len: u64, piece_len: u64) -> Option<u64> {
    if piece_len == 0 {
        return None;
    }
    Some(total_len.div_ceil(piece_len))
}

/// Length of the final piece (it's usually shorter). `None` for nonsense input.
pub fn last_piece_len(total_len: u64, piece_len: u64) -> Option<u64> {
    if piece_len == 0 || total_len == 0 {
        return None;
    }
    match total_len % piece_len {
        0 => Some(piece_len),
        rem => Some(rem),
    }
}

/// Byte offset where piece `index` starts. `None` if the multiplication overflows.
pub fn piece_offset(index: u64, piece_len: u64) -> Option<u64> {
    index.checked_mul(piece_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_exact_fit() {
        assert_eq!(piece_count(1024, 256), Some(4));
    }

    #[test]
    fn count_partial_last_piece() {
        assert_eq!(piece_count(1000, 256), Some(4));
    }

    #[test]
    fn t14_count_rejects_zero_piece_len() {
        assert_eq!(piece_count(1000, 0), None);
    }

    #[test]
    fn last_piece_partial() {
        assert_eq!(last_piece_len(1000, 256), Some(232));
    }

    #[test]
    fn last_piece_full() {
        assert_eq!(last_piece_len(1024, 256), Some(256));
    }

    #[test]
    fn last_piece_rejects_empty_or_zero() {
        assert_eq!(last_piece_len(0, 256), None);
        assert_eq!(last_piece_len(1000, 0), None);
    }

    #[test]
    fn offset_normal() {
        assert_eq!(piece_offset(3, 256), Some(768));
    }

    #[test]
    fn t14_offset_overflow_is_caught() {
        assert_eq!(piece_offset(u64::MAX, 2), None);
    }
}
