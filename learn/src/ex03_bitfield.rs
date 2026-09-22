//! ex03: which pieces does a peer have? One bit per piece (BEP-3).
//! The highest bit of byte 0 is piece 0.
//! Security lesson: use `.get()`, never `[i]`, so a bad index can't crash us.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    bytes: Vec<u8>,
    num_pieces: usize,
}

impl Bitfield {
    /// An all-zero bitfield for `num_pieces` pieces.
    pub fn new(num_pieces: usize) -> Self {
        Bitfield {
            bytes: vec![0; num_pieces.div_ceil(8)],
            num_pieces,
        }
    }

    pub fn len(&self) -> usize {
        self.num_pieces
    }

    pub fn is_empty(&self) -> bool {
        self.num_pieces == 0
    }

    /// Does the peer have piece `index`? Out of range → false.
    pub fn has(&self, index: usize) -> bool {
        if index >= self.num_pieces {
            return false;
        }
        let bit = 7 - (index % 8);
        match self.bytes.get(index / 8) {
            Some(&byte) => (byte >> bit) & 1 == 1,
            None => false,
        }
    }

    /// Mark piece `index` as present. Returns false (and changes nothing) if out of range.
    pub fn set(&mut self, index: usize) -> bool {
        if index >= self.num_pieces {
            return false;
        }
        let bit = 7 - (index % 8);
        match self.bytes.get_mut(index / 8) {
            Some(byte) => {
                *byte |= 1 << bit;
                true
            }
            None => false,
        }
    }

    /// How many pieces are present.
    pub fn count(&self) -> usize {
        self.bytes.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Build from bytes a peer sent. Takes ownership of `bytes`, so nothing is copied.
    /// Rejects the wrong length, or spare bits that aren't zero (BEP-3 says they must be).
    pub fn from_bytes(bytes: Vec<u8>, num_pieces: usize) -> Option<Self> {
        if bytes.len() != num_pieces.div_ceil(8) {
            return None;
        }
        let bf = Bitfield { bytes, num_pieces };
        let spare_bits_set = bf.count() != (0..num_pieces).filter(|&i| bf.has(i)).count();
        if spare_bits_set {
            return None;
        }
        Some(bf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty_of_pieces() {
        let bf = Bitfield::new(10);
        assert_eq!(bf.len(), 10);
        assert_eq!(bf.count(), 0);
        assert!(!bf.has(0));
    }

    #[test]
    fn set_then_has() {
        let mut bf = Bitfield::new(10);
        assert!(bf.set(9));
        assert!(bf.has(9));
        assert!(!bf.has(8));
        assert_eq!(bf.count(), 1);
    }

    #[test]
    fn bit_order_is_high_bit_first() {
        let mut bf = Bitfield::new(8);
        bf.set(0);
        assert_eq!(bf.bytes, vec![0b1000_0000]);
    }

    #[test]
    fn t3_out_of_range_is_safe() {
        let mut bf = Bitfield::new(10);
        assert!(!bf.has(10));
        assert!(!bf.has(usize::MAX));
        assert!(!bf.set(10));
        assert_eq!(bf.count(), 0);
    }

    #[test]
    fn from_bytes_accepts_valid() {
        let bf = Bitfield::from_bytes(vec![0b1100_0000, 0b0100_0000], 10).unwrap();
        assert!(bf.has(0) && bf.has(1) && bf.has(9));
        assert_eq!(bf.count(), 3);
    }

    #[test]
    fn t3_from_bytes_rejects_wrong_length() {
        assert_eq!(Bitfield::from_bytes(vec![0], 10), None);
        assert_eq!(Bitfield::from_bytes(vec![0, 0, 0], 10), None);
    }

    #[test]
    fn t3_from_bytes_rejects_spare_bits() {
        // 10 pieces → 16 bits, so the last 6 bits are spare and must be zero.
        assert_eq!(Bitfield::from_bytes(vec![0, 0b0010_0000], 10), None);
    }
}
