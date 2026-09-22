//! ex02: a few BEP-3 peer messages as a Rust enum.
//! Security lesson: every message type has an EXACT payload size (threat T3).
//! Anything else is rejected, not guessed at.

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have { piece_index: u32 },
}

impl Message {
    /// The ID byte sent on the wire. KeepAlive has no ID (it's an empty frame).
    pub fn id(&self) -> Option<u8> {
        match self {
            Message::KeepAlive => None,
            Message::Choke => Some(0),
            Message::Unchoke => Some(1),
            Message::Interested => Some(2),
            Message::NotInterested => Some(3),
            Message::Have { .. } => Some(4),
        }
    }
}

/// Decode an ID byte plus payload. Unknown ID or wrong size → `None`, never a crash.
pub fn from_wire(id: u8, payload: &[u8]) -> Option<Message> {
    match (id, payload) {
        (0, []) => Some(Message::Choke),
        (1, []) => Some(Message::Unchoke),
        (2, []) => Some(Message::Interested),
        (3, []) => Some(Message::NotInterested),
        (4, [a, b, c, d]) => Some(Message::Have {
            piece_index: u32::from_be_bytes([*a, *b, *c, *d]),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_bep3() {
        assert_eq!(Message::KeepAlive.id(), None);
        assert_eq!(Message::Choke.id(), Some(0));
        assert_eq!(Message::Unchoke.id(), Some(1));
        assert_eq!(Message::Interested.id(), Some(2));
        assert_eq!(Message::NotInterested.id(), Some(3));
        assert_eq!(Message::Have { piece_index: 7 }.id(), Some(4));
    }

    #[test]
    fn decodes_simple_messages() {
        assert_eq!(from_wire(0, &[]), Some(Message::Choke));
        assert_eq!(from_wire(2, &[]), Some(Message::Interested));
    }

    #[test]
    fn decodes_have_big_endian() {
        assert_eq!(
            from_wire(4, &[0, 0, 1, 2]),
            Some(Message::Have { piece_index: 258 })
        );
    }

    #[test]
    fn t3_rejects_have_with_wrong_length() {
        assert_eq!(from_wire(4, &[0, 0, 1]), None);
        assert_eq!(from_wire(4, &[0, 0, 0, 1, 9]), None);
    }

    #[test]
    fn t3_rejects_payload_on_choke() {
        assert_eq!(from_wire(0, &[1]), None);
    }

    #[test]
    fn t3_rejects_unknown_id() {
        assert_eq!(from_wire(99, &[]), None);
    }
}
