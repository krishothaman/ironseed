//! ex05: errors as values. `Result<T, E>` is either Ok(T) or Err(E).
//! `?` means "if this is an error, return it right now".
//! Security lesson: trackers send peers as 6-byte chunks (4 IP + 2 port). A
//! hostile tracker can send junk lengths or millions of peers (T7).

use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug, PartialEq, Eq)]
pub enum PeerAddrError {
    MissingColon,
    BadIp,
    BadPort,
    PortZero,
    BadCompactLength,
    TooManyPeers,
}

pub const MAX_PEERS: usize = 200;

pub fn parse_port(s: &str) -> Result<u16, PeerAddrError> {
    let port: u16 = s.parse().map_err(|_| PeerAddrError::BadPort)?;
    if port == 0 {
        return Err(PeerAddrError::PortZero);
    }
    Ok(port)
}

/// Parse "1.2.3.4:6881".
pub fn parse_peer(s: &str) -> Result<SocketAddrV4, PeerAddrError> {
    let (ip_part, port_part) = s.rsplit_once(':').ok_or(PeerAddrError::MissingColon)?;
    let ip: Ipv4Addr = ip_part.parse().map_err(|_| PeerAddrError::BadIp)?;
    let port = parse_port(port_part)?;
    Ok(SocketAddrV4::new(ip, port))
}

/// Parse a tracker's compact peer list (BEP-23).
pub fn parse_compact_peers(bytes: &[u8]) -> Result<Vec<SocketAddrV4>, PeerAddrError> {
    if !bytes.len().is_multiple_of(6) {
        return Err(PeerAddrError::BadCompactLength);
    }
    let count = bytes.len() / 6;
    if count > MAX_PEERS {
        return Err(PeerAddrError::TooManyPeers);
    }
    let mut peers = Vec::with_capacity(count);
    // `as_chunks::<6>()` gives `[u8; 6]` arrays: the TYPE guarantees 6 bytes each.
    // `.0` is the full chunks; the leftover (`.1`) is empty, we checked above.
    for &[a, b, c, d, p1, p2] in bytes.as_chunks::<6>().0 {
        let port = u16::from_be_bytes([p1, p2]);
        if port == 0 {
            return Err(PeerAddrError::PortZero);
        }
        peers.push(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port));
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port() {
        assert_eq!(parse_port("6881"), Ok(6881));
    }

    #[test]
    fn rejects_bad_ports() {
        assert_eq!(parse_port("0"), Err(PeerAddrError::PortZero));
        assert_eq!(parse_port("70000"), Err(PeerAddrError::BadPort));
        assert_eq!(parse_port("abc"), Err(PeerAddrError::BadPort));
        assert_eq!(parse_port(""), Err(PeerAddrError::BadPort));
    }

    #[test]
    fn parses_peer() {
        assert_eq!(
            parse_peer("10.0.0.5:6881"),
            Ok(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 6881))
        );
    }

    #[test]
    fn peer_errors_bubble_up_through_question_mark() {
        assert_eq!(parse_peer("10.0.0.5"), Err(PeerAddrError::MissingColon));
        assert_eq!(parse_peer("999.0.0.1:80"), Err(PeerAddrError::BadIp));
        assert_eq!(parse_peer("10.0.0.5:0"), Err(PeerAddrError::PortZero));
    }

    #[test]
    fn parses_compact_peers() {
        let bytes = [127, 0, 0, 1, 0x1A, 0xE1, 10, 0, 0, 2, 0x1A, 0xE2];
        let peers = parse_compact_peers(&bytes).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers.first(),
            Some(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6881))
        );
    }

    #[test]
    fn t7_rejects_ragged_length() {
        assert_eq!(
            parse_compact_peers(&[1, 2, 3, 4, 5]),
            Err(PeerAddrError::BadCompactLength)
        );
    }

    #[test]
    fn t7_rejects_too_many_peers() {
        let bytes = vec![1u8; 6 * (MAX_PEERS + 1)];
        assert_eq!(
            parse_compact_peers(&bytes),
            Err(PeerAddrError::TooManyPeers)
        );
    }

    #[test]
    fn t7_rejects_port_zero_in_compact() {
        assert_eq!(
            parse_compact_peers(&[1, 2, 3, 4, 0, 0]),
            Err(PeerAddrError::PortZero)
        );
    }
}
