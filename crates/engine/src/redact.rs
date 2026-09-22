//! Log redaction (spec T8). Sensitive values (peer IPs, torrent names, tracker
//! URLs) are logged ONLY through `LogPolicy::redact`, which prints `[redacted]`
//! unless the user explicitly turned on diagnostic logging.

use std::fmt;

const MASK: &str = "[redacted]";

/// Default: diagnostics OFF, so sensitive values are hidden.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogPolicy {
    pub diagnostics: bool,
}

pub struct Redacted<'a, T: ?Sized> {
    value: &'a T,
    reveal: bool,
}

impl LogPolicy {
    pub fn redact<'a, T: ?Sized>(&self, value: &'a T) -> Redacted<'a, T> {
        Redacted {
            value,
            reveal: self.diagnostics,
        }
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for Redacted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reveal {
            fmt::Display::fmt(self.value, f)
        } else {
            f.write_str(MASK)
        }
    }
}

impl<T: fmt::Debug + ?Sized> fmt::Debug for Redacted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reveal {
            fmt::Debug::fmt(self.value, f)
        } else {
            f.write_str(MASK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn t8_default_policy_hides_ip() {
        let policy = LogPolicy::default();
        assert_eq!(format!("peer {}", policy.redact(&IP)), "peer [redacted]");
    }

    #[test]
    fn t8_default_policy_hides_debug_output_too() {
        let policy = LogPolicy::default();
        assert_eq!(
            format!("{:?}", policy.redact("secret-name.iso")),
            "[redacted]"
        );
    }

    #[test]
    fn t8_diagnostics_reveals() {
        let policy = LogPolicy { diagnostics: true };
        assert_eq!(policy.redact(&IP).to_string(), "203.0.113.7");
        assert_eq!(format!("{:?}", policy.redact("a.iso")), "\"a.iso\"");
    }
}
