//! Time formatting and random identifiers.
//!
//! The gateway has no third-party date library: the values it needs are
//! RFC 3339 timestamps derived from a Unix epoch and unpredictable opaque
//! identifiers, and both are small enough to implement exactly.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Seconds since the Unix epoch.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as an RFC 3339 UTC timestamp.
pub fn format_rfc3339(epoch_seconds: u64) -> String {
    let days = (epoch_seconds / 86_400) as i64;
    let seconds_of_day = epoch_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse an RFC 3339 timestamp into a Unix timestamp.
///
/// Only the UTC `Z` form and whole seconds are accepted, which is what the
/// upstream date headers and the gateway's own timestamps use. Anything else
/// is reported as unknown rather than guessed at.
pub fn parse_rfc3339(value: &str) -> Option<u64> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z' {
        return None;
    }
    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: i64 = value.get(5..7)?.parse().ok()?;
    let day: i64 = value.get(8..10)?.parse().ok()?;
    let hour: i64 = value.get(11..13)?.parse().ok()?;
    let minute: i64 = value.get(14..16)?.parse().ok()?;
    let second: i64 = value.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let total = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(total).ok()
}

/// Days since the Unix epoch to a civil year, month and day.
///
/// This is Howard Hinnant's `civil_from_days`, which is exact for the whole
/// range of dates a mailbox can hold.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A civil year, month and day to days since the Unix epoch.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Random bytes from the operating system.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0_u8; len];
    if getrandom::fill(&mut buffer).is_err() {
        // A gateway that cannot read random bytes cannot mint unpredictable
        // identifiers, and an unpredictable identifier is the difference
        // between an opaque cursor and a guessable one. Failing loudly is
        // better than minting a predictable one.
        panic!("the operating system did not provide random bytes");
    }
    buffer
}

/// An opaque, URL-safe identifier.
///
/// The value carries no timestamp and no counter, so two identifiers minted
/// in the same second cannot be told apart by shape.
pub fn random_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(16))
}

/// An opaque, URL-safe identifier of `len` random bytes.
pub fn random_id_of(len: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn formats_a_known_instant() {
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn round_trips_timestamps() {
        for epoch in [0_u64, 1, 1_700_000_000, 2_000_000_000] {
            let text = format_rfc3339(epoch);
            assert_eq!(parse_rfc3339(&text), Some(epoch));
        }
    }

    #[test]
    fn rejects_malformed_timestamps() {
        assert_eq!(parse_rfc3339("2023-11-14"), None);
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20"), None);
        assert_eq!(parse_rfc3339("2023-13-14T22:13:20Z"), None);
        assert_eq!(parse_rfc3339("not a date at all!"), None);
    }

    #[test]
    fn identifiers_do_not_repeat() {
        let first = random_id();
        let second = random_id();
        assert_ne!(first, second);
        assert!(first.len() >= 20);
    }
}
