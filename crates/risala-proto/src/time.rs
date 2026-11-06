//! Timestamps (SPEC 3.5): the value of the `t` tag (3.2) and of `<since>` in
//! CONNECTION lines (10.3).
//!
//! The wire form is RFC 3339 in UTC with exactly three fractional digits,
//! `YYYY-MM-DDTHH:MM:SS.mmmZ`, for example `2026-11-06T15:40:58.120Z`.
//! The calendar arithmetic is written out here (proleptic Gregorian, after
//! Howard Hinnant's `days_from_civil`), so the crate needs no date library.

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::ParseError;

const MS_PER_DAY: u64 = 86_400_000;

/// A point in time with millisecond precision, the `timestamp` of 3.5.
///
/// It is stored as milliseconds since the Unix epoch. The range is
/// 1970-01-01T00:00:00.000Z to 9999-12-31T23:59:59.999Z: nothing in the
/// protocol predates 1970, and the format has four digits for the year.
///
/// Parsing is strict:
///
/// - exactly `YYYY-MM-DDTHH:MM:SS.mmmZ`, with no other offset and no more
///   or fewer fractional digits
/// - real dates only, so February 30 and month 13 are rejected
/// - no leap seconds: a second of `60` is rejected. Unix time has no leap
///   seconds, and a server that stamps events from the system clock never
///   produces one. Accepting `:60` would make two strings mean the same
///   instant and break round trips.
///
/// The `T` and `Z` may also be written in lower case, since ABNF string
/// literals are case-insensitive (RFC 5234 2.3). `Display` always writes
/// upper case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The earliest timestamp, 1970-01-01T00:00:00.000Z.
    pub const MIN: Timestamp = Timestamp(0);
    /// The latest timestamp, 9999-12-31T23:59:59.999Z.
    pub const MAX: Timestamp = Timestamp(253_402_300_799_999);

    /// The timestamp `ms` milliseconds after the Unix epoch, or `None` if
    /// that is after [`Timestamp::MAX`] (3.5).
    pub const fn from_unix_millis(ms: u64) -> Option<Timestamp> {
        if ms <= Timestamp::MAX.0 {
            Some(Timestamp(ms))
        } else {
            None
        }
    }

    /// Milliseconds since the Unix epoch (3.5).
    pub const fn unix_millis(self) -> u64 {
        self.0
    }

    /// The current time from the system clock, cut to whole milliseconds,
    /// as a server stamps the `t` tag (3.2).
    /// A clock set before 1970 or after 9999 gives the nearest end of the
    /// range.
    pub fn now() -> Timestamp {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp::from_duration(d).unwrap_or(Timestamp::MAX),
            Err(_) => Timestamp::MIN,
        }
    }

    /// Converts a [`SystemTime`], cut to whole milliseconds. `None` if it is
    /// outside the range (3.5).
    pub fn from_system_time(t: SystemTime) -> Option<Timestamp> {
        Timestamp::from_duration(t.duration_since(UNIX_EPOCH).ok()?)
    }

    /// Converts to a [`SystemTime`] (3.5).
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.0)
    }

    /// `self + d`, cut to whole milliseconds, or `None` past the range (3.5).
    pub fn checked_add(self, d: Duration) -> Option<Timestamp> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        Timestamp::from_unix_millis(self.0.checked_add(ms)?)
    }

    /// `self - d`, cut to whole milliseconds, or `None` before 1970. Useful
    /// for windows such as the 24 hours of 7.6 or retention (7.5).
    pub fn checked_sub(self, d: Duration) -> Option<Timestamp> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_sub(ms).map(Timestamp)
    }

    /// How long after `earlier` this is, or zero if it is not later (3.5).
    pub fn saturating_duration_since(self, earlier: Timestamp) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    fn from_duration(d: Duration) -> Option<Timestamp> {
        Timestamp::from_unix_millis(u64::try_from(d.as_millis()).ok()?)
    }
}

/// Days from 1970-01-01 to the given proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date `days` days after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Both fit easily: days < 2^22 and ms < 2^27.
        let days = (self.0 / MS_PER_DAY) as i64;
        let ms = self.0 % MS_PER_DAY;
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
            ms / 3_600_000,
            ms / 60_000 % 60,
            ms / 1000 % 60,
            ms % 1000,
        )
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Timestamp, ParseError> {
        const BAD: ParseError = ParseError::BadSyntax("a timestamp is YYYY-MM-DDTHH:MM:SS.mmmZ");
        let b = s.as_bytes();
        if b.len() != 24
            || b[4] != b'-'
            || b[7] != b'-'
            || !matches!(b[10], b'T' | b't')
            || b[13] != b':'
            || b[16] != b':'
            || b[19] != b'.'
            || !matches!(b[23], b'Z' | b'z')
        {
            return Err(BAD);
        }
        let num = |range: std::ops::Range<usize>| -> Result<i64, ParseError> {
            b[range].iter().try_fold(0i64, |n, &d| {
                if d.is_ascii_digit() {
                    Ok(n * 10 + i64::from(d - b'0'))
                } else {
                    Err(BAD)
                }
            })
        };
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second, milli) =
            (num(11..13)?, num(14..16)?, num(17..19)?, num(20..23)?);

        if year < 1970 {
            return Err(ParseError::BadSyntax("timestamp is before 1970"));
        }
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return Err(ParseError::BadSyntax("timestamp has an invalid date"));
        }
        if hour > 23 || minute > 59 || second > 59 {
            return Err(ParseError::BadSyntax("timestamp has an invalid time"));
        }
        let days = days_from_civil(year, month, day);
        let ms = ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + milli;
        // Non-negative and within MAX, given the checks above.
        Ok(Timestamp(ms as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn spec_examples() {
        for s in [
            "2026-11-06T15:40:58.120Z",
            "2026-11-06T15:41:02.377Z",
            "2026-10-02T09:12:40.118Z",
            "2026-11-06T15:44:10.230Z",
        ] {
            assert_eq!(ts(s).to_string(), s);
        }
        assert_eq!(
            ts("2026-11-06T15:40:58.120Z").unix_millis(),
            1_793_979_658_120
        );
    }

    #[test]
    fn epoch_and_limits() {
        assert_eq!(ts("1970-01-01T00:00:00.000Z"), Timestamp::MIN);
        assert_eq!(Timestamp::MIN.to_string(), "1970-01-01T00:00:00.000Z");
        assert_eq!(ts("9999-12-31T23:59:59.999Z"), Timestamp::MAX);
        assert_eq!(Timestamp::MAX.to_string(), "9999-12-31T23:59:59.999Z");
        assert_eq!(
            Timestamp::from_unix_millis(Timestamp::MAX.unix_millis() + 1),
            None
        );
        assert_eq!(Timestamp::from_unix_millis(0), Some(Timestamp::MIN));
        assert_eq!(ts("1970-01-01T00:00:00.001Z").unix_millis(), 1);
        assert_eq!(ts("1970-01-02T00:00:00.000Z").unix_millis(), MS_PER_DAY);
    }

    #[test]
    fn known_instants() {
        // Values checked against `date -u -d @<secs>`.
        assert_eq!(
            ts("2000-02-29T12:00:00.000Z").unix_millis(),
            951_825_600_000
        );
        assert_eq!(
            ts("2038-01-19T03:14:07.000Z").unix_millis(),
            2_147_483_647_000
        );
        assert_eq!(
            ts("2100-03-01T00:00:00.000Z").unix_millis(),
            4_107_542_400_000
        );
        assert_eq!(
            ts("2024-12-31T23:59:59.999Z").unix_millis(),
            1_735_689_599_999
        );
    }

    #[test]
    fn leap_years() {
        assert!(ts("2024-02-29T00:00:00.000Z") < ts("2024-03-01T00:00:00.000Z"));
        ts("2000-02-29T00:00:00.000Z");
        ts("2400-02-29T00:00:00.000Z");
        for s in [
            "2023-02-29T00:00:00.000Z",
            "1900-02-29T00:00:00.000Z",
            "2100-02-29T00:00:00.000Z",
        ] {
            assert!(s.parse::<Timestamp>().is_err(), "{s}");
        }
    }

    #[test]
    fn every_day_round_trips() {
        // Walk day by day across leap years and a century boundary.
        let start = ts("1999-12-01T00:00:00.000Z").unix_millis();
        let mut prev = None;
        for day in 0..(366 * 6) {
            let t = Timestamp::from_unix_millis(start + day * MS_PER_DAY + 45_296_789).unwrap();
            let s = t.to_string();
            assert!(s.ends_with("T12:34:56.789Z"), "{s}");
            assert_eq!(ts(&s), t);
            if let Some(prev) = prev {
                assert!(s > prev);
            }
            prev = Some(s);
        }
    }

    #[test]
    fn civil_conversions_agree() {
        for days in (0..2_932_897).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert!((1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m));
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(days_from_civil(10_000, 1, 1), 2_932_897);
    }

    #[test]
    fn rejects() {
        for s in [
            "",
            "2026-11-06T15:40:58Z",
            "2026-11-06T15:40:58.12Z",
            "2026-11-06T15:40:58.1200Z",
            "2026-11-06T15:40:58.120",
            "2026-11-06T15:40:58.120+00:00",
            "2026-11-06 15:40:58.120Z",
            "2026-11-06T15:40:58,120Z",
            "2026-11-6T15:40:58.120Z",
            "26-11-06T15:40:58.120Z",
            "+2026-11-06T15:40:58.120Z",
            "2026-13-06T15:40:58.120Z",
            "2026-00-06T15:40:58.120Z",
            "2026-11-00T15:40:58.120Z",
            "2026-11-31T15:40:58.120Z",
            "2026-02-30T15:40:58.120Z",
            "2026-04-31T00:00:00.000Z",
            "2026-11-06T24:00:00.000Z",
            "2026-11-06T23:60:00.000Z",
            "2016-12-31T23:59:60.000Z",
            "2026-11-06T15:40:58.12aZ",
            "2026-11-06T15:4-:58.120Z",
            "1969-12-31T23:59:59.999Z",
            "0000-01-01T00:00:00.000Z",
            "２026-11-06T15:40:58.120Z",
            " 2026-11-06T15:40:58.120Z",
        ] {
            assert!(
                matches!(s.parse::<Timestamp>(), Err(ParseError::BadSyntax(_))),
                "{s:?}"
            );
        }
    }

    #[test]
    fn lower_case_t_and_z() {
        let t = ts("2026-11-06t15:40:58.120z");
        assert_eq!(t.to_string(), "2026-11-06T15:40:58.120Z");
    }

    #[test]
    fn arithmetic() {
        let t = ts("2026-11-06T15:40:58.120Z");
        let day = Duration::from_secs(86_400);
        assert_eq!(
            t.checked_add(day).unwrap().to_string(),
            "2026-11-07T15:40:58.120Z"
        );
        assert_eq!(
            t.checked_sub(day).unwrap().to_string(),
            "2026-11-05T15:40:58.120Z"
        );
        assert_eq!(
            t.checked_add(day).unwrap().saturating_duration_since(t),
            day
        );
        assert_eq!(
            t.saturating_duration_since(t.checked_add(day).unwrap()),
            Duration::ZERO
        );
        assert_eq!(Timestamp::MIN.checked_sub(Duration::from_millis(1)), None);
        assert_eq!(Timestamp::MAX.checked_add(Duration::from_millis(1)), None);
        assert_eq!(Timestamp::MIN.checked_add(Duration::MAX), None);
    }

    #[test]
    fn system_time() {
        let t = ts("2026-11-06T15:40:58.120Z");
        assert_eq!(Timestamp::from_system_time(t.to_system_time()), Some(t));
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(Timestamp::from_system_time(before), None);
        let now = Timestamp::now();
        assert!(now > Timestamp::MIN);
        assert_eq!(ts(&now.to_string()), now);
    }
}
