//! Dates and UTC instants as text, over the wire's whole range.
//!
//! The wire admits years -262143 to 262142 (see
//! [`MIN_DATE_DAYS`]), and
//! JavaScript values reach all of it, so the binding cannot use a date
//! library with a narrower range: jiff stops at ±9999. This is the
//! proleptic Gregorian calendar, by Howard Hinnant's `days_from_civil` and
//! `civil_from_days`, and the two text forms the binding reads and writes:
//!
//! - a date, `YYYY-MM-DD`, with the year as four digits from 0000 to 9999
//!   and otherwise signed and at least four digits (`-0005`, `+12000`);
//! - an instant, RFC 3339 (`2024-02-29T12:00:00.5Z`, `+01:00`), or the
//!   same with an expanded year as above. A leap second has no count and
//!   is refused, as the leaf codec refuses it.

use std::fmt;

use vitaminc_aead::plaintext::kinds::{
    MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS, MIN_DATE_DAYS, MIN_TIMESTAMP_NANOS,
};

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
/// More digits than any year in the wire's range, so a year that parses
/// cannot overflow before the range check.
const MAX_YEAR_DIGITS: usize = 9;

/// A day of the proleptic Gregorian calendar, within the wire's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Date {
    year: i64,
    month: u8,
    day: u8,
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Date {
    /// The date, if it is one and lies within the wire's range.
    pub(crate) fn new(year: i64, month: u8, day: u8) -> Option<Self> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        let date = Self { year, month, day };
        (i64::from(MIN_DATE_DAYS)..=i64::from(MAX_DATE_DAYS))
            .contains(&date.days())
            .then_some(date)
    }

    /// The date `days` after 1970-01-01, if it lies within the wire's range.
    pub(crate) fn from_days(days: i64) -> Option<Self> {
        if !(i64::from(MIN_DATE_DAYS)..=i64::from(MAX_DATE_DAYS)).contains(&days) {
            return None;
        }
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let day_of_era = z - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        Some(Self {
            year,
            month: u8::try_from(month).ok()?,
            day: u8::try_from(day).ok()?,
        })
    }

    /// Days since 1970-01-01.
    pub(crate) fn days(self) -> i64 {
        let (month, day) = (i64::from(self.month), i64::from(self.day));
        let year = if month <= 2 { self.year - 1 } else { self.year };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// `YYYY-MM-DD`, exactly as [`Display`](fmt::Display) writes it.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (date, rest) = Self::parse_prefix(text)?;
        rest.is_empty().then_some(date)
    }

    /// A date at the start of `text`, and what follows it. Any year width
    /// is read; [`Date::parse`] is what holds it to the canonical form.
    fn parse_prefix(text: &str) -> Option<(Self, &str)> {
        let (negative, unsigned) = match text.as_bytes().first()? {
            b'+' => (false, &text[1..]),
            b'-' => (true, &text[1..]),
            _ => (false, text),
        };
        let digits = unsigned.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > MAX_YEAR_DIGITS {
            return None;
        }
        let (year, rest) = unsigned.split_at(digits);
        let year: i64 = year.parse().ok()?;
        let rest = rest.strip_prefix('-')?;
        let (month, rest) = two_digits(rest)?;
        let rest = rest.strip_prefix('-')?;
        let (day, rest) = two_digits(rest)?;
        let date = Self::new(if negative { -year } else { year }, month, day)?;
        Some((date, rest))
    }
}

/// Four digits from 0000 to 9999, otherwise signed and at least four.
impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if (0..=9999).contains(&self.year) {
            write!(f, "{:04}", self.year)?;
        } else {
            write!(f, "{:+05}", self.year)?;
        }
        write!(f, "-{:02}-{:02}", self.month, self.day)
    }
}

/// Exactly two ASCII digits at the start of `text`, and what follows.
fn two_digits(text: &str) -> Option<(u8, &str)> {
    let (digits, rest) = text.split_at_checked(2)?;
    let [tens, ones] = digits.as_bytes() else {
        return None;
    };
    (tens.is_ascii_digit() && ones.is_ascii_digit())
        .then(|| ((tens - b'0') * 10 + (ones - b'0'), rest))
}

/// An instant as RFC 3339 text, or the same with an expanded year, as
/// nanoseconds since the epoch, if it lies within the wire's range.
/// Fractional seconds past the ninth digit are read and dropped. A leap
/// second has no count and is refused.
pub(crate) fn parse_timestamp(text: &str) -> Option<i128> {
    let expanded = text.starts_with(['+', '-']);
    let (date, rest) = Date::parse_prefix(text)?;
    if !expanded && text.find('-') != Some(4) {
        // RFC 3339 spells a year in exactly four digits.
        return None;
    }
    let rest = match rest.as_bytes().first()? {
        b'T' => &rest[1..],
        b't' | b' ' if !expanded => &rest[1..],
        _ => return None,
    };
    let (hour, rest) = two_digits(rest)?;
    let rest = rest.strip_prefix(':')?;
    let (minute, rest) = two_digits(rest)?;
    let rest = rest.strip_prefix(':')?;
    let (second, rest) = two_digits(rest)?;
    // 60 is a leap second, which has no count.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let (nanos, rest) = match rest.strip_prefix('.') {
        Some(fraction) => {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return None;
            }
            let kept = &fraction[..digits.min(9)];
            let scale = 10i128.pow(9 - u32::try_from(kept.len()).ok()?);
            (kept.parse::<i128>().ok()? * scale, &fraction[digits..])
        }
        None => (0, rest),
    };
    let offset_seconds = match rest {
        "Z" | "z" => 0,
        _ => {
            let (sign, rest) = match rest.as_bytes().first()? {
                b'+' => (1, &rest[1..]),
                b'-' => (-1, &rest[1..]),
                _ => return None,
            };
            let (hours, rest) = two_digits(rest)?;
            let rest = rest.strip_prefix(':')?;
            let (minutes, rest) = two_digits(rest)?;
            if !rest.is_empty() || hours > 23 || minutes > 59 {
                return None;
            }
            sign * (i64::from(hours) * 3_600 + i64::from(minutes) * 60)
        }
    };
    let seconds = date.days() * SECONDS_PER_DAY
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second)
        - offset_seconds;
    let total = i128::from(seconds) * NANOS_PER_SECOND + nanos;
    (MIN_TIMESTAMP_NANOS..=MAX_TIMESTAMP_NANOS)
        .contains(&total)
        .then_some(total)
}

/// Nanoseconds since the epoch as RFC 3339 text in UTC with nine
/// fractional digits, the year expanded outside 0000 to 9999, if the count
/// lies within the wire's range.
pub(crate) fn timestamp_text(nanos: i128) -> Option<String> {
    if !(MIN_TIMESTAMP_NANOS..=MAX_TIMESTAMP_NANOS).contains(&nanos) {
        return None;
    }
    let seconds = i64::try_from(nanos.div_euclid(NANOS_PER_SECOND)).ok()?;
    let subsec = nanos.rem_euclid(NANOS_PER_SECOND);
    let date = Date::from_days(seconds.div_euclid(SECONDS_PER_DAY))?;
    let of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    Some(format!(
        "{date}T{:02}:{:02}:{:02}.{subsec:09}Z",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_counts_match_known_dates() {
        for (text, days) in [
            ("1970-01-01", 0),
            ("1969-12-31", -1),
            ("2000-03-01", 11_017),
            ("2024-02-29", 19_782),
            ("0000-01-01", -719_528),
            ("0001-01-01", -719_162),
            ("1899-12-31", -25_568),
            ("-0001-12-31", -719_529),
            ("+10000-01-01", 2_932_897),
        ] {
            let date = Date::parse(text).expect(text);
            assert_eq!(date.days(), days, "{text}");
            assert_eq!(Date::from_days(days), Some(date), "{text}");
            assert_eq!(date.to_string(), text);
        }
    }

    /// chrono's limits, which the wire's range was taken from.
    #[test]
    fn the_wire_range_ends_where_chrono_did() {
        let min = Date::from_days(MIN_DATE_DAYS.into()).expect("min");
        let max = Date::from_days(MAX_DATE_DAYS.into()).expect("max");
        assert_eq!(min.to_string(), "-262143-01-01");
        assert_eq!(max.to_string(), "+262142-12-31");
        assert_eq!(Date::from_days(i64::from(MIN_DATE_DAYS) - 1), None);
        assert_eq!(Date::from_days(i64::from(MAX_DATE_DAYS) + 1), None);
        assert_eq!(Date::parse("-262144-12-31"), None);
        assert_eq!(Date::parse("+262143-01-01"), None);
        assert_eq!(
            timestamp_text(MIN_TIMESTAMP_NANOS).as_deref(),
            Some("-262143-01-01T00:00:00.000000000Z")
        );
        assert_eq!(
            timestamp_text(MAX_TIMESTAMP_NANOS).as_deref(),
            Some("+262142-12-31T23:59:59.999999999Z")
        );
        assert_eq!(timestamp_text(MAX_TIMESTAMP_NANOS + 1), None);
        assert_eq!(timestamp_text(MIN_TIMESTAMP_NANOS - 1), None);
    }

    /// Every day of four centuries, and both ends of the range, comes back
    /// as it went in, one day after the last.
    #[test]
    fn every_day_round_trips() {
        let mut previous: Option<Date> = None;
        for days in (-146_097 * 2..=146_097 * 2)
            .chain(i64::from(MIN_DATE_DAYS)..i64::from(MIN_DATE_DAYS) + 800)
            .chain(i64::from(MAX_DATE_DAYS) - 800..=i64::from(MAX_DATE_DAYS))
        {
            let date = Date::from_days(days).expect("in range");
            assert_eq!(date.days(), days);
            assert_eq!(Date::parse(&date.to_string()), Some(date));
            if let Some(p) = previous.filter(|p| p.days() + 1 == days) {
                let next_day = p.day < days_in_month(p.year, p.month);
                assert_eq!(date.day, if next_day { p.day + 1 } else { 1 });
            }
            previous = Some(date);
        }
    }

    /// Inside jiff's range, the calendar agrees with jiff day for day.
    #[test]
    fn it_agrees_with_jiff_where_jiff_reaches() {
        let jiff_min = jiff::civil::Date::MIN;
        let mut jiff_date = jiff_min;
        let first = Date::new(-9999, 1, 1).expect("in range").days();
        for days in first..first + 3_652_059 * 2 + 1 {
            let date = Date::from_days(days).expect("in range");
            assert_eq!(
                (date.year, date.month, date.day),
                (
                    i64::from(jiff_date.year()),
                    jiff_date.month().unsigned_abs(),
                    jiff_date.day().unsigned_abs()
                ),
                "{days}"
            );
            match jiff_date.tomorrow() {
                Ok(next) => jiff_date = next,
                Err(_) => {
                    assert_eq!(jiff_date, jiff::civil::Date::MAX);
                    break;
                }
            }
        }
        // RFC 3339 years, 0000 to 9999: jiff reads only six-digit
        // expanded years, which this binding does not write.
        for nanos in [
            0,
            -1,
            1_700_000_000_123_456_789,
            -62_167_219_200_000_000_000,
            jiff::Timestamp::MAX.as_nanosecond(),
        ] {
            let text = timestamp_text(nanos).expect("in range");
            let parsed: jiff::Timestamp = text.parse().expect(&text);
            assert_eq!(parsed.as_nanosecond(), nanos, "{text}");
            assert_eq!(parse_timestamp(&text), Some(nanos), "{text}");
        }
    }

    #[test]
    fn dates_hold_to_the_canonical_form() {
        for invalid in [
            "2023-02-29",
            "1900-02-29",
            "2024-2-9",
            "2024-00-10",
            "2024-13-10",
            "2024-04-31",
            "",
            "-",
            "+",
            "2024-01-01T00:00:00Z",
            "02024-01-01",
            "+2024-01-01",
            "-05-03-01",
            "1234567890-01-01",
            "２０２４-01-01",
        ] {
            let parsed = Date::parse(invalid).filter(|d| d.to_string() == invalid);
            assert_eq!(parsed, None, "{invalid}");
        }
        assert_eq!(Date::parse("2000-02-29").map(Date::days), Some(11_016));
    }

    #[test]
    fn timestamps_read_rfc_3339_and_expanded_years() {
        for (text, nanos) in [
            ("1970-01-01T00:00:00Z", 0),
            ("1970-01-01t00:00:00z", 0),
            ("1970-01-01 00:00:00Z", 0),
            ("1970-01-01T00:00:00.123Z", 123_000_000),
            ("1970-01-01T00:00:00.1234567891Z", 123_456_789),
            ("1970-01-01T01:00:00+01:00", 0),
            ("1969-12-31T23:00:00-01:00", 0),
            ("1969-12-31T23:59:59.999999999Z", -1),
            ("-0005-03-01T12:00:00+01:00", -62_319_848_400_000_000_000),
        ] {
            assert_eq!(parse_timestamp(text), Some(nanos), "{text}");
        }
        for invalid in [
            "2016-12-31T23:59:60Z",
            "2016-12-31T23:59:60.123456789Z",
            "1970-01-01T24:00:00Z",
            "1970-01-01T00:60:00Z",
            "1970-01-01T00:00:00",
            "1970-01-01T00:00:00.Z",
            "1970-01-01T00:00:00+0100",
            "1970-01-01T00:00:00+24:00",
            "1970-01-01T00:00:00Zjunk",
            "1970-01-01",
            "+12000-01-01",
            "+12000-01-01t00:00:00Z",
            "+12000-13-01T00:00:00Z",
            "-0005-03-01T12:00:00",
            "02024-01-01T00:00:00Z",
            "+262143-01-01T00:00:00Z",
            "bad",
            "",
        ] {
            assert_eq!(parse_timestamp(invalid), None, "{invalid}");
        }
    }
}
