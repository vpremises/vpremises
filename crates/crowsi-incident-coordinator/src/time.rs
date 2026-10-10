pub(crate) fn normalized_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range| {
        std::str::from_utf8(&bytes[range])
            .ok()
            .and_then(|part| part.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    if year == 0 {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    day > 0 && day <= maximum && hour < 24 && minute < 60 && second < 60
}

pub(crate) fn current(start: &str, end: &str, at: &str) -> bool {
    normalized_utc(start) && normalized_utc(end) && normalized_utc(at) && start <= at && at < end
}

pub(crate) fn unix_millis(value: &str) -> Option<i64> {
    if !normalized_utc(value) {
        return None;
    }
    let number = |start, end| value.get(start..end)?.parse::<i64>().ok();
    let mut year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let millis = number(20, 23)?;
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days.checked_mul(86_400_000)?
        .checked_add(hour * 3_600_000)?
        .checked_add(minute * 60_000)?
        .checked_add(second * 1_000)?
        .checked_add(millis)
}

pub(crate) fn window_within(start: &str, end: &str, maximum: i64) -> bool {
    unix_millis(end)
        .zip(unix_millis(start))
        .is_some_and(|(end, start)| end > start && end - start <= maximum)
}

pub(crate) fn elapsed_at_least(start: &str, end: &str, minimum: i64) -> bool {
    unix_millis(end)
        .zip(unix_millis(start))
        .is_some_and(|(end, start)| end >= start && end - start >= minimum)
}

pub(crate) fn system_utc_now() -> Result<String, CoordinatorError> {
    format_system_time(SystemTime::now())
}

pub(crate) fn system_utc_window(seconds: u64) -> Result<(String, String), CoordinatorError> {
    let now = SystemTime::now();
    let expires = now
        .checked_add(std::time::Duration::from_secs(seconds))
        .ok_or_else(|| CoordinatorError::new("system_clock", "timestamp overflow"))?;
    Ok((format_system_time(now)?, format_system_time(expires)?))
}

fn format_system_time(value: SystemTime) -> Result<String, CoordinatorError> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoordinatorError::new("system_clock", "precedes the Unix epoch"))?;
    let seconds = i64::try_from(duration.as_secs())
        .map_err(|_| CoordinatorError::new("system_clock", "timestamp is out of range"))?;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(1..=9999).contains(&year) {
        return Err(CoordinatorError::new(
            "system_clock",
            "year is outside normalized timestamp range",
        ));
    }
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        duration.subsec_millis()
    ))
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}
use std::time::{SystemTime, UNIX_EPOCH};

use crate::CoordinatorError;
