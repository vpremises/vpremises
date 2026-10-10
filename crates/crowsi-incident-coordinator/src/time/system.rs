//! Convert the trusted system clock to normalized UTC timestamps.
use super::{CoordinatorError, SystemTime, UNIX_EPOCH};

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

pub(in crate::time) fn format_system_time(value: SystemTime) -> Result<String, CoordinatorError> {
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

pub(in crate::time) fn civil_from_days(days: i64) -> (i64, i64, i64) {
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
