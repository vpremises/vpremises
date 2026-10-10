use crate::{RouteStateV1, RoutesV1, SensorError};

pub(crate) const MAX_LISTENERS: usize = 4_096;
pub(crate) const MAX_FINDINGS: usize = 8_194;

pub(crate) fn sort_unique<T: Ord>(values: &mut [T], maximum: usize) -> Result<(), SensorError> {
    if values.len() > maximum {
        return Err(SensorError::InvalidContract);
    }
    values.sort();
    validate_sorted(values, maximum)
}

pub(crate) fn validate_sorted<T: Ord>(values: &[T], maximum: usize) -> Result<(), SensorError> {
    if values.len() > maximum || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(SensorError::InvalidContract)
    } else {
        Ok(())
    }
}

pub(crate) fn known_routes(routes: &RoutesV1) -> bool {
    matches!(routes.ipv4(), RouteStateV1::Present | RouteStateV1::Absent)
        && matches!(routes.ipv6(), RouteStateV1::Present | RouteStateV1::Absent)
}

pub(crate) fn unknown_routes(routes: &RoutesV1) -> bool {
    routes.ipv4() == RouteStateV1::Unknown && routes.ipv6() == RouteStateV1::Unknown
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

pub(crate) fn timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || !matches!(
            (
                bytes.get(4),
                bytes.get(7),
                bytes.get(10),
                bytes.get(13),
                bytes.get(16),
                bytes.get(19),
                bytes.get(23)
            ),
            (
                Some(b'-'),
                Some(b'-'),
                Some(b'T'),
                Some(b':'),
                Some(b':'),
                Some(b'.'),
                Some(b'Z')
            )
        )
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |start, end| {
        std::str::from_utf8(&bytes[start..end])
            .ok()
            .and_then(|part| part.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    day > 0 && day <= max_day && hour < 24 && minute < 60 && second < 60
}
