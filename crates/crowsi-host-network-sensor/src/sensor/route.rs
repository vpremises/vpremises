use super::read::SourceFailure;

const MAX_ROWS: usize = 8_192;
const ROUTE_UP: u32 = 0x0001;

pub(super) fn parse_ipv4(source: &str) -> Result<bool, SourceFailure> {
    let mut lines = source.lines();
    let header = lines.next().ok_or(SourceFailure::Invalid)?;
    let names = header.split_ascii_whitespace().collect::<Vec<_>>();
    if names.len() < 8
        || names[0] != "Iface"
        || names[1] != "Destination"
        || names[3] != "Flags"
        || names[7] != "Mask"
    {
        return Err(SourceFailure::Invalid);
    }
    let mut default_present = false;
    for (index, line) in lines.filter(|line| !line.trim().is_empty()).enumerate() {
        if index >= MAX_ROWS {
            return Err(SourceFailure::Invalid);
        }
        let columns = line.split_ascii_whitespace().collect::<Vec<_>>();
        if columns.len() != 11 || !valid_interface(columns[0]) {
            return Err(SourceFailure::Invalid);
        }
        for field in [columns[1], columns[2], columns[7]] {
            fixed_hex(field, 8)?;
        }
        let flags = parse_hex(columns[3], 8)?;
        for field in &columns[4..7] {
            parse_decimal(field)?;
        }
        for field in &columns[8..11] {
            parse_decimal(field)?;
        }
        if all_zero(columns[1]) && all_zero(columns[7]) && flags & ROUTE_UP != 0 {
            default_present = true;
        }
    }
    Ok(default_present)
}

pub(super) fn parse_ipv6(source: &str) -> Result<bool, SourceFailure> {
    let mut default_present = false;
    for (index, line) in source
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        if index >= MAX_ROWS {
            return Err(SourceFailure::Invalid);
        }
        let columns = line.split_ascii_whitespace().collect::<Vec<_>>();
        if columns.len() != 10 || !valid_interface(columns[9]) {
            return Err(SourceFailure::Invalid);
        }
        fixed_hex(columns[0], 32)?;
        let prefix = parse_hex(columns[1], 2)?;
        fixed_hex(columns[2], 32)?;
        parse_hex(columns[3], 2)?;
        fixed_hex(columns[4], 32)?;
        for field in &columns[5..9] {
            fixed_hex(field, 8)?;
        }
        let flags = parse_hex(columns[8], 8)?;
        if all_zero(columns[0]) && prefix == 0 && flags & ROUTE_UP != 0 {
            default_present = true;
        }
    }
    Ok(default_present)
}

fn fixed_hex(value: &str, width: usize) -> Result<(), SourceFailure> {
    if value.len() == width && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(SourceFailure::Invalid)
    }
}

fn parse_hex(value: &str, width: usize) -> Result<u32, SourceFailure> {
    if value.is_empty()
        || value.len() > width
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SourceFailure::Invalid);
    }
    u32::from_str_radix(value, 16).map_err(|_| SourceFailure::Invalid)
}

fn parse_decimal(value: &str) -> Result<u64, SourceFailure> {
    value.parse::<u64>().map_err(|_| SourceFailure::Invalid)
}

fn all_zero(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte == b'0')
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{parse_ipv4, parse_ipv6};

    #[test]
    fn detects_default_routes_without_returning_route_details() {
        let ipv4 = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n"
        );
        let ipv6 = concat!(
            "00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 00000064 00000000 00000000 ",
            "00000001 eth0\n"
        );
        assert!(parse_ipv4(ipv4).unwrap());
        assert!(parse_ipv6(ipv6).unwrap());
    }

    #[test]
    fn absence_is_valid_but_malformed_input_is_unknown() {
        let header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n";
        assert!(!parse_ipv4(header).unwrap());
        assert!(!parse_ipv6("").unwrap());
        assert!(parse_ipv4("bad\n").is_err());
        assert!(parse_ipv6("0000\n").is_err());
    }
}
