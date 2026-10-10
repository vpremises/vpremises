use std::collections::BTreeSet;

use crate::validation::MAX_LISTENERS;
use crate::{AddressFamilyV1, BindScopeV1, ListenerV1, ProtocolV1};

use super::read::SourceFailure;

const MAX_ROWS: usize = 8_192;

pub(super) fn parse(
    source: &str,
    protocol: ProtocolV1,
    family: AddressFamilyV1,
) -> Result<BTreeSet<ListenerV1>, SourceFailure> {
    let mut lines = source.lines();
    let header = lines.next().ok_or(SourceFailure::Invalid)?;
    let names = header.split_ascii_whitespace().collect::<Vec<_>>();
    if !names.windows(3).any(|part| {
        part[0] == "local_address"
            && matches!(part[1], "rem_address" | "remote_address")
            && part[2] == "st"
    }) {
        return Err(SourceFailure::Invalid);
    }
    let mut listeners = BTreeSet::new();
    for (index, line) in lines.filter(|line| !line.trim().is_empty()).enumerate() {
        if index >= MAX_ROWS {
            return Err(SourceFailure::Invalid);
        }
        let columns = line.split_ascii_whitespace().collect::<Vec<_>>();
        if columns.len() < 4 || !valid_state(columns[3]) {
            return Err(SourceFailure::Invalid);
        }
        let (scope, port) = endpoint(columns[1], family)?;
        endpoint(columns[2], family)?;
        let selected = match protocol {
            ProtocolV1::Tcp => columns[3].eq_ignore_ascii_case("0A"),
            ProtocolV1::Udp => port != 0,
        };
        if selected {
            let listener = ListenerV1::new(protocol, family, port, scope)
                .map_err(|_| SourceFailure::Invalid)?;
            listeners.insert(listener);
            if listeners.len() > MAX_LISTENERS {
                return Err(SourceFailure::Invalid);
            }
        }
    }
    Ok(listeners)
}

fn endpoint(value: &str, family: AddressFamilyV1) -> Result<(BindScopeV1, u16), SourceFailure> {
    let (address, port) = value.split_once(':').ok_or(SourceFailure::Invalid)?;
    if port.len() != 4 || !hex(port) || address.contains(':') {
        return Err(SourceFailure::Invalid);
    }
    let port = u16::from_str_radix(port, 16).map_err(|_| SourceFailure::Invalid)?;
    let bytes = address_bytes(address, family)?;
    let scope = if bytes.iter().all(|byte| *byte == 0) {
        BindScopeV1::Wildcard
    } else if loopback(&bytes) {
        BindScopeV1::Loopback
    } else {
        BindScopeV1::Specific
    };
    Ok((scope, port))
}

fn address_bytes(address: &str, family: AddressFamilyV1) -> Result<Vec<u8>, SourceFailure> {
    let words = match family {
        AddressFamilyV1::Ipv4 if address.len() == 8 => 1,
        AddressFamilyV1::Ipv6 if address.len() == 32 => 4,
        _ => return Err(SourceFailure::Invalid),
    };
    if !hex(address) {
        return Err(SourceFailure::Invalid);
    }
    let mut bytes = Vec::with_capacity(words * 4);
    for chunk in address.as_bytes().chunks_exact(8) {
        let text = std::str::from_utf8(chunk).map_err(|_| SourceFailure::Invalid)?;
        let word = u32::from_str_radix(text, 16).map_err(|_| SourceFailure::Invalid)?;
        bytes.extend(word.to_ne_bytes());
    }
    Ok(bytes)
}

fn loopback(bytes: &[u8]) -> bool {
    bytes.len() == 4 && bytes[0] == 127
        || bytes.len() == 16
            && (bytes[..15].iter().all(|byte| *byte == 0) && bytes[15] == 1
                || bytes[..10].iter().all(|byte| *byte == 0)
                    && bytes[10..12] == [0xff, 0xff]
                    && bytes[12] == 127)
}

fn valid_state(value: &str) -> bool {
    value.len() == 2 && hex(value)
}

fn hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::{AddressFamilyV1, BindScopeV1, ProtocolV1};

    #[test]
    fn keeps_tcp_listeners_and_discards_remote_endpoint() {
        let source = concat!(
            "sl local_address rem_address st\n",
            "0: 0100007F:1F90 0200007F:C350 0A more\n",
            "1: 0300007F:C351 0400007F:C352 01 more\n"
        );
        let values = parse(source, ProtocolV1::Tcp, AddressFamilyV1::Ipv4).unwrap();
        let value = values.first().unwrap();
        assert_eq!(value.port(), 8_080);
        assert_eq!(value.bind_scope(), BindScopeV1::Loopback);
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn keeps_bound_udp_and_rejects_malformed_rows() {
        let source = concat!(
            "sl local_address remote_address st\n",
            "0: 00000000000000000000000001000000:14E9 ",
            "00000000000000000000000000000000:0000 07 more\n"
        );
        let values = parse(source, ProtocolV1::Udp, AddressFamilyV1::Ipv6).unwrap();
        assert_eq!(values.first().unwrap().bind_scope(), BindScopeV1::Loopback);
        assert!(parse("bad\n", ProtocolV1::Tcp, AddressFamilyV1::Ipv4).is_err());
    }
}
