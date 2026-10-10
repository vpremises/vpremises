use std::fs::File;
use std::io::{Read, Take};

const MAX_SOURCE_BYTES: u64 = 1_048_576;
const TCP: &str = "/proc/net/tcp";
const TCP6: &str = "/proc/net/tcp6";
const UDP: &str = "/proc/net/udp";
const UDP6: &str = "/proc/net/udp6";
const ROUTE: &str = "/proc/net/route";
const IPV6_ROUTE: &str = "/proc/net/ipv6_route";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceFailure {
    Unavailable,
    Invalid,
}

pub(super) struct Sources {
    pub(super) tcp: String,
    pub(super) tcp6: String,
    pub(super) udp: String,
    pub(super) udp6: String,
    pub(super) route: String,
    pub(super) ipv6_route: String,
}

pub(super) fn fixed_sources() -> Result<Sources, SourceFailure> {
    Ok(Sources {
        tcp: fixed_file(TCP)?,
        tcp6: fixed_file(TCP6)?,
        udp: fixed_file(UDP)?,
        udp6: fixed_file(UDP6)?,
        route: fixed_file(ROUTE)?,
        ipv6_route: fixed_file(IPV6_ROUTE)?,
    })
}

fn fixed_file(path: &'static str) -> Result<String, SourceFailure> {
    let file = File::open(path).map_err(|_| SourceFailure::Unavailable)?;
    let metadata = file.metadata().map_err(|_| SourceFailure::Unavailable)?;
    if !metadata.file_type().is_file() {
        return Err(SourceFailure::Unavailable);
    }
    let mut bytes = Vec::new();
    let mut bounded: Take<File> = file.take(MAX_SOURCE_BYTES + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| SourceFailure::Unavailable)?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(SourceFailure::Invalid);
    }
    String::from_utf8(bytes).map_err(|_| SourceFailure::Invalid)
}

#[cfg(test)]
impl Sources {
    pub(super) fn minimal() -> Self {
        let socket_header = "sl local_address rem_address st\n".to_owned();
        Self {
            tcp: socket_header.clone(),
            tcp6: socket_header.clone(),
            udp: socket_header.clone(),
            udp6: socket_header,
            route: "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
                .to_owned(),
            ipv6_route: String::new(),
        }
    }
}
