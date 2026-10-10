//! Focused regression cases for the enclosing implementation.
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
