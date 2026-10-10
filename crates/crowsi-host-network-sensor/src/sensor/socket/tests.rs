//! Focused regression cases for the enclosing implementation.
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
