extern crate tls;
use tls::net::*;
use tls::init;
use std::io::{Write,Read};

#[test]
fn test_net_stream() {
    assert!(init());

    let mut conn = TlsConnection::new().unwrap();
    conn.set_ca_file("tests/cert.pem");
    let mut s = conn.connect("google.com", "443").unwrap();

    s.write("GET / HTTP/1.1\n\n".as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    s.read(&mut buf).unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 "));
}

#[test]
fn test_net_shutdown_twice() {
    assert!(init());

    let mut conn = TlsConnection::new().unwrap();
    conn.set_ca_file("tests/cert.pem");
    let mut s = conn.connect("google.com", "443").unwrap();

    s.shutdown().unwrap();
    assert!(s.shutdown().is_err());
}

