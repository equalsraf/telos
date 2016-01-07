extern crate tls;
use tls::*;
use std::io::{Read, Write};

mod common;

#[test]
fn test_client_defs() {
    assert!(init());

    let c = TlsContext::new_client().unwrap();

    // These are the defaults before the connection is set
    assert_eq!(c.conn_version(), "");
    assert_eq!(c.conn_cipher(), "");
    assert!(c.peer_cert_notbefore().is_err());
    assert!(c.peer_cert_notafter().is_err());
    assert_eq!(c.peer_cert_issuer(), "");
    assert_eq!(c.peer_cert_subject(), "");
    assert_eq!(c.peer_cert_hash(), "");
    assert_eq!(c.peer_cert_contains_name("some.name"), false);
    assert_eq!(c.peer_cert_provided(), false);
}

#[test]
fn test_client() {
    assert!(init());

    let mut c = common::tls_client();
    c.connect_servername("google.com", "443", "").unwrap();
    c.handshake().unwrap();

    let notbefore = c.peer_cert_notbefore().unwrap();
    let notafter = c.peer_cert_notafter().unwrap();
    assert!(notbefore < notafter);
    assert!(c.peer_cert_provided());
    assert!(c.peer_cert_contains_name("google.com"));

    // Start an HTTP request just to check read/write
    c.write("GET / HTTP/1.1\n\n".as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    c.read(&mut buf).unwrap();
    println!("{}", String::from_utf8_lossy(&buf));
    assert!(buf.starts_with(b"HTTP/1.1 "));
}

#[test]
fn stream_write_read() {
    assert!(init());

    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", "")
                .unwrap();

    cli.write("GET / HTTP/1.1\n\n".as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    cli.read(&mut buf).unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 "));
}

#[test]
fn shutdown_twice_fails() {
    assert!(init());

    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", "")
                .unwrap();

    cli.handshake().unwrap();
    cli.shutdown().unwrap();
    assert!(cli.shutdown().is_err());
}

#[test]
fn shutdown_without_handshake_fails() {
    assert!(init());

    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", "")
                .unwrap();

    assert!(cli.shutdown().is_err());
}
