extern crate tls;
use std::io::{Read, Write};
use tls::{new_client,init};
use std::net::TcpStream;

#[test]
fn test_client() {
    assert!(init());

    let mut c = new_client()
        .connect("google.com", "443", None).unwrap();
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
                .connect("www.google.com", "443", None)
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
                .connect("www.google.com", "443", None)
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
                .connect("www.google.com", "443", None)
                .unwrap();

    assert!(cli.shutdown().is_err());
}

#[test]
fn ca_invalid() {
    assert!(init());
    // This will fail because there is no CA file
    let cli = new_client()
                .ca_path(".")
                .ca_file("")
                .connect("www.google.com", "443", None);
    assert!(cli.is_err());
}

#[test]
fn ca_string() {
    assert!(init());

    let pem = include_str!("cert.pem");
    let mut cli = new_client()
                .ca(&pem)
                .connect("www.google.com", "443", None)
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn ca_string_invalid() {
    assert!(init());

    let cli = new_client()
                .ca("--INVALID PEM")
                .connect("www.google.com", "443", None);
    assert!(cli.is_err());
}

#[test]
fn connect_hostport() {
    assert!(init());
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com:443", "", None)
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn connect_servername() {
    assert!(init());
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", Some("www.google.com"))
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn connect_socket() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect_socket(tcp, "www.google.com")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn double_handshake_is_error() {
    assert!(init());

    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", None)
                .unwrap();

    cli.handshake().unwrap();
    assert!(cli.handshake().is_err());
}

#[test]
fn verify_depth() {
    assert!(init());

    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .verify_depth(0)
                .connect("www.google.com", "443", None)
                .unwrap();
    assert!(cli.handshake().is_err());
}
