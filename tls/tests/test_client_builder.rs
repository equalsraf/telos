
extern crate tls;
use tls::{new_client,init};
use std::net::TcpStream;

#[test]
fn ca_invalid() {
    assert!(init());
    // This will fail because there is no CA file
    let cli = new_client()
                .ca_path(".")
                .ca_file("")
                .connect("www.google.com", "443", "");
    assert!(cli.is_err());
}

#[test]
fn ca_string() {
    assert!(init());

    let pem = include_str!("cert.pem");
    let mut cli = new_client()
                .ca(&pem)
                .connect("www.google.com", "443", "")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn ca_string_invalid() {
    assert!(init());

    let cli = new_client()
                .ca("--INVALID PEM")
                .connect("www.google.com", "443", "");
    assert!(cli.is_err());
}

#[test]
fn connect_hostport() {
    assert!(init());
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com:443", "", "")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn connect_servername() {
    assert!(init());
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", "www.google.com")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn connect_socket() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect_socket(tcp,  "www.google.com")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn double_handshake_is_error() {
    assert!(init());

    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect("www.google.com", "443", "")
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
                .connect("www.google.com", "443", "")
                .unwrap();
    assert!(cli.handshake().is_err());
}
