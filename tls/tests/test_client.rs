extern crate tls;
use tls::*;
use std::net::TcpStream;

mod common;

#[test]
fn test_client_defs() {
    assert!(init());

    let c = TlsContext::new_client().unwrap();

    // These are the defaults before the connection is set
    assert_eq!(c.conn_version(), "");
    assert_eq!(c.conn_cipher(), "");
    assert_eq!(c.peer_cert_notbefore(), None);
    assert_eq!(c.peer_cert_notafter(), None);
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
fn test_connect_noport() {
    assert!(init());

    let mut c = common::tls_client();
    c.connect_servername("google.com:443", "", "").unwrap();
    c.handshake().unwrap();
}

#[test]
fn test_client_servername() {
    assert!(init());

    let mut c = common::tls_client();
    c.connect_servername("google.com", "443", "google.com").unwrap();
    c.handshake().unwrap();
}

/// Similar to test_client_servername, but setups CA
/// from memory.
#[test]
fn test_set_ca_mem() {
    assert!(init());

    let mut cfg = TlsConfig::new().unwrap();
    let pem = include_str!("cert.pem");
    cfg.set_ca_mem(&pem);

    let mut c = TlsContext::new_client().unwrap();
    c.configure(cfg).unwrap();
    c.connect_servername("google.com", "443", "").unwrap();
    c.handshake().unwrap();
}

#[test]
fn test_connect_socket() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    
    let mut c = common::tls_client();
    c.connect_socket(tcp, "google.com").unwrap();
    c.handshake().unwrap();
}

#[test]
fn test_client_verify_depth() {
    assert!(init());

    let mut c = TlsContext::new_client().unwrap();
    let mut cfg = TlsConfig::new().unwrap();
    // This will cause verification to fail
    cfg.set_verify_depth(0);
    c.configure(cfg).unwrap();
    assert!(c.connect_servername("google.com", "443", "").is_err()
            || c.handshake().is_err());
}

#[test]
fn test_client_double_handshake() {
    assert!(init());

    let mut c = common::tls_client();
    c.connect_servername("google.com", "443", "").unwrap();
    c.handshake().unwrap();
    assert!(c.handshake().is_err());
}

//#[test]
//fn test_client_errors() {
//    assert!(init());
//
//    let mut c = TlsContext::new_client().unwrap();
//    c.handshake().unwrap();
//}

