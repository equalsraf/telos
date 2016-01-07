extern crate tls;
use tls::net::*;
use tls::init;
use std::io::{Write,Read};
use std::net::{TcpListener, TcpStream};
use std::thread;

#[test]
fn test_net_stream() {
    assert!(init());

    let mut conn = TlsConnection::new().unwrap();
    conn.set_ca_mem(include_str!("cert.pem")).unwrap();
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
    conn.set_ca_file("tests/cert.pem").unwrap();
    let mut s = conn.connect("google.com", "443").unwrap();

    s.shutdown().unwrap();
    assert!(s.shutdown().is_err());
}

#[test]
fn test_net_listener() {
    assert!(init());

    let mut tls_srv = TlsListener::new().unwrap();
    tls_srv.set_key_file("tests/private_key.key").unwrap();
    tls_srv.set_cert_file("tests/certificate.crt").unwrap();

    let mut listener = tls_srv.bind().unwrap();

    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap();

    let cli = thread::spawn(move ||{
        let tcp_stream = TcpStream::connect(addr).unwrap();
        let mut conn = TlsConnection::new().unwrap();
        conn.insecure_noverifyname();
        conn.insecure_noverifycert();
        let tls_stream = conn.from_tcp_stream(tcp_stream, "").unwrap();
    });

    // Accept TCP connection
    let tcp_conn = srv.incoming().next().unwrap().unwrap();
    let tls_conn = listener.accept(tcp_conn).unwrap();

    let _ = cli.join();
}
