extern crate tls;
use tls::net::*;
use tls::init;
use std::io::{Write,Read};
use std::net::{TcpListener, TcpStream};
use std::thread;

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
        let mut tls_stream = tls::new_client()
                .insecure_noverifyname()
                .insecure_noverifycert()
                .connect_socket(tcp_stream, "").unwrap();
        tls_stream.handshake().unwrap();
    });

    // Accept TCP connection
    let tcp_conn = srv.incoming().next().unwrap().unwrap();
    let tls_conn = listener.accept(tcp_conn).unwrap();

    let _ = cli.join();
}
