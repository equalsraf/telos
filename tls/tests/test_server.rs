
extern crate tls;
use tls::init;
use std::io::{Write,Read};
use std::net::{TcpListener, TcpStream};
use std::thread;

#[test]
fn tls_server() {
    assert!(init());

    let mut tls_srv = tls::new_server()
        .key_file("tests/private_key.key")
        .cert_file("tests/certificate.crt")
        .bind().unwrap();

    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap();

    let cli = thread::spawn(move ||{
        let tcp_stream = TcpStream::connect(addr).unwrap();
        let mut tls_stream = tls::new_client()
                .insecure_noverifyname()
                .insecure_noverifycert()
                .connect_socket(tcp_stream, "").unwrap();
        //tls_stream.handshake().unwrap();
        let mut buf = [0u8; 128];
        let len = tls_stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    });

    // Accept TCP connection
    let tcp_conn = srv.incoming().next().unwrap().unwrap();
    let mut tls_conn = tls_srv.accept(tcp_conn).unwrap();
    tls_conn.write(b"hello").unwrap();

    let _ = cli.join();
}
