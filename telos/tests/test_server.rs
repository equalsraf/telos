
extern crate telos;
use std::io::{Write,Read};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[test]
fn tls_server() {
    let mut tls_srv = telos::new_server()
        .key_file("tests/private_key.key")
        .cert_file("tests/certificate.crt")
        .bind().unwrap();

    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap();

    let cli = thread::spawn(move ||{
        let tcp_stream = TcpStream::connect(addr).unwrap();
        let mut tls_stream = telos::new_client()
                .insecure_noverifyname()
                .insecure_noverifycert()
                .connect(tcp_stream, "").unwrap();
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

#[test]
fn double_handshake() {
    let mut tls_srv = telos::new_server()
        .key_file("tests/private_key.key")
        .cert_file("tests/certificate.crt")
        .bind().unwrap();

    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap();

    let cli = thread::spawn(move ||{
        let tcp_stream = TcpStream::connect(addr).unwrap();
        let mut tls_stream = telos::new_client()
                .insecure_noverifyname()
                .insecure_noverifycert()
                .connect(tcp_stream, "").unwrap();
        let mut buf = [0u8; 128];
        let len = tls_stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        tls_stream.handshake().unwrap();
        buf = [0u8; 128];
        let len = tls_stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    });

    // Accept TCP connection
    let tcp_conn = srv.incoming().next().unwrap().unwrap();
    let mut tls_conn = tls_srv.accept(tcp_conn).unwrap();
    tls_conn.write(b"hello").unwrap();
    tls_conn.handshake().unwrap();
    tls_conn.write(b"hello").unwrap();

    let _ = cli.join();
}


#[test]
fn server_handshake_does_nothing() {
    let mut tls_srv = telos::new_server()
        .key_file("tests/private_key.key")
        .cert_file("tests/certificate.crt")
        .bind().unwrap();

    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap();

    let cli = thread::spawn(move ||{
        let tcp_stream = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::new(5, 0));
    });

    // Accept TCP connection
    let tcp_conn = srv.incoming().next().unwrap().unwrap();
    let mut tls_conn = tls_srv.accept(tcp_conn).unwrap();

    // It is slightly unexpected but this will succeed, this
    // test is here just in case this behaviour changes
    tls_conn.handshake().unwrap();
    let _ = cli.join();
}
