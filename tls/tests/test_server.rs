
extern crate tls;
use tls::*;
use std::net::{TcpStream,TcpListener};
use std::os::unix::io::IntoRawFd;
use std::thread;
use std::io::Read;

#[test]
fn test_server() {
    init();

    let srv = TcpListener::bind("127.0.0.1:0").unwrap();

    let addr = srv.local_addr().unwrap();
    let cli = thread::spawn(move ||{
    init();
        let stream = TcpStream::connect(addr).unwrap();
        let mut cli_tls = TlsContext::new_client().unwrap();
        let mut cfg = TlsConfig::new().unwrap();
        cfg.insecure_noverifyname();
        cfg.insecure_noverifycert();
        cli_tls.configure(cfg).unwrap();
        cli_tls.connect_socket(stream.into_raw_fd(), "").unwrap();
        cli_tls.handshake().unwrap();

        let mut buf = [0u8; 128];
        let len = cli_tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
    });

    let mut tls_srv = TlsContext::new_server().unwrap();
    let mut cfg = TlsConfig::new().unwrap();
    cfg.set_key_file("tests/private_key.key").unwrap();
    cfg.set_cert_file("tests/certificate.crt").unwrap();
    tls_srv.configure(cfg).unwrap();

    let conn = srv.incoming().next().unwrap().unwrap();
    let mut conn_tls = tls_srv.accept_socket(conn.into_raw_fd()).unwrap();
    conn_tls.handshake().unwrap();
    conn_tls.write(b"hello").unwrap();

    let _ = cli.join();
}


