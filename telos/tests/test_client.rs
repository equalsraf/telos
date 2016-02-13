extern crate telos;
use std::io::{Read, Write};
use telos::new_client;
use std::net::{TcpStream, TcpListener};
use std::thread;
use std::time::Duration;

#[test]
fn test_client() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut c = new_client()
        .ca_file("tests/cert.pem")
        .connect(tcp, "google.com").unwrap();
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
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect(tcp, "google.com")
                .unwrap();

    cli.write("GET / HTTP/1.1\n\n".as_bytes()).unwrap();
    let mut buf = [0u8; 256];
    cli.read(&mut buf).unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 "));
}

#[test]
fn shutdown_twice_fails() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect(tcp, "www.google.com")
                .unwrap();

    cli.handshake().unwrap();
    cli.shutdown().unwrap();
    assert!(cli.shutdown().is_err());
}

#[test]
fn shutdown_without_handshake_fails() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect(tcp, "google.com")
                .unwrap();

    assert!(cli.shutdown().is_err());
}

#[test]
fn ca_invalid() {
    // This will fail because there is no CA file
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let cli = new_client()
                .ca_path(".")
                .ca_file("")
                .connect(tcp, "google.com");
    assert!(cli.is_err());
}

#[test]
fn ca_string() {
    let pem = include_str!("cert.pem");
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca(&pem)
                .connect(tcp, "google.com")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn ca_string_invalid() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let cli = new_client()
                .ca("--INVALID PEM")
                .connect(tcp, "google.com");
    assert!(cli.is_err());
}

#[test]
fn connect_hostport() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect(tcp, "google.com")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn connect_socket() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect(tcp, "google.com")
                .unwrap();
    cli.handshake().unwrap();
}

#[test]
fn double_handshake_is_error() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .connect(tcp, "google.com")
                .unwrap();

    cli.handshake().unwrap();
    assert!(cli.handshake().is_err());
}

#[test]
fn verify_depth() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let mut cli = new_client()
                .ca_file("tests/cert.pem")
                .verify_depth(0)
                .connect(tcp, "google.com")
                .unwrap();
    assert!(cli.handshake().is_err());
}

#[test]
fn error_ciphers() {
    let tcp = TcpStream::connect("google.com:443").unwrap();
    let cli = new_client()
                .ca_file("tests/cert.pem")
                .ciphers("unknown_cipher")
                .connect(tcp, "google.com");
    assert!(cli.is_err());
}

#[test]
fn client_handshake_blocks() {
    let srv = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = srv.local_addr().unwrap();

    let cli = thread::spawn(move ||{
        let tcp_stream = TcpStream::connect(addr).unwrap();
        tcp_stream.set_read_timeout(Some(Duration::new(1,0))).unwrap();
        let mut tls_stream = telos::new_client()
                .insecure_noverifyname()
                .insecure_noverifycert()
                .connect(tcp_stream, "").unwrap();
        let res = tls_stream.handshake();
        assert!(res.is_err());
        assert!(res.unwrap_err().wants_more());
    });

    // Accept TCP connection
    let tcp_conn = srv.incoming().next().unwrap().unwrap();
    let _ = cli.join();
}

#[test]
fn invalid_file_descriptor() {
    // This fails, the socket is closed
    let mut client = {
        let tcp = TcpStream::connect("google.com:443").unwrap();
        let mut client = telos::new_client()
            .insecure_noverifycert()
            .connect_socket(&tcp, "google.com")
            .unwrap();
        client
    };
    assert!(client.handshake().is_err());

    let mut client = {
        let tcp = TcpStream::connect("google.com:443").unwrap();
        let mut client = telos::new_client()
            .insecure_noverifycert()
            .connect(tcp, "google.com")
            .unwrap();
        client
    };
    client.handshake().unwrap();
}

#[test]
fn inner_stream() {
        use std::net::Shutdown;

        let tcp = TcpStream::connect("google.com:443").unwrap();
        let mut client = telos::new_client()
            .insecure_noverifycert()
            .connect(tcp, "google.com")
            .unwrap();

        client.inner().shutdown(Shutdown::Both).unwrap();
        assert!(client.handshake().is_err());
}
