/// This is a minimal example using mio, it just accepts TLS
/// connections and reads. There are no assertion, this was added
/// as a quick test for a bug.
extern crate telos;
extern crate mio;

use mio::*;
use mio::tcp::*;
use std::net::SocketAddr;
use std::thread;
use std::net::TcpStream as StdTcp;
use std::io::{Write, Read, ErrorKind};
use telos::{TlsStream, TlsServer};
use std::collections::HashMap;

struct Server {
    listener: TcpListener,
    tls: TlsServer,
    clients: HashMap<Token, TlsStream<TcpStream>>,
    count: usize,
}

// For now mio::net::TcpStream does not implement AsRawSocket
#[cfg(unix)]
impl Handler for Server {
    type Timeout = usize;
    type Message = ();

    fn ready(&mut self, evloop: &mut EventLoop<Server>, token: Token,
             events: EventSet) {
        println!("{:?} {:?}", token, events);
        if token == Token(0) {
            let sock = match self.listener.accept() {
                Err(err) => {
                    println!("Failed to accept connection: {}", err);
                    return;
                },
                Ok(None) => {
                    println!("Accept() returned None");
                    return;
                },
                Ok(Some((sock, addr))) => {
                    println!("New connection from {}", addr);
                    sock
                },
            };

            let tls = match self.tls.accept(sock) {
                Err(err) => {
                    println!("Unable to accept TLS connection: {}", err);
                    return;
                },
                Ok(stream) => stream,
            };

            let newtoken = Token(self.count);
            self.count += 1;
            if evloop.register(tls.inner(), newtoken,
                                EventSet::readable(),
                                PollOpt::edge() | PollOpt::oneshot()).is_ok() {
                self.clients.insert(newtoken, tls);
            }
        } else if self.clients.contains_key(&token) {

            if let Some(client) = self.clients.get_mut(&token) {
                if events.is_readable() {
                    let mut buf = [0u8; 1024];
                    loop {
                        match client.read(&mut buf) {
                            Ok(0) => break,
                            Ok(len) => {
                                println!("Read {} bytes", len);
                                evloop.shutdown();
                                break;
                            },
                            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                                println!("Read WouldBlock");
                                break;
                            },
                            Err(_) => {
                                break;
                            },
                        }
                    }
                }
                if events.is_writable() {
                }
                if events.is_hup() {
                }

                evloop.reregister(client.inner(), token,
                                EventSet::readable(),
                                PollOpt::edge() | PollOpt::oneshot()).unwrap();
            }
        }
    }
}

// For now mio::net::TcpStream does not implement AsRawSocket
#[cfg(unix)]
#[test]
fn test_mio() {
    let address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
    let listener = TcpListener::bind(&address).unwrap();
    let srvaddr = listener.local_addr().unwrap();

    let join = thread::spawn(move || {
        let mut evloop: EventLoop<Server> = EventLoop::new().unwrap();
        let tlssrv = telos::new_server()
                    .key_file("tests/private_key.key")
                    .cert_file("tests/certificate.crt")
                    .bind().unwrap();

        evloop.register(&listener, Token(0), EventSet::readable(), PollOpt::edge()).unwrap();
        let mut server = Server {
            listener: listener,
            clients: HashMap::new(),
            tls: tlssrv,
            count: 1,
        };
        evloop.run(&mut server).unwrap();
    });

    // Client
    let tcp = StdTcp::connect(&srvaddr).unwrap();
    let mut client = telos::new_client()
        .insecure_noverifycert()
        .insecure_noverifyname()
        .connect(tcp, "")
        .unwrap();

    let payload: [u8; 2048] = [b'X'; 2048];
    client.write_all(&payload).unwrap();
    join.join().unwrap();
}
