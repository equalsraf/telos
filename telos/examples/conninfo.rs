extern crate telos;
extern crate rustc_serialize;
extern crate docopt;

use docopt::Docopt;
use std::net::TcpStream;

const USAGE: &'static str = "
conninfo

Usage:
  conninfo [options] <address> <port>
  conninfo --help

Options:
  --protocols=<protocols>
  --ciphers=<ciphers>
  --noverifycert
  --noverifyname
  --accept-all              Alias for protocols=all, ciphers=legacy
                            noverifycert, noverifyname.
";

#[derive(Debug,RustcDecodable)]
struct Args {
    arg_address: String,
    arg_port: u16,
    flag_protocols: String,
    flag_ciphers: String,
    flag_noverifycert: bool,
    flag_noverifyname: bool,
    flag_accept_all: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());

    let mut c = telos::new_client()
        .ca(include_str!("../tests/cert.pem"));

    if !args.flag_protocols.is_empty() {
        c = c.protocols(&args.flag_protocols);
    }
    if !args.flag_ciphers.is_empty() {
        c = c.ciphers(&args.flag_ciphers);
    }
    if args.flag_noverifycert || args.flag_accept_all {
        c = c.insecure_noverifycert();
    }
    if args.flag_noverifyname || args.flag_accept_all {
        c = c.insecure_noverifyname();
    }

    if args.flag_accept_all {
        c = c.protocols("all");
        c = c.ciphers("legacy");
    }

    let tcp_stream = TcpStream::connect((&*args.arg_address, args.arg_port)).unwrap();
    let mut stream = c.from_socket(&tcp_stream, &args.arg_address).unwrap();
    stream.handshake().unwrap();

    println!("Certificate Issuer: {}", stream.certificate_issuer());
    println!("Certificate Hash: {}", stream.certificate_hash());
    println!("Certificate Subject: {}", stream.certificate_subject());
    println!("Connection Version: {}", stream.version());
    println!("Connection Cipher: {}", stream.cipher());
    println!("Valid from: {}", stream.peer_cert_notbefore().unwrap());
    println!("Valid Until: {}", stream.peer_cert_notafter().unwrap());
}
