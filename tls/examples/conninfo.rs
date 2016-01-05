extern crate tls;
extern crate rustc_serialize;
extern crate docopt;

use tls::net::TlsConnection;
use docopt::Docopt;

const USAGE: &'static str = "
conninfo

Usage:
  conninfo [options] <address>
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

    tls::init();

    let mut c = TlsConnection::new().unwrap();

    c.set_ca_mem(include_str!("../tests/cert.pem")).unwrap();
    if !args.flag_protocols.is_empty() {
        c.set_protocols(&args.flag_protocols).unwrap();
    }
    if !args.flag_ciphers.is_empty() {
        c.set_ciphers(&args.flag_ciphers).unwrap();
    }
    if args.flag_noverifycert || args.flag_accept_all {
        c.insecure_noverifycert();
    }
    if args.flag_noverifyname || args.flag_accept_all {
        c.insecure_noverifyname();
    }

    if args.flag_accept_all {
        c.set_protocols("all").unwrap();
        c.set_ciphers("legacy").unwrap();
    }

    let stream = c.connect(&args.arg_address, "").unwrap();

    println!("Certificate Issuer: {}", stream.certificate_issuer());
    println!("Certificate Hash: {}", stream.certificate_hash());
    println!("Certificate Subject: {}", stream.certificate_subject());
    println!("Connection Version: {}", stream.version());
    println!("Connection Cipher: {}", stream.cipher());
}
