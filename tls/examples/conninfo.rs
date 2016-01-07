extern crate tls;
extern crate rustc_serialize;
extern crate docopt;

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

    let mut c = tls::new_client()
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

    let stream = c.connect(&args.arg_address, "", "").unwrap();

    println!("Certificate Issuer: {}", stream.certificate_issuer());
    println!("Certificate Hash: {}", stream.certificate_hash());
    println!("Certificate Subject: {}", stream.certificate_subject());
    println!("Connection Version: {}", stream.version());
    println!("Connection Cipher: {}", stream.cipher());
}
