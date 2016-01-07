
extern crate tls;
use tls::*;

pub fn tls_client() -> TlsContext {
    let mut cfg = TlsConfig::new().unwrap();
    cfg.set_ca_file("tests/cert.pem").unwrap();

    let mut c = TlsContext::new_client().unwrap();
    c.configure(cfg).unwrap();
    c
}

