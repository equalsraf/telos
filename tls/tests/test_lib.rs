extern crate tls;
use tls::*;

#[test]
fn test_init() {
    assert_eq!(init(), true);
    assert_eq!(init(), true);
}

#[test]
fn client_ctx_defs() {
    assert!(init());

    let c = TlsContext::new_client().unwrap();

    // These are the defaults before the connection is set
    assert_eq!(c.conn_version(), "");
    assert_eq!(c.conn_cipher(), "");
    assert!(c.peer_cert_notbefore().is_err());
    assert!(c.peer_cert_notafter().is_err());
    assert_eq!(c.peer_cert_issuer(), "");
    assert_eq!(c.peer_cert_subject(), "");
    assert_eq!(c.peer_cert_hash(), "");
    assert_eq!(c.peer_cert_contains_name("some.name"), false);
    assert_eq!(c.peer_cert_provided(), false);
}

