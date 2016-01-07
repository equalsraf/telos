extern crate tls;
use tls::{init,TlsConfig};

#[test]
fn test_init() {
    assert_eq!(init(), true);
    assert_eq!(init(), true);
}

#[test]
fn test_protocols() {
    let mut cfg = TlsConfig::new().unwrap();

    // The following are all supported
    cfg.set_protocols("all").unwrap();
    cfg.set_protocols("legacy").unwrap();
    cfg.set_protocols("default").unwrap();
    cfg.set_protocols("secure").unwrap();
    cfg.set_protocols("tlsv1").unwrap();
    cfg.set_protocols("tlsv1.0").unwrap();
    cfg.set_protocols("tlsv1.1").unwrap();
    cfg.set_protocols("tlsv1.2").unwrap();

    // This is not valid
    assert!(cfg.set_protocols("unknown-proto").is_err());
}

