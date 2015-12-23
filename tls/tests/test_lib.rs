extern crate tls;
use tls::init;

#[test]
fn test_init() {
    assert_eq!(init(), true);
    assert_eq!(init(), true);
}
