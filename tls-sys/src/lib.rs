extern crate libc;
use libc::{c_int,c_void,c_char,time_t,ssize_t,size_t,uint8_t,uint32_t};

pub type Tls = *mut c_void;
pub type Config = *mut c_void;

pub const WANT_POLLIN: i64 = -2;
pub const WANT_POLLOUT: i64 = -3;

extern "C" {
    pub fn tls_init() -> c_int;
    pub fn tls_free(ctx: Tls);
    pub fn tls_error(ctx: Tls) -> *const c_char;
    pub fn tls_configure(ctx: Tls, cfg: Config) -> c_int;

    pub fn tls_config_new() -> Config;
    pub fn tls_config_free(cfg: Config);
    pub fn tls_config_set_ca_file(cfg: Config, ca_file: *const c_char) -> c_int;
    pub fn tls_config_set_ca_path(cfg: Config, ca_file: *const c_char) -> c_int;
    pub fn tls_config_set_ca_mem(cfg: Config, ca: *const uint8_t, len: size_t) -> c_int;
    pub fn tls_config_set_verify_depth(cfg: Config, depth: c_int);
    pub fn tls_config_set_key_file(cfg: Config, key_file: *const c_char) -> c_int;
    pub fn tls_config_set_cert_file(cfg: Config, key_file: *const c_char) -> c_int;
    pub fn tls_config_insecure_noverifyname(cfg: Config);
    pub fn tls_config_insecure_noverifycert(cfg: Config);
    pub fn tls_config_set_protocols(cfg: Config, protocols: uint32_t);
    pub fn tls_config_parse_protocols(protocols: *mut uint32_t, protocols: *const c_char) -> c_int;

    pub fn tls_conn_version(ctx: Tls) -> *const c_char;
    pub fn tls_conn_cipher(ctx: Tls) -> *const c_char;

    pub fn tls_peer_cert_notbefore(ctx: Tls) -> time_t;
    pub fn tls_peer_cert_notafter(ctx: Tls) -> time_t;
    pub fn tls_peer_cert_issuer(ctx: Tls) -> *const c_char;
    pub fn tls_peer_cert_subject(ctx: Tls) -> *const c_char;
    pub fn tls_peer_cert_hash(ctx: Tls) -> *const c_char;
    pub fn tls_peer_cert_contains_name(ctx: Tls, name: *const c_char) -> c_int;
    pub fn tls_peer_cert_provided(ctx: Tls) -> c_int;

    pub fn tls_client() -> Tls;
    pub fn tls_connect(ctx: Tls, hostname: *const c_char, port: *const c_char) -> c_int;
    pub fn tls_connect_servername(ctx: Tls, hostname: *const c_char, port: *const c_char,
                                  servername: *const c_char) -> c_int;
    pub fn tls_connect_fds(ctx: Tls, fd_read: c_int, fd_write: c_int,
                                servername: *const c_char) -> c_int;
    pub fn tls_connect_socket(ctx: Tls, fd: c_int, servername: *const c_char) -> c_int;
    pub fn tls_handshake(ctx: Tls) -> c_int;
    pub fn tls_read(ctx: Tls, buf: *mut c_void, buflen: size_t) -> ssize_t;
    pub fn tls_write(ctx: Tls, buf: *const c_void, buflen: size_t) -> ssize_t;
    pub fn tls_close(ctx: Tls) -> c_int;

    pub fn tls_server() -> Tls;
    pub fn tls_accept_socket(ctx: Tls, cctx: *mut Tls, fd: c_int) -> c_int;
}

// A minimal test, enough to force a sanity check on the linkage
#[test]
fn test_init() {
    unsafe {tls_init();}
}

