//! Rust bindings for [libressl](http://libressl.org)'s libtls
//!
//! For the authoritative source on the inner workings of libtls check
//! the [manpage](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man3/tls_accept_fds.3?query=tls_init&sec=3).
//!
//! This is a minimal wrapper around the API. For higher level APIs check the **net** module.
//!

extern crate tls_sys as ffi;
extern crate libc;

use std::ffi::CString;
use libc::{time_t, c_void, size_t};
use std::ptr;
use std::error::Error;
use std::fmt;
use std::sync::{Once, ONCE_INIT};
use std::io;
use std::convert;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
#[cfg(windows)]
use std::os::windows::io::IntoRawSocket;

mod util;
use util::{from_cstr, str_c_ptr};

/// A structure that represents all TLS context
///
/// This can be a client connection, a server, or a connection accepted by the server
pub struct TlsContext {
    ptr: ffi::Tls,
    cfg: Option<TlsConfig>,
}

impl TlsContext {
    /// Create a new client context
    pub fn new_client() -> Option<TlsContext> {
        let p = unsafe { ffi::tls_client() };
        if p == ptr::null_mut() {
            None
        } else {
            Some(TlsContext {
                ptr: p,
                cfg: None,
            })
        }
    }

    fn error(&self) -> String {
        unsafe { from_cstr(ffi::tls_error(self.ptr)) }
    }

    fn rv_to_result(&self, rv: i64) -> TlsResult<()> {
        if rv == 0 {
            Ok(())
        } else {
            Err(TlsError {
                msg: self.error(),
                code: rv,
            })
        }
    }

    /// If port is empty, the port value is assumed to be part of the hostname string as host:port.
    /// If servername is not empty it is used instead of the hostname for verification.
    pub fn connect_servername(&mut self,
                              hostname: &str,
                              port: &str,
                              servername: &str)
                              -> TlsResult<()> {
        let rv = unsafe {
            let hostname_c = CString::from_vec_unchecked(hostname.bytes().collect()).as_ptr();
            // Both port and servername can be NULL
            let port_c = str_c_ptr(port);
            let servername_c = str_c_ptr(servername);
            ffi::tls_connect_servername(self.ptr, hostname_c, port_c, servername_c)
        };
        self.rv_to_result(rv as i64)
    }

    #[cfg(unix)]
    /// Establish a TLS connection over the given socket
    pub fn connect_socket<F: IntoRawFd>(&mut self, fd: F, servername: &str) -> TlsResult<()> {
        let rv = unsafe {
            let servername_c = str_c_ptr(servername);
            ffi::tls_connect_socket(self.ptr, fd.into_raw_fd(), servername_c)
        };
        self.rv_to_result(rv as i64)
    }

    #[cfg(windows)]
    /// Establish a TLS connection over the given socket
    pub fn connect_socket<F: IntoRawSocket>(&mut self, fd: F, servername: &str) -> TlsResult<()> {
        let rv = unsafe {
            let servername_c = str_c_ptr(servername);
            // This cast is not exactly safe
            // http://stackoverflow.com/questions/1953639/
            ffi::tls_connect_socket(self.ptr, fd.into_raw_socket() as i32, servername_c)
        };
        self.rv_to_result(rv as i64)
    }

    pub fn conn_version(&self) -> String {
        unsafe { from_cstr(ffi::tls_conn_version(self.ptr)) }
    }
    pub fn conn_cipher(&self) -> String {
        unsafe { from_cstr(ffi::tls_conn_cipher(self.ptr)) }
    }

    /// Apply configuration settings to the context, consuming the config struct
    ///
    /// This should be called BEFORE trying to establish/accept
    /// a connection
    pub fn configure(&mut self, cfg: TlsConfig) -> TlsResult<()> {
        let rv = unsafe { ffi::tls_configure(self.ptr, cfg.cfg) };
        self.cfg = Some(cfg);
        self.rv_to_result(rv as i64)
    }

    pub fn peer_cert_notbefore(&self) -> Option<time_t> {
        let rv = unsafe { ffi::tls_peer_cert_notbefore(self.ptr) };
        if rv == -1 {
            None
        } else {
            Some(rv)
        }
    }

    pub fn peer_cert_notafter(&self) -> Option<time_t> {
        let rv = unsafe { ffi::tls_peer_cert_notafter(self.ptr) };
        if rv == -1 {
            None
        } else {
            Some(rv)
        }
    }

    pub fn peer_cert_hash(&self) -> String {
        unsafe { from_cstr(ffi::tls_peer_cert_hash(self.ptr)) }
    }

    pub fn peer_cert_issuer(&self) -> String {
        unsafe { from_cstr(ffi::tls_peer_cert_issuer(self.ptr)) }
    }

    pub fn peer_cert_subject(&self) -> String {
        unsafe { from_cstr(ffi::tls_peer_cert_subject(self.ptr)) }
    }

    pub fn peer_cert_contains_name(&self, name: &str) -> bool {
        let rv = unsafe {
            let name_c = CString::from_vec_unchecked(name.bytes().collect());
            ffi::tls_peer_cert_contains_name(self.ptr, name_c.as_ptr())
        };
        (rv == 1)
    }

    pub fn peer_cert_provided(&self) -> bool {
        let rv = unsafe { ffi::tls_peer_cert_provided(self.ptr) };
        (rv == 1)
    }

    fn rv_to_result_io(&self, rv: i64) -> TlsResult<usize> {
        match rv {
            ffi::WANT_POLLIN => {
                Err(TlsError {
                    msg: String::new(),
                    code: rv,
                })
            }
            ffi::WANT_POLLOUT => {
                Err(TlsError {
                    msg: String::new(),
                    code: rv,
                })
            }
            rv if rv < 0 => {
                Err(TlsError {
                    msg: self.error(),
                    code: -1,
                })
            }
            rv => Ok(rv as usize),
        }
    }

    /// Complete the TLS handshake
    ///
    /// This function will be called when needed by `read()` or `write()`, but
    /// can be called to complete the handshake.
    pub fn handshake(&mut self) -> TlsResult<()> {
        let rv = unsafe { ffi::tls_handshake(self.ptr) };
        self.rv_to_result_io(rv as i64).map(|_| ())
    }

    pub fn close(&mut self) -> TlsResult<()> {
        let rv = unsafe { ffi::tls_close(self.ptr) };
        self.rv_to_result_io(rv as i64).map(|_| ())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> TlsResult<usize> {
        let buflen = buf.len() as size_t;
        let bptr = buf.as_mut_ptr() as *mut c_void;
        let rv = unsafe { ffi::tls_read(self.ptr, bptr, buflen) };
        self.rv_to_result_io(rv as i64)
    }

    pub fn write(&mut self, buf: &[u8]) -> TlsResult<usize> {
        let buflen = buf.len() as size_t;
        let bptr = buf.as_ptr() as *const c_void;
        let rv = unsafe { ffi::tls_write(self.ptr, bptr, buflen) };
        self.rv_to_result_io(rv as i64)
    }

    /// Create new server context
    pub fn new_server() -> Option<TlsContext> {
        let p = unsafe { ffi::tls_server() };
        if p == ptr::null_mut() {
            None
        } else {
            Some(TlsContext {
                ptr: p,
                cfg: None,
            })
        }
    }

    #[cfg(unix)]
    /// Accept a new TLS connection over an existing socket
    pub fn accept_socket<F: IntoRawFd>(&mut self, fd: F) -> TlsResult<TlsContext> {
        let mut cctx: ffi::Tls = ptr::null_mut();;
        let rv = unsafe { ffi::tls_accept_socket(self.ptr, &mut cctx, fd.into_raw_fd()) };
        self.rv_to_result(rv as i64)
            .map(|_| {
                TlsContext {
                    ptr: cctx,
                    cfg: None,
                }
            })
    }

    #[cfg(windows)]
    /// Accept a new TLS connection over an existing socket
    pub fn accept_socket<F: IntoRawSocket>(&mut self, fd: F) -> TlsResult<TlsContext> {
        let mut cctx: ffi::Tls = ptr::null_mut();;
        // This cast is not exactly safe
        // http://stackoverflow.com/questions/1953639/
        let rv = unsafe {
            ffi::tls_accept_socket(self.ptr, &mut cctx, fd.into_raw_socket() as i32)
        };
        self.rv_to_result(rv as i64)
            .map(|_| {
                TlsContext {
                    ptr: cctx,
                    cfg: None,
                }
            })
    }
}

impl Drop for TlsContext {
    fn drop(&mut self) {
        unsafe {
            ffi::tls_free(self.ptr);
        }
    }
}

/// TLS configuration settings, see `TlsContext::configure` to apply them
pub struct TlsConfig {
    cfg: ffi::Config,
}

impl TlsConfig {
    pub fn new() -> Option<TlsConfig> {
        let p = unsafe { ffi::tls_config_new() };
        if p == ptr::null_mut() {
            None
        } else {
            Some(TlsConfig { cfg: p })
        }
    }

    pub fn set_ca_file(&mut self, path: &str) -> Option<()> {
        let rv = unsafe {
            let path_c = CString::from_vec_unchecked(path.bytes().collect());
            ffi::tls_config_set_ca_file(self.cfg, path_c.as_ptr())
        };
        if rv == 0 {
            Some(())
        } else {
            None
        }
    }
    pub fn set_ca_path(&mut self, path: &str) -> Option<()> {
        let rv = unsafe {
            let path_c = str_c_ptr(path);
            ffi::tls_config_set_ca_path(self.cfg, path_c)
        };
        if rv == 0 {
            Some(())
        } else {
            None
        }
    }
    pub fn set_ca_mem(&mut self, ca: &str) -> Option<()> {
        let rv = unsafe { ffi::tls_config_set_ca_mem(self.cfg, ca.as_ptr(), ca.len()) };
        if rv == 0 {
            Some(())
        } else {
            None
        }
    }
    pub fn set_verify_depth(&mut self, depth: i32) {
        unsafe { ffi::tls_config_set_verify_depth(self.cfg, depth) }
    }
    pub fn insecure_noverifyname(&mut self) {
        unsafe { ffi::tls_config_insecure_noverifyname(self.cfg) }
    }
    pub fn insecure_noverifycert(&mut self) {
        unsafe { ffi::tls_config_insecure_noverifycert(self.cfg) }
    }
    pub fn set_key_file(&mut self, path: &str) -> Option<()> {
        let rv = unsafe {
            let path_c = CString::from_vec_unchecked(path.bytes().collect());
            ffi::tls_config_set_key_file(self.cfg, path_c.as_ptr())
        };
        if rv == 0 {
            Some(())
        } else {
            None
        }
    }
    pub fn set_cert_file(&mut self, path: &str) -> Option<()> {
        let rv = unsafe {
            let path_c = CString::from_vec_unchecked(path.bytes().collect());
            ffi::tls_config_set_cert_file(self.cfg, path_c.as_ptr())
        };
        if rv == 0 {
            Some(())
        } else {
            None
        }
    }
    pub fn set_protocols(&mut self, protocols: &str) -> Option<()> {
        let mut proto = 0;
        unsafe {
            let proto_c = CString::from_vec_unchecked(protocols.bytes().collect());
            if ffi::tls_config_parse_protocols(&mut proto, proto_c.as_ptr()) == -1 {
                return None;
            }
            ffi::tls_config_set_protocols(self.cfg, proto);
        }
        Some(())
    }
    pub fn set_ciphers(&mut self, ciphers: &str) -> Option<()> {
        let rv = unsafe {
            let ciphers_c = CString::from_vec_unchecked(ciphers.bytes().collect());
            ffi::tls_config_set_ciphers(self.cfg, ciphers_c.as_ptr())
        };
        if rv == 0 {
            Some(())
        } else {
            None
        }
    }
}

impl Drop for TlsConfig {
    fn drop(&mut self) {
        unsafe {
            ffi::tls_config_free(self.cfg);
        }
    }
}

#[derive(Debug)]
pub struct TlsError {
    msg: String,
    code: i64,
}

impl TlsError {
    /// The operation failed because it would block reading
    fn want_pollin(&self) -> bool {
        self.code == ffi::WANT_POLLIN
    }
    /// The operation failed because it would block writing
    fn want_pollout(&self) -> bool {
        self.code == ffi::WANT_POLLIN
    }
    fn wants_more(&self) -> bool {
        self.want_pollin() || self.want_pollout()
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl Error for TlsError {
    fn description(&self) -> &str {
        &self.msg
    }
}
/// Convert TlsError to io::Error, use WouldBlock if applicable
impl convert::From<TlsError> for io::Error {
    fn from(err: TlsError) -> Self {
        match err.code {
            ffi::WANT_POLLIN | ffi::WANT_POLLOUT => io::Error::new(io::ErrorKind::WouldBlock, err),
            _ => io::Error::new(io::ErrorKind::Other, err.msg),
        }
    }
}

/// Base result type for TLS operations
pub type TlsResult<T> = Result<T, TlsError>;

/// Initialize libtls - make sure to call this before using the API
/// Returns false if libtls failed to initialise.
pub fn init() -> bool {
    static mut RET: i32 = -1;
    static ONCE: Once = ONCE_INIT;
    ONCE.call_once(|| {
        util::other_init();
        unsafe { RET = ffi::tls_init() };
    });
    unsafe { (RET == 0) }
}

pub mod net;
