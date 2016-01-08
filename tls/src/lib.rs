//! Rust bindings for [libressl](http://libressl.org)'s libtls
//! For the authoritative source on the inner workings of libtls check
//! the [manpage](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man3/tls_accept_fds.3?query=tls_init&sec=3).
//!
//! ## Client
//!
//! ```no_run
//! use std::io::Write;
//! tls::init();
//! let mut client = tls::new_client()
//!     .connect("www.duckduckgo.com", "443", None)
//!     .unwrap();
//! client.write("GET / HTTP/1.1\n\n".as_bytes()).unwrap();
//! ```
//!
//! ## Server
//!
//! The library does not handle TCP listening and binding, you need to handle the
//! TCP server accept() and then call `TlsServer::accept`
//!
//! ```no_run
//! use std::net::TcpListener;
//! tls::init();
//! let srv = TcpListener::bind("127.0.0.1:0").unwrap();
//! let addr = srv.local_addr().unwrap();
//! let mut tls_srv = tls::new_server()
//!     .key_file("tests/private_key.key")
//!     .cert_file("tests/certificate.crt")
//!     .bind().unwrap();
//! // Accept TCP connection, and then start TLS over it
//! let tcp_conn = srv.incoming().next().unwrap().unwrap();
//! let mut tls_conn = tls_srv.accept(tcp_conn).unwrap();
//! ```
//!
//! ## Certificate Verification
//!
//! By default libtls will verify certificates using the system certificate store (usually defined
//! as /etc/ssl/cert.pem). In some Linux flavours and in Windows this file does not exist and you
//! will need to use one of the appropriate methods to load the correct certificates for your
//! system - check the Builder classes for the ca methods.

extern crate libc;

/// TODO: Remove this from the public API
use libc::time_t;
use std::error::Error;
use std::io;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
#[cfg(windows)]
use std::os::windows::io::IntoRawSocket;

mod util;
mod raw;
use raw::{TlsConfig, TlsContext};

pub use raw::{TlsResult, TlsError, init};

pub struct ClientBuilder {
    cfg: Option<TlsConfig>,
    error: Option<TlsError>,
}

impl ClientBuilder {
    /// Load CA certificates from PEM file
    pub fn ca_file(mut self, path: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_ca_file(path).err();
        }
        self
    }
    /// Load CA certificates from folder
    pub fn ca_path(mut self, path: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_ca_path(path).err();
        }
        self
    }
    /// Use CA certificates from PEM string
    pub fn ca(mut self, ca: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_ca_mem(ca).err();
        }
        self
    }
    pub fn verify_depth(mut self, depth: i32) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            cfg.set_verify_depth(depth);
        }
        self
    }
    pub fn protocols(mut self, protocols: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_protocols(protocols).err();
        }
        self
    }
    pub fn ciphers(mut self, ciphers: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_ciphers(ciphers).err();
        }
        self
    }
    /// Disable certificate verification
    pub fn insecure_noverifycert(mut self) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            cfg.insecure_noverifycert();
        }
        self
    }
    /// Disable hostname verification
    pub fn insecure_noverifyname(mut self) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            cfg.insecure_noverifyname();
        }
        self
    }

    /// Create client context from settings
    fn new_ctx(self) -> TlsResult<TlsContext> {
        if let Some(err) = self.error {
            Err(err)
        } else {
            let mut cli = try!(TlsContext::new_client());
            // This unwrap should be safe, we can't have a cfg without an error
            try!(cli.configure(self.cfg.unwrap()));
            Ok(cli)
        }
    }

    /// Open Connection to remote host
    ///
    /// - If port is empty, the port value is assumed to be part of the hostname string as `host:port`.
    /// - If servername is not empty it is used instead of the hostname for verification.
    pub fn connect(self,
                   hostname: &str,
                   port: &str,
                   servername: Option<&str>)
                   -> TlsResult<TlsStream> {
        let mut ctx = try!(self.new_ctx());
        try!(ctx.connect_servername(hostname, port, servername.unwrap_or("")));
        Ok(TlsStream { ctx: ctx })
    }

    #[cfg(unix)]
    /// Establish a TLS connection over the given socket
    pub fn connect_socket<F: IntoRawFd>(self, fd: F, servername: &str) -> TlsResult<TlsStream> {
        let mut ctx = try!(self.new_ctx());
        try!(ctx.connect_socket(fd, servername));
        Ok(TlsStream { ctx: ctx })
    }

    #[cfg(windows)]
    /// Establish a TLS connection over the given socket
    pub fn connect_socket<F: IntoRawSocket>(self, fd: F, servername: &str) -> TlsResult<TlsStream> {
        let mut ctx = try!(self.new_ctx());
        try!(ctx.connect_socket(fd, servername));
        Ok(TlsStream { ctx: ctx })
    }
}

/// Create a new TLS client
pub fn new_client() -> ClientBuilder {
    match TlsConfig::new() {
        Ok(cfg) => {
            ClientBuilder {
                cfg: Some(cfg),
                error: None,
            }
        }
        Err(err) => {
            ClientBuilder {
                cfg: None,
                error: Some(err),
            }
        }
    }
}

pub struct TlsStream {
    ctx: TlsContext,
}

impl TlsStream {
    /// Executes the TLS handshake. This function is automatically called when reading or writing,
    /// you usually don't need to call it unless you want to force the handshake to finish sooner.
    ///
    /// Calling handshake multiple times, if the other end of the connection is not expecting it
    /// will usually result in an error.
    pub fn handshake(&mut self) -> TlsResult<()> {
        self.ctx.handshake()
    }

    /// Close the connection
    pub fn shutdown(&mut self) -> io::Result<()> {
        if let Err(err) = self.ctx.close() {
            if err.wants_more() {
                try!(self.ctx.close());
            } else {
                return Err(io::Error::from(err));
            }
        }
        Ok(())
    }

    pub fn certificate_issuer(&self) -> String {
        self.ctx.peer_cert_issuer()
    }
    pub fn certificate_hash(&self) -> String {
        self.ctx.peer_cert_hash()
    }
    pub fn certificate_subject(&self) -> String {
        self.ctx.peer_cert_subject()
    }
    pub fn peer_cert_provided(&self) -> bool {
        self.ctx.peer_cert_provided()
    }
    pub fn peer_cert_notbefore(&self) -> TlsResult<time_t> {
        self.ctx.peer_cert_notbefore()
    }
    pub fn peer_cert_notafter(&self) -> TlsResult<time_t> {
        self.ctx.peer_cert_notafter()
    }
    pub fn peer_cert_contains_name(&self, name: &str) -> bool {
        self.ctx.peer_cert_contains_name(name)
    }
    pub fn version(&self) -> String {
        self.ctx.conn_version()
    }
    pub fn cipher(&self) -> String {
        self.ctx.conn_cipher()
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ctx
            .read(buf)
            .map_err(|err| io::Error::from(err))
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ctx
            .write(buf)
            .map_err(|err| io::Error::from(err))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        let _ = self.ctx.close();
    }
}

pub struct ServerBuilder {
    cfg: Option<TlsConfig>,
    error: Option<TlsError>,
}

impl ServerBuilder {
    pub fn key_file(mut self, path: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_key_file(path).err();
        }
        self
    }
    pub fn cert_file(mut self, path: &str) -> Self {
        if self.error.is_some() {
            return self;
        }
        if let Some(cfg) = self.cfg.as_mut() {
            self.error = cfg.set_cert_file(path).err();
        }
        self
    }

    /// Create server context from settings
    fn new_ctx(self) -> TlsResult<TlsContext> {
        if let Some(err) = self.error {
            Err(err)
        } else {
            let mut cli = try!(TlsContext::new_server());
            // This unwrap should be safe, we can't have a cfg without an error
            try!(cli.configure(self.cfg.unwrap()));
            Ok(cli)
        }
    }
    pub fn bind(self) -> TlsResult<TlsServer> {
        let ctx = try!(self.new_ctx());
        Ok(TlsServer { ctx: ctx })
    }
}

/// Create a new TLS server
pub fn new_server() -> ServerBuilder {
    match TlsConfig::new() {
        Ok(cfg) => {
            ServerBuilder {
                cfg: Some(cfg),
                error: None,
            }
        }
        Err(err) => {
            ServerBuilder {
                cfg: None,
                error: Some(err),
            }
        }
    }
}

/// TLS Server, used to start TLS session over existing sockets.
pub struct TlsServer {
    ctx: TlsContext,
}

impl TlsServer {
    #[cfg(unix)]
    /// Start a new TLS connection over an existing socket (server-side)
    pub fn accept<F: IntoRawFd>(&mut self, fd: F) -> io::Result<TlsStream> {
        let c = try!(self.ctx.accept_socket(fd));
        Ok(TlsStream { ctx: c })
    }

    #[cfg(windows)]
    /// Start a new TLS connection over an existing socket (server-side)
    pub fn accept<F: IntoRawSocket>(&mut self, fd: F) -> TlsResult<TlsStream> {
        let c = try!(self.ctx.accept_socket(fd));
        Ok(TlsStream { ctx: c })
    }
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
