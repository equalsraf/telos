//! Rust bindings for [libressl](http://libressl.org)'s libtls
//! For the authoritative source on the inner workings of libtls check
//! the [manpage](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man3/tls_accept_fds.3?query=tls_init&sec=3).
//!
//! ## Client
//!
//! ```no_run
//! use std::io::Write;
//! use std::net::TcpStream;
//! let tcp = TcpStream::connect("google.com:443").unwrap();
//! let mut client = tls::new_client()
//!     .from_socket(&tcp, "google.com")
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
//! let srv = TcpListener::bind("127.0.0.1:0").unwrap();
//! let addr = srv.local_addr().unwrap();
//! let mut tls_srv = tls::new_server()
//!     .key_file("tests/private_key.key")
//!     .cert_file("tests/certificate.crt")
//!     .bind().unwrap();
//! // Accept TCP connection, and then start TLS over it
//! let tcp_conn = srv.incoming().next().unwrap().unwrap();
//! let mut tls_conn = tls_srv.accept(&tcp_conn).unwrap();
//! ```
//!
//! ## Certificate Verification
//!
//! By default libtls will verify certificates using the system certificate store (usually defined
//! as /etc/ssl/cert.pem). In some Linux flavours and in Windows this file does not exist and you
//! will need to use one of the appropriate methods to load the correct certificates for your
//! system - check the Builder classes for the ca methods.
//!
//! ## Connection Lifetime
//!
//! The `from_socket()` and `accept()` methods build new connections on top of
//! `RawFd`/`RawSocket`. Destroying the TlsStream object WILL NOT cause the underlying
//! sockets to be closed, you need to close them yourself.

extern crate libc;

/// TODO: Remove this from the public API
use libc::time_t;
use std::error::Error;
use std::io;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

mod util;
mod raw;
use raw::{TlsConfig, TlsContext};

pub use raw::{TlsResult, TlsError};

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

    #[cfg(unix)]
    /// Establish a TLS connection over the given socket
    pub fn from_socket<F: AsRawFd>(self, ifd: &F, servername: &str) -> TlsResult<TlsStream> {
        let mut ctx = try!(self.new_ctx());
        let fd = ifd.as_raw_fd();
        try!(ctx.connect_socket(fd, servername));
        Ok(TlsStream {
            ctx: ctx,
        })
    }

    #[cfg(windows)]
    /// Establish a TLS connection over the given socket
    pub fn from_socket<F: AsRawSocket>(self, isock: &F, servername: &str) -> TlsResult<TlsStream> {
        let mut ctx = try!(self.new_ctx());
        let sock = isock.as_raw_socket();
        try!(ctx.connect_socket(sock, servername));
        Ok(TlsStream { ctx: ctx })
    }
}

/// Create a new TLS client
pub fn new_client() -> ClientBuilder {
    if !raw::init() {
        return ClientBuilder {
            cfg: None,
            error: Some(TlsError::new("Failed to initialize libtls")),
        }
    }

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

    /// Close TLS connection. This will not close the underlying transport.
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

    /// Calling this method before the handshake is complete causes this method
    /// to return an empty string. See [handshake()](#method.handshake).
    pub fn certificate_issuer(&self) -> String {
        self.ctx.peer_cert_issuer()
    }
    /// Calling this method before the handshake is complete causes this method
    /// to return an empty string. See [handshake()](#method.handshake).
    pub fn certificate_hash(&self) -> String {
        self.ctx.peer_cert_hash()
    }
    /// Calling this method before the handshake is complete causes this method
    /// to return an empty string. See [handshake()](#method.handshake).
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
    /// Calling this method before the handshake is complete causes this method
    /// to return an empty string. See [handshake()](#method.handshake).
    pub fn version(&self) -> String {
        self.ctx.conn_version()
    }
    /// Calling this method before the handshake is complete causes this method
    /// to return an empty string. See [handshake()](#method.handshake).
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
    if !raw::init() {
        return ServerBuilder {
            cfg: None,
            error: Some(TlsError::new("Failed to initialize libtls")),
        }
    }

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
    pub fn accept<F: AsRawFd>(&mut self, ifd: &F) -> io::Result<TlsStream> {
        let fd = ifd.as_raw_fd();
        let c = try!(self.ctx.accept_socket(fd));
        Ok(TlsStream {
            ctx: c,
        })
    }

    #[cfg(windows)]
    /// Start a new TLS connection over an existing socket (server-side)
    pub fn accept<F: AsRawSocket>(&mut self, isock: &F) -> TlsResult<TlsStream> {
        let sock = isock.as_raw_socket();
        let c = try!(self.ctx.accept_socket(sock));
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
