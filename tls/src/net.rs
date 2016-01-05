//! Higher level libtls API wrappers to use along with the Rust
//! standard library

use super::{TlsContext, TlsConfig};
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct TlsConnection {
    cfg: TlsConfig,
}
impl TlsConnection {
    pub fn new() -> Option<TlsConnection> {
        if let Some(cfg) = TlsConfig::new() {
            Some(TlsConnection { cfg: cfg })
        } else {
            None
        }
    }

    /// Connect to server, and process the TLS handshake
    pub fn connect(self, hostname: &str, port: &str) -> io::Result<TlsStream> {
        let mut c = try!(TlsStream::new_client());
        try!(c.configure(self.cfg));
        try!(c.connect_servername(hostname, port, ""));
        if let Err(err) = c.handshake() {
            if err.wants_more() {
                try!(c.handshake());
            } else {
                return Err(io::Error::from(err));
            }
        }
        Ok(TlsStream { ctx: c })
    }

    /// Create a new TLS stream from an existing TCP stream
    pub fn from_tcp_stream(self, tcp: TcpStream, servername: &str) -> io::Result<TlsStream> {
        let mut c = try!(TlsStream::new_client());
        try!(c.configure(self.cfg));
        try!(c.connect_socket(tcp, servername)
              .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg)));
        if let Err(err) = c.handshake() {
            if err.wants_more() {
                try!(c.handshake());
            } else {
                return Err(io::Error::from(err));
            }
        }
        Ok(TlsStream { ctx: c })
    }


    pub fn set_ca_file(&mut self, path: &str) -> Option<()> {
        self.cfg.set_ca_file(path)
    }
    pub fn set_ca_path(&mut self, path: &str) -> Option<()> {
        self.cfg.set_ca_path(path)
    }
    pub fn set_ca_mem(&mut self, ca: &str) -> Option<()> {
        self.cfg.set_ca_mem(ca)
    }
    pub fn set_verify_depth(&mut self, depth: i32) {
        self.cfg.set_verify_depth(depth)
    }
    pub fn set_protocols(&mut self, protocols: &str) -> Option<()> {
        self.cfg.set_protocols(protocols)
    }
    pub fn set_ciphers(&mut self, ciphers: &str) -> Option<()> {
        self.cfg.set_ciphers(ciphers)
    }
    pub fn insecure_noverifycert(&mut self) {
        self.cfg.insecure_noverifycert()
    }
    pub fn insecure_noverifyname(&mut self) {
        self.cfg.insecure_noverifyname()
    }
}

pub struct TlsStream {
    ctx: TlsContext,
}

impl TlsStream {
    /// Convinience method to create TlsContext clients
    fn new_client() -> io::Result<TlsContext> {
        TlsContext::new_client()
            .ok_or(io::Error::new(io::ErrorKind::Other, "Failed to create new TLS context"))
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
