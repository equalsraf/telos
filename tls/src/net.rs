//! Higher level libtls API wrappers to use along with the Rust
//! standard library

use super::{TlsContext, TlsConfig};
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct TlsStream {
    ctx: TlsContext,
}

impl TlsStream {
    /// Convinience method to create TlsContext clients
    fn new_client() -> io::Result<TlsContext> {
        TlsContext::new_client().map_err(|err| io::Error::from(err))
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

pub struct TlsListenerBuilder {
    cfg: TlsConfig,
}

impl TlsListenerBuilder {
    pub fn set_key_file(&mut self, path: &str) -> io::Result<()> {
        self.cfg.set_key_file(path)
                    .map_err(|err| io::Error::from(err))
    }
    pub fn set_cert_file(&mut self, path: &str) -> io::Result<()> {
        self.cfg.set_cert_file(path)
                    .map_err(|err| io::Error::from(err))
    }
    pub fn bind(self) -> io::Result<TlsListener> {
        let mut srv = try!(TlsListener::new_server());
        try!(srv.configure(self.cfg));
        Ok(TlsListener {
            ctx: srv,
        })
    }
}

pub struct TlsListener {
    ctx: TlsContext,
}

impl TlsListener {

    fn new_server() -> io::Result<TlsContext> {
        TlsContext::new_server().map_err(|err| io::Error::from(err))
    }

    pub fn new() -> io::Result<TlsListenerBuilder> {
        let cfg = try!(TlsConfig::new()
                    .map_err(|err| io::Error::from(err)));
        Ok(TlsListenerBuilder { cfg: cfg })
    }

    pub fn accept(&mut self, tcp: TcpStream) -> io::Result<TlsStream> {
        let mut c = try!(self.ctx.accept_socket(tcp));
        if let Err(err) = c.handshake() {
            if err.wants_more() {
                try!(c.handshake());
            } else {
                return Err(io::Error::from(err));
            }
        }
        Ok(TlsStream {
            ctx: c,
        })
    }
}
