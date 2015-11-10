//! Higher level libtls API wrappers to use along with the Rust
//! standard library

use super::{TlsContext,TlsConfig};
use std::io;
use std::io::{Read,Write};
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
                return Err(io::Error::from(err))
            }
        }
        Ok(TlsStream {ctx: c})
    }

    pub fn set_ca_file(&mut self, path: &str) -> Option<()> {
        self.cfg.set_ca_file(path)
    }
    pub fn set_ca_path(&mut self, path: &str) -> Option<()> {
        self.cfg.set_ca_path(path)
    }
    pub fn set_verify_depth(&mut self, depth: i32 ) {
        self.cfg.set_verify_depth(depth)
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
                return Err(io::Error::from(err))
            }
        }
        Ok(())
    }

    /// Create a new TLS stream from an existing TCP stream
    pub fn from_tcp_stream(tcp: TcpStream, servername: &str) -> io::Result<TlsStream> {
        let mut c = try!(TlsStream::new_client());
        try!(c.connect_socket(tcp, servername)
             .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg)));
        Ok(TlsStream {ctx: c})
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ctx.read(buf)
            .map_err(|err| io::Error::from(err))
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ctx.write(buf)
            .map_err(|err| io::Error::from(err))
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        let _ = self.ctx.close();
    }
}
