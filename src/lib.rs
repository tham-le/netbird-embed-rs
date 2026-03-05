mod error;
mod ffi;

pub use error::Error;

use serde::Deserialize;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};

const INITIAL_BUF_SIZE: usize = 4096;

/// Options for creating a NetBird embedded client.
#[derive(Debug, Default)]
pub struct ClientOptions {
    /// Setup key for headless registration.
    pub setup_key: Option<String>,
    /// NetBird management server URL.
    pub management_url: Option<String>,
    /// Human-readable device name.
    pub device_name: Option<String>,
    /// JWT token for OIDC-based registration.
    pub token: Option<String>,
}

/// A NetBird embedded client.
///
/// Wraps a Go `client/embed.Client` via FFI integer handle.
/// The client is stopped and freed on drop. Note that drop may block
/// while the Go runtime shuts down the WireGuard tunnel.
pub struct Client {
    handle: c_int,
}

// SAFETY: The Go side protects the handle map with `handleMu` and each
// client's mutable state (`lastErr`, `cancel`) with a per-client `mu`.
// The handle is just an integer ID — all Go operations are thread-safe.
unsafe impl Send for Client {}
unsafe impl Sync for Client {}

impl Client {
    /// Create a new NetBird client with the given options.
    pub fn new(opts: ClientOptions) -> Result<Self, Error> {
        let setup_key = make_cstring(opts.setup_key.as_deref())?;
        let management_url = make_cstring(opts.management_url.as_deref())?;
        let device_name = make_cstring(opts.device_name.as_deref())?;
        let token = make_cstring(opts.token.as_deref())?;

        let handle = unsafe {
            ffi::nb_new(
                cstr_ptr(&setup_key),
                cstr_ptr(&management_url),
                cstr_ptr(&device_name),
                cstr_ptr(&token),
            )
        };

        if handle < 0 {
            return Err(Error::Create(create_error_msg()));
        }

        Ok(Self { handle })
    }

    /// Start the client and join the mesh network.
    pub fn start(&self) -> Result<(), Error> {
        let rc = unsafe { ffi::nb_start(self.handle) };
        if rc != 0 {
            return Err(self.last_error_or(Error::Start));
        }
        Ok(())
    }

    /// Stop the client and leave the mesh network.
    pub fn stop(&self) -> Result<(), Error> {
        let rc = unsafe { ffi::nb_stop(self.handle) };
        if rc != 0 {
            return Err(self.last_error_or(Error::Stop));
        }
        Ok(())
    }

    /// Get the current client status including local peer info and all peers.
    pub fn status(&self) -> Result<Status, Error> {
        let json =
            self.call_json_buf(|buf, len| unsafe { ffi::nb_status(self.handle, buf, len) })?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Get the list of known peers.
    pub fn peers(&self) -> Result<Vec<Peer>, Error> {
        let json =
            self.call_json_buf(|buf, len| unsafe { ffi::nb_peers(self.handle, buf, len) })?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Dial a peer over the mesh network, returning a Unix stream.
    ///
    /// The returned stream is one end of a socketpair; the Go runtime
    /// pumps data between the other end and the mesh connection.
    ///
    /// `addr` should be in `"host:port"` format using the overlay IP.
    #[cfg(unix)]
    pub fn dial(&self, network: &str, addr: &str) -> Result<std::os::unix::net::UnixStream, Error> {
        let net_type = CString::new(network).map_err(|_| Error::Dial)?;
        let c_addr = CString::new(addr).map_err(|_| Error::Dial)?;

        let fd = unsafe { ffi::nb_dial(self.handle, net_type.as_ptr(), c_addr.as_ptr()) };
        if fd < 0 {
            return Err(self.last_error_or(Error::Dial));
        }

        // SAFETY: Go gave us ownership of this FD via socketpair.
        Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd as RawFd) })
    }

    /// Listen on a mesh address, returning a listener that yields Unix streams.
    ///
    /// The returned [`Listener`] reads accepted connection FDs from the Go
    /// accept loop over a signaling socketpair.
    ///
    /// `addr` should be in `":port"` or `"host:port"` format.
    #[cfg(unix)]
    pub fn listen(&self, addr: &str) -> Result<Listener, Error> {
        let net_type = CString::new("tcp").expect("static string");
        let c_addr = CString::new(addr).map_err(|_| Error::Listen)?;

        let fd = unsafe { ffi::nb_listen(self.handle, net_type.as_ptr(), c_addr.as_ptr()) };
        if fd < 0 {
            return Err(self.last_error_or(Error::Listen));
        }

        // SAFETY: Go gave us ownership of this signaling FD via socketpair.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd as RawFd) };
        Ok(Listener { signal: stream })
    }

    fn last_error(&self) -> Option<String> {
        let mut buf = vec![0u8; 512];
        unsafe {
            ffi::nb_errmsg(
                self.handle,
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as c_int,
            );
        }
        let msg = cstr_from_buf(&buf);
        if msg.is_empty() || msg == "no error" {
            None
        } else {
            Some(msg)
        }
    }

    fn last_error_or(&self, fallback: Error) -> Error {
        self.last_error().map(Error::Ffi).unwrap_or(fallback)
    }

    /// Call a Go function that writes JSON into a caller-provided buffer.
    /// Retries with a larger buffer if ERANGE is returned.
    fn call_json_buf<F>(&self, f: F) -> Result<String, Error>
    where
        F: Fn(*mut c_char, c_int) -> c_int,
    {
        let mut size = INITIAL_BUF_SIZE;
        loop {
            let mut buf = vec![0u8; size];
            let rc = f(buf.as_mut_ptr() as *mut c_char, size as c_int);

            if rc == 0 {
                return Ok(cstr_from_buf(&buf));
            }

            if rc == libc::ERANGE as c_int {
                size *= 2;
                if size > 1024 * 1024 {
                    return Err(Error::BufferTooSmall);
                }
                continue;
            }

            return Err(self.last_error_or(Error::Ffi("unknown error".into())));
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { ffi::nb_free(self.handle) };
    }
}

/// A mesh network listener that yields Unix streams for accepted connections.
///
/// The Go accept loop sends accepted connection FDs as 4-byte LE integers
/// over a signaling socketpair. This type reads those integers and wraps
/// the FDs as `UnixStream`s.
#[cfg(unix)]
pub struct Listener {
    signal: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
impl Listener {
    /// Accept the next connection from the mesh listener.
    ///
    /// Blocks until a connection is available or the listener is closed.
    pub fn accept(&self) -> Result<std::os::unix::net::UnixStream, Error> {
        use std::io::Read;

        let mut fd_buf = [0u8; 4];
        (&self.signal)
            .read_exact(&mut fd_buf)
            .map_err(|_| Error::Listen)?;
        let fd = u32::from_le_bytes(fd_buf) as RawFd;

        // SAFETY: Go created this FD via socketpair and sent the integer
        // over the signal socket. Both sides are in the same process, so
        // the FD is valid. Ownership is transferred to us.
        Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) })
    }
}

/// Full client status including local peer info and connected peers.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    /// Local overlay IP address.
    pub ip: String,
    /// Local WireGuard public key.
    pub pub_key: String,
    /// Local FQDN on the mesh.
    #[serde(default)]
    pub fqdn: String,
    /// Management server connection state.
    pub management_state: String,
    /// Signal server connection state.
    pub signal_state: String,
    /// Connected peers.
    #[serde(default)]
    pub peers: Vec<Peer>,
    /// Error message if any.
    #[serde(default)]
    pub error: Option<String>,
}

/// A peer on the mesh network.
#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    /// Peer's overlay IP address.
    pub ip: String,
    /// Peer's WireGuard public key.
    pub pub_key: String,
    /// Peer's FQDN on the mesh.
    #[serde(default)]
    pub fqdn: String,
    /// Connection status: "connected" or "disconnected".
    pub conn_status: String,
    /// Whether the connection is relayed (not direct P2P).
    #[serde(default)]
    pub relayed: bool,
    /// Round-trip latency as a duration string.
    #[serde(default)]
    pub latency: String,
}

impl Peer {
    pub fn is_connected(&self) -> bool {
        self.conn_status == "connected"
    }
}

fn create_error_msg() -> String {
    let mut buf = vec![0u8; 512];
    unsafe {
        ffi::nb_create_errmsg(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int);
    }
    let msg = cstr_from_buf(&buf);
    if msg.is_empty() || msg == "no error" {
        "unknown error".into()
    } else {
        msg
    }
}

fn make_cstring(s: Option<&str>) -> Result<Option<CString>, Error> {
    match s {
        Some(s) => CString::new(s).map(Some).map_err(|_| Error::InteriorNul),
        None => Ok(None),
    }
}

fn cstr_ptr(s: &Option<CString>) -> *const c_char {
    match s {
        Some(cs) => cs.as_ptr(),
        None => std::ptr::null(),
    }
}

fn cstr_from_buf(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
