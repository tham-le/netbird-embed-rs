//! Rust bindings for [NetBird's `client/embed`](https://github.com/netbirdio/netbird/tree/main/client/embed)
//! via Go C-shared FFI.
//!
//! Embeds a full NetBird node (WireGuard mesh networking) into any Rust
//! application — no separate VPN client needed.
//!
//! # Cross-platform support
//!
//! The core API ([`Client::new`], [`Client::start`], [`Client::status`],
//! [`Client::start_proxy`], etc.) works on all platforms. Direct mesh
//! sockets ([`Client::dial`], [`Client::dial_udp`], [`Client::listen`],
//! [`Client::listen_udp`]) require Unix (socketpair-based).
//!
//! On Windows, use [`Client::start_proxy`] to get a localhost port that
//! forwards to a mesh peer, then connect with standard sockets.
//!
//! # Additional features
//!
//! [`ClientOptions`] exposes IPv6, Rosenpass, LAN-access, lazy-connection, MTU,
//! DNS-label, NAT-address, and performance settings. Running clients can resolve
//! peers with [`Client::identity_for_ip`], expose local services with
//! [`Client::expose`], tune buffer pooling with [`Client::set_performance`],
//! and record pcap/text captures with [`Client::start_capture`].
//!
//! [`ExposeSession::stop`] and its destructor wait for the keep-alive task and
//! may block for up to ~10 seconds; [`Client::stop`] and dropping the client
//! cancel and wait for every session. [`Client::start_capture`] is file-based
//! and requires at least one output path.
//!
//! # Example
//!
//! ```no_run
//! use netbird_embed::{Client, ClientOptions, ConnectionState};
//!
//! let client = Client::new(ClientOptions {
//!     setup_key: Some("YOUR-SETUP-KEY".into()),
//!     management_url: Some("https://api.netbird.io".into()),
//!     ..Default::default()
//! })?;
//!
//! client.start()?;
//!
//! let status = client.status()?;
//! println!("Overlay IP: {}", status.ip);
//!
//! // Cross-platform: proxy to a peer's service
//! let port = client.start_proxy("100.64.0.2:8080")?;
//! let stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod error;
mod ffi;

pub use error::Error;

use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

const INITIAL_BUF_SIZE: usize = 4096;

/// Connection state for the client, management server, or signal server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Connected,
    Connecting,
    #[default]
    Disconnected,
    #[serde(other)]
    Unknown,
}

/// Tunnel performance knobs for the embedded client.
///
/// These settings are process-global upstream: any value set here also becomes
/// the default for clients created later in the same process.
#[derive(Debug, Default, Clone, Copy)]
pub struct Performance {
    /// Caps the per-tunnel buffer pool. Zero leaves the pool unbounded.
    /// Runtime changes via [`Client::set_performance`] only take effect when
    /// this was set to a nonzero value at construction.
    pub preallocated_buffers_per_pool: Option<u32>,
    /// Number of packets read or written per syscall. Construction-only
    /// upstream; [`Client::set_performance`] rejects it.
    pub max_batch_size: Option<u32>,
}

/// Options for creating a NetBird embedded client.
#[derive(Default)]
pub struct ClientOptions {
    /// Setup key for headless registration.
    pub setup_key: Option<String>,
    /// NetBird management server URL.
    pub management_url: Option<String>,
    /// Human-readable device name.
    pub device_name: Option<String>,
    /// JWT token for OIDC-based registration.
    pub token: Option<String>,
    /// WireGuard private key (base64). Generated automatically if not set.
    pub private_key: Option<String>,
    /// WireGuard pre-shared key (base64).
    pub pre_shared_key: Option<String>,
    /// Log level: "panic", "fatal", "error", "warn", "info", "debug", "trace".
    pub log_level: Option<String>,
    /// Path to the NetBird config file.
    pub config_path: Option<String>,
    /// Path to the NetBird state file.
    pub state_path: Option<String>,
    /// WireGuard listen port. Use `Some(0)` for a random port (avoids conflicts
    /// with other WireGuard instances). `None` uses the NetBird default (51820).
    pub wireguard_port: Option<i32>,
    /// Disable client routes advertised by peers.
    pub disable_client_routes: bool,
    /// Block inbound connections from peers.
    pub block_inbound: bool,
    /// Disable userspace WireGuard (use kernel module instead).
    pub no_userspace: bool,
    /// Disable IPv6 overlay addressing.
    pub disable_ipv6: bool,
    /// Enable the Rosenpass post-quantum key exchange.
    pub enable_rosenpass: bool,
    /// Allow a Rosenpass-enabled peer to connect to peers without Rosenpass.
    pub rosenpass_permissive: bool,
    /// Block the embedded peer from reaching the host's LAN.
    pub block_lan_access: bool,
    /// Tri-state override for lazy connections. `None` defers to the
    /// management feature flag.
    pub lazy_connection_enabled: Option<bool>,
    /// Tunnel MTU (576..=8192). `None` keeps the config/default MTU.
    pub mtu: Option<u16>,
    /// Additional DNS labels configured in the peer.
    pub dns_labels: Vec<String>,
    /// NAT external IP mappings for ICE candidates.
    pub nat_external_ips: Vec<String>,
    /// Tunnel performance knobs.
    pub performance: Performance,
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOptions")
            .field("setup_key", &redacted(&self.setup_key))
            .field("management_url", &self.management_url)
            .field("device_name", &self.device_name)
            .field("token", &redacted(&self.token))
            .field("private_key", &redacted(&self.private_key))
            .field("pre_shared_key", &redacted(&self.pre_shared_key))
            .field("log_level", &self.log_level)
            .field("config_path", &self.config_path)
            .field("state_path", &self.state_path)
            .field("wireguard_port", &self.wireguard_port)
            .field("disable_client_routes", &self.disable_client_routes)
            .field("block_inbound", &self.block_inbound)
            .field("no_userspace", &self.no_userspace)
            .field("disable_ipv6", &self.disable_ipv6)
            .field("enable_rosenpass", &self.enable_rosenpass)
            .field("rosenpass_permissive", &self.rosenpass_permissive)
            .field("block_lan_access", &self.block_lan_access)
            .field("lazy_connection_enabled", &self.lazy_connection_enabled)
            .field("mtu", &self.mtu)
            .field("dns_labels", &self.dns_labels)
            .field("nat_external_ips", &self.nat_external_ips)
            .field("performance", &self.performance)
            .finish()
    }
}

fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
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
        let private_key = make_cstring(opts.private_key.as_deref())?;
        let pre_shared_key = make_cstring(opts.pre_shared_key.as_deref())?;
        let log_level = make_cstring(opts.log_level.as_deref())?;
        let config_path = make_cstring(opts.config_path.as_deref())?;
        let state_path = make_cstring(opts.state_path.as_deref())?;
        let dns_labels = json_list(&opts.dns_labels)?;
        let nat_external_ips = json_list(&opts.nat_external_ips)?;

        let wg_port = opts.wireguard_port.unwrap_or(-1);

        let handle = unsafe {
            ffi::nb_new(
                cstr_ptr(&setup_key),
                cstr_ptr(&management_url),
                cstr_ptr(&device_name),
                cstr_ptr(&token),
                cstr_ptr(&private_key),
                cstr_ptr(&pre_shared_key),
                cstr_ptr(&log_level),
                cstr_ptr(&config_path),
                cstr_ptr(&state_path),
                cstr_ptr(&dns_labels),
                cstr_ptr(&nat_external_ips),
                wg_port as c_int,
                opts.disable_client_routes as c_int,
                opts.block_inbound as c_int,
                opts.no_userspace as c_int,
                opts.disable_ipv6 as c_int,
                opts.enable_rosenpass as c_int,
                opts.rosenpass_permissive as c_int,
                opts.block_lan_access as c_int,
                tri_state(opts.lazy_connection_enabled),
                opt_u16(opts.mtu),
                opt_u32(opts.performance.preallocated_buffers_per_pool)?,
                opt_u32(opts.performance.max_batch_size)?,
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

    /// Dial a peer over UDP through the mesh, returning a Unix datagram socket.
    ///
    /// Use [`Client::dial`] with `"udp"` only for compatibility: it returns a
    /// stream socketpair that concatenates datagrams and therefore loses
    /// message boundaries. This method preserves them.
    ///
    /// `addr` should be in `"host:port"` format using the overlay IP.
    #[cfg(unix)]
    pub fn dial_udp(&self, addr: &str) -> Result<std::os::unix::net::UnixDatagram, Error> {
        let c_addr = CString::new(addr).map_err(|_| Error::DialUdp)?;

        let fd = unsafe { ffi::nb_dial_udp(self.handle, c_addr.as_ptr()) };
        if fd < 0 {
            return Err(self.last_error_or(Error::DialUdp));
        }

        // SAFETY: Go gave us ownership of this datagram FD via socketpair.
        Ok(unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd as RawFd) })
    }

    /// Listen on a mesh address, returning a listener that yields Unix streams.
    ///
    /// The returned [`Listener`] reads accepted connection FDs from the Go
    /// accept loop over a signaling socketpair.
    ///
    /// `addr` should be in `":port"` or `"host:port"` format.
    #[cfg(unix)]
    pub fn listen(&self, addr: &str) -> Result<Listener, Error> {
        let c_addr = CString::new(addr).map_err(|_| Error::Listen)?;

        let fd = unsafe { ffi::nb_listen(self.handle, c"tcp".as_ptr(), c_addr.as_ptr()) };
        if fd < 0 {
            return Err(self.last_error_or(Error::Listen));
        }

        // SAFETY: Go gave us ownership of this signaling FD via socketpair.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd as RawFd) };
        Ok(Listener { signal: stream })
    }

    /// Start a localhost TCP+UDP proxy forwarding to the given target
    /// address through the mesh netstack.
    ///
    /// Returns the local port that the proxy is listening on.
    /// Both TCP and UDP are proxied on the same port.
    ///
    /// `target` should be `"host:port"` using the peer's overlay IP.
    pub fn start_proxy(&self, target: &str) -> Result<u16, Error> {
        let c_target = CString::new(target).map_err(|_| Error::Proxy)?;

        let port = unsafe { ffi::nb_proxy(self.handle, c_target.as_ptr()) };
        if port < 0 {
            return Err(self.last_error_or(Error::Proxy));
        }

        Ok(port as u16)
    }

    /// Start a reverse proxy: listen on `mesh_port` inside the mesh netstack
    /// and forward incoming connections to `local_addr` on the OS network.
    ///
    /// This allows mesh peers to reach an OS-level service (e.g. a web server
    /// on `localhost:8080`) through the overlay network, even in userspace
    /// netstack mode where overlay IPs are not routable by OS sockets.
    ///
    /// Returns the bound mesh port. Pass `0` to have the netstack choose a
    /// free port.
    pub fn start_reverse_proxy(&self, mesh_port: u16, local_addr: &str) -> Result<u16, Error> {
        let c_local = CString::new(local_addr).map_err(|_| Error::Proxy)?;

        let port =
            unsafe { ffi::nb_reverse_proxy(self.handle, mesh_port as c_int, c_local.as_ptr()) };
        if port <= 0 {
            return Err(self.last_error_or(Error::Proxy));
        }

        Ok(port as u16)
    }

    /// Listen for UDP datagrams on a mesh address, returning a Unix datagram socket.
    ///
    /// The returned socket is one end of a `SOCK_DGRAM` socketpair; the Go
    /// runtime pumps datagrams between the other end and the mesh PacketConn.
    ///
    /// `addr` should be in `":port"` or `"host:port"` format.
    #[cfg(unix)]
    pub fn listen_udp(&self, addr: &str) -> Result<std::os::unix::net::UnixDatagram, Error> {
        let c_addr = CString::new(addr).map_err(|_| Error::ListenUdp)?;

        let fd = unsafe { ffi::nb_listen_udp(self.handle, c_addr.as_ptr()) };
        if fd < 0 {
            return Err(self.last_error_or(Error::ListenUdp));
        }

        // SAFETY: Go gave us ownership of this FD via socketpair.
        Ok(unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd as RawFd) })
    }

    /// Retune tunnel performance on a running client.
    ///
    /// Upstream only applies `preallocated_buffers_per_pool`, and only when
    /// it was set to a nonzero value at construction. `max_batch_size` is
    /// construction-only and returns an error here.
    pub fn set_performance(&self, perf: Performance) -> Result<(), Error> {
        let prealloc = opt_u32(perf.preallocated_buffers_per_pool)?;
        let max_batch = opt_u32(perf.max_batch_size)?;

        let rc = unsafe { ffi::nb_set_performance(self.handle, prealloc, max_batch) };
        if rc != 0 {
            return Err(self.last_error_or(Error::SetPerformance));
        }

        Ok(())
    }

    /// Look up the peer identity (public key and FQDN) for an overlay IP.
    ///
    /// Returns `Ok(None)` when the IP does not belong to an active peer.
    pub fn identity_for_ip(&self, ip: &str) -> Result<Option<PeerIdentity>, Error> {
        let c_ip = CString::new(ip).map_err(|_| Error::Identity)?;
        let json = self.call_json_buf(|buf, len| unsafe {
            ffi::nb_identity_for_ip(self.handle, c_ip.as_ptr(), buf, len)
        })?;
        identity_from_json(&json)
    }

    /// Expose a local service through the mesh.
    ///
    /// The returned session is torn down when dropped.
    pub fn expose(&self, mut req: ExposeRequest) -> Result<ExposeSession, Error> {
        req.call_id = Some(next_expose_call_id(self.handle));
        let json = serde_json::to_string(&req)?;
        let c_json = CString::new(json).map_err(|_| Error::Expose)?;
        let json = self.call_json_buf(|buf, len| unsafe {
            ffi::nb_expose(self.handle, c_json.as_ptr(), buf, len)
        })?;
        expose_from_json(&json, self.handle)
    }

    /// Start a file-based packet capture.
    ///
    /// Any previously running capture is stopped first. The returned session
    /// is stopped on drop.
    pub fn start_capture(&self, opts: CaptureOptions) -> Result<CaptureSession, Error> {
        let json = serde_json::to_string(&opts)?;
        let c_json = CString::new(json).map_err(|_| Error::Capture)?;
        let json = self.call_json_buf(|buf, len| unsafe {
            ffi::nb_capture_start(self.handle, c_json.as_ptr(), buf, len)
        })?;
        capture_start_from_json(&json, self.handle)
    }

    /// Change the runtime log level.
    pub fn set_log_level(&self, level: &str) -> Result<(), Error> {
        let c_level = CString::new(level).map_err(|_| Error::SetLogLevel)?;

        let rc = unsafe { ffi::nb_set_log_level(self.handle, c_level.as_ptr()) };
        if rc != 0 {
            return Err(self.last_error_or(Error::SetLogLevel));
        }

        Ok(())
    }

    fn last_error(&self) -> Option<String> {
        read_error_buf(|buf, len| unsafe { ffi::nb_errmsg(self.handle, buf, len) })
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

impl Drop for Listener {
    fn drop(&mut self) {
        // Stop the Go accept loop before the signaling FD is closed; otherwise
        // the mesh port would stay open until the whole client stops.
        unsafe { ffi::nb_listener_close(self.signal.as_raw_fd()) };
    }
}

/// Full client status including local peer info and connected peers.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    /// Overall connection state.
    #[serde(default)]
    pub state: ConnectionState,
    /// Local overlay IP address.
    pub ip: String,
    /// Local IPv6 overlay address.
    #[serde(default)]
    pub ipv6: String,
    /// Local WireGuard public key.
    pub pub_key: String,
    /// Local FQDN on the mesh.
    #[serde(default)]
    pub fqdn: String,
    /// WireGuard listen port.
    #[serde(default)]
    pub wg_port: i32,
    /// Whether the kernel WireGuard interface is in use.
    #[serde(default)]
    pub kernel_interface: bool,
    /// Management server connection state.
    pub management_state: ConnectionState,
    /// Signal server connection state.
    pub signal_state: ConnectionState,
    /// Whether Rosenpass is enabled.
    #[serde(default)]
    pub rosenpass_enabled: bool,
    /// Whether Rosenpass is permissive.
    #[serde(default)]
    pub rosenpass_permissive: bool,
    /// Whether lazy connections are enabled.
    #[serde(default)]
    pub lazy_connection_enabled: bool,
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
    /// Peer's IPv6 overlay address.
    #[serde(default)]
    pub ipv6: String,
    /// Peer's WireGuard public key.
    pub pub_key: String,
    /// Peer's FQDN on the mesh.
    #[serde(default)]
    pub fqdn: String,
    /// Connection status.
    pub conn_status: ConnectionState,
    /// Whether the connection is relayed (not direct P2P).
    #[serde(default)]
    pub relayed: bool,
    /// Round-trip latency as a duration string.
    #[serde(default)]
    pub latency: String,
    /// Latency jitter as a duration string.
    #[serde(default)]
    pub latency_noise: String,
    /// Bytes transmitted to the peer.
    #[serde(default)]
    pub bytes_tx: i64,
    /// Bytes received from the peer.
    #[serde(default)]
    pub bytes_rx: i64,
    /// Time of the last WireGuard handshake (RFC 3339), or empty.
    #[serde(default)]
    pub last_wireguard_handshake: String,
    /// Local ICE candidate type.
    #[serde(default)]
    pub local_ice_candidate_type: String,
    /// Remote ICE candidate type.
    #[serde(default)]
    pub remote_ice_candidate_type: String,
    /// Relay server address, if relayed.
    #[serde(default)]
    pub relay_server_address: String,
    /// Whether Rosenpass is enabled for this peer.
    #[serde(default)]
    pub rosenpass_enabled: bool,
}

impl Peer {
    pub fn is_connected(&self) -> bool {
        self.conn_status == ConnectionState::Connected
    }
}

/// Identity of a peer on the mesh.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerIdentity {
    /// Peer's WireGuard public key.
    pub pub_key: String,
    /// Peer's FQDN on the mesh.
    pub fqdn: String,
}

/// Protocol used when exposing a local service through the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposeProtocol {
    /// Plain HTTP.
    #[default]
    Http,
    /// HTTPS.
    Https,
    /// Raw TCP.
    Tcp,
    /// Raw UDP.
    Udp,
    /// TLS.
    Tls,
}

/// Request to expose a local service through the mesh.
///
/// The management server assigns `domain` when it is omitted.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ExposeRequest {
    /// Prefix used to derive the assigned domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_prefix: Option<String>,
    /// Explicit domain to request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Local port to expose.
    pub port: u16,
    /// Protocol of the exposed service.
    pub protocol: ExposeProtocol,
    /// PIN for access control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Password for access control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// User groups allowed to access the service.
    pub user_groups: Vec<String>,
    /// Requested public listen port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// Internal per-call token used to make the ERANGE retry idempotent.
    /// [`Client::expose`] overwrites it with a fresh value on every call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

impl fmt::Debug for ExposeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExposeRequest")
            .field("name_prefix", &self.name_prefix)
            .field("domain", &self.domain)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("pin", &redacted(&self.pin))
            .field("password", &redacted(&self.password))
            .field("user_groups", &self.user_groups)
            .field("listen_port", &self.listen_port)
            .finish()
    }
}

static EXPOSE_CALL_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_expose_call_id(handle: c_int) -> String {
    format!(
        "{handle}-{}",
        EXPOSE_CALL_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// An active expose session.
///
/// The session stays alive until dropped or [`ExposeSession::stop`] is called.
#[derive(Debug)]
pub struct ExposeSession {
    /// Public domain assigned to the service.
    pub domain: String,
    /// Service name reported by the management server.
    pub service_name: String,
    /// Public service URL.
    pub service_url: String,
    handle: c_int,
}

impl ExposeSession {
    /// Stop the expose session. Idempotent.
    pub fn stop(&self) -> Result<(), Error> {
        let c_domain = CString::new(self.domain.as_str()).map_err(|_| Error::Expose)?;
        let rc = unsafe { ffi::nb_expose_stop(self.handle, c_domain.as_ptr()) };
        if rc == -1 {
            let msg = read_error_buf(|buf, len| unsafe { ffi::nb_errmsg(self.handle, buf, len) });
            return Err(msg.map(Error::Ffi).unwrap_or(Error::Expose));
        }
        Ok(())
    }
}

impl Drop for ExposeSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Deserialize)]
struct ExposeResponse {
    domain: String,
    service_name: String,
    service_url: String,
}

fn expose_from_json(json: &str, handle: c_int) -> Result<ExposeSession, Error> {
    let resp: ExposeResponse = serde_json::from_str(json)?;
    Ok(ExposeSession {
        domain: resp.domain,
        service_name: resp.service_name,
        service_url: resp.service_url,
        handle,
    })
}

/// Options for a file-based packet capture.
///
/// At least one of `pcap_path` or `text_path` must be set.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CaptureOptions {
    /// File to receive pcap-formatted data.
    pub pcap_path: Option<String>,
    /// File to receive human-readable packet summaries.
    pub text_path: Option<String>,
    /// BPF-like filter expression. Empty captures everything.
    pub filter: String,
    /// Add seq/ack, TTL, window, and length to text output.
    pub verbose: bool,
    /// Dump transport payload as printable ASCII.
    pub ascii: bool,
}

/// Counters of a capture session.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CaptureStats {
    /// Packets captured.
    #[serde(default)]
    pub packets: i64,
    /// Bytes captured.
    #[serde(default)]
    pub bytes: i64,
    /// Packets dropped.
    #[serde(default)]
    pub dropped: i64,
}

/// An active packet capture.
///
/// Stopping flushes buffered packets and waits for the writer to finish. The
/// session is stopped on drop if [`CaptureSession::stop`] was not called.
#[derive(Debug)]
pub struct CaptureSession {
    handle: c_int,
    id: c_int,
}

impl CaptureSession {
    /// Current capture counters.
    pub fn stats(&self) -> Result<CaptureStats, Error> {
        let mut size = INITIAL_BUF_SIZE;
        loop {
            let mut buf = vec![0u8; size];
            let rc = unsafe {
                ffi::nb_capture_stats(
                    self.handle,
                    self.id,
                    buf.as_mut_ptr() as *mut c_char,
                    size as c_int,
                )
            };

            if rc == 0 {
                return Ok(serde_json::from_str(&cstr_from_buf(&buf))?);
            }

            if rc == libc::ERANGE as c_int {
                size *= 2;
                if size > 1024 * 1024 {
                    return Err(Error::BufferTooSmall);
                }
                continue;
            }

            let msg = read_error_buf(|buf, len| unsafe { ffi::nb_errmsg(self.handle, buf, len) });
            return Err(msg.map(Error::Ffi).unwrap_or(Error::Capture));
        }
    }

    /// Stop the capture and flush it to disk.
    pub fn stop(mut self) -> Result<(), Error> {
        let result = self.stop_inner();
        if result.is_ok() {
            self.id = -1;
        }
        result
    }

    fn stop_inner(&self) -> Result<(), Error> {
        let rc = unsafe { ffi::nb_capture_stop(self.handle, self.id) };
        if rc != 0 {
            let msg = read_error_buf(|buf, len| unsafe { ffi::nb_errmsg(self.handle, buf, len) });
            return Err(msg.map(Error::Ffi).unwrap_or(Error::Capture));
        }
        Ok(())
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        if self.id >= 0 {
            let _ = self.stop_inner();
        }
    }
}

#[derive(Deserialize)]
struct CaptureStartResponse {
    id: c_int,
}

fn capture_start_from_json(json: &str, handle: c_int) -> Result<CaptureSession, Error> {
    let resp: CaptureStartResponse = serde_json::from_str(json)?;
    Ok(CaptureSession {
        handle,
        id: resp.id,
    })
}

#[derive(Deserialize)]
struct IdentityResponse {
    #[serde(default)]
    found: bool,
    #[serde(default)]
    pub_key: String,
    #[serde(default)]
    fqdn: String,
}

fn identity_from_json(json: &str) -> Result<Option<PeerIdentity>, Error> {
    let resp: IdentityResponse = serde_json::from_str(json)?;
    Ok(resp.found.then_some(PeerIdentity {
        pub_key: resp.pub_key,
        fqdn: resp.fqdn,
    }))
}

fn create_error_msg() -> String {
    read_error_buf(|buf, len| unsafe { ffi::nb_create_errmsg(buf, len) })
        .unwrap_or_else(|| "unknown error".into())
}

fn read_error_buf(f: impl FnOnce(*mut c_char, c_int)) -> Option<String> {
    let mut buf = vec![0u8; 512];
    f(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int);
    let msg = cstr_from_buf(&buf);
    if msg.is_empty() || msg == "no error" {
        None
    } else {
        Some(msg)
    }
}

fn json_list(items: &[String]) -> Result<Option<CString>, Error> {
    if items.is_empty() {
        return Ok(None);
    }
    let json = serde_json::to_string(items)?;
    Ok(Some(CString::new(json).map_err(|_| Error::InteriorNul)?))
}

fn tri_state(v: Option<bool>) -> c_int {
    match v {
        None => -1,
        Some(false) => 0,
        Some(true) => 1,
    }
}

fn opt_u16(v: Option<u16>) -> c_int {
    v.map(|x| x as c_int).unwrap_or(-1)
}

fn opt_u32(v: Option<u32>) -> Result<c_int, Error> {
    match v {
        None => Ok(-1),
        Some(x) => {
            c_int::try_from(x).map_err(|_| Error::Ffi(format!("value {x} out of c_int range")))
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_list_empty_is_none() {
        assert!(json_list(&[]).unwrap().is_none());
    }

    #[test]
    fn json_list_encodes_array() {
        let c = json_list(&["a".into(), "b".into()]).unwrap().unwrap();
        assert_eq!(c.to_str().unwrap(), r#"["a","b"]"#);
    }

    #[test]
    fn tri_state_maps_none_false_true() {
        assert_eq!(tri_state(None), -1);
        assert_eq!(tri_state(Some(false)), 0);
        assert_eq!(tri_state(Some(true)), 1);
    }

    #[test]
    fn capture_options_serialize_snake_case() {
        let v = serde_json::to_value(CaptureOptions {
            pcap_path: Some("/tmp/a.pcap".into()),
            filter: "tcp".into(),
            verbose: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(v["pcap_path"], "/tmp/a.pcap");
        assert_eq!(v["text_path"], serde_json::Value::Null);
        assert_eq!(v["filter"], "tcp");
        assert_eq!(v["verbose"], true);
        assert_eq!(v["ascii"], false);
    }

    #[test]
    fn capture_start_from_json_reads_id() {
        let s = capture_start_from_json(r#"{"id":3}"#, 7).unwrap();
        assert_eq!(s.id, 3);
    }

    #[test]
    fn expose_request_serializes_snake_case() {
        let v = serde_json::to_value(ExposeRequest {
            name_prefix: Some("api".into()),
            port: 8080,
            protocol: ExposeProtocol::Https,
            listen_port: Some(9000),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(v["name_prefix"], "api");
        assert_eq!(v["protocol"], "https");
        assert_eq!(v["listen_port"], 9000);
        assert_eq!(v["user_groups"], serde_json::json!([]));
    }

    #[test]
    fn call_ids_are_unique_and_serialized() {
        let a = next_expose_call_id(7);
        let b = next_expose_call_id(7);
        assert_ne!(a, b);
        let v = serde_json::to_value(ExposeRequest {
            call_id: Some(a.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(v["call_id"], a);
    }

    #[test]
    fn expose_from_json_reads_response() {
        let s = expose_from_json(
            r#"{"domain":"svc.example","service_name":"api","service_url":"https://svc.example"}"#,
            7,
        )
        .unwrap();
        assert_eq!(s.domain, "svc.example");
        assert_eq!(s.service_name, "api");
        assert_eq!(s.service_url, "https://svc.example");
    }

    #[test]
    fn identity_from_json_not_found() {
        assert!(identity_from_json(r#"{"found":false}"#).unwrap().is_none());
    }

    #[test]
    fn identity_from_json_found() {
        let id = identity_from_json(r#"{"found":true,"pub_key":"abc","fqdn":"peer.example"}"#)
            .unwrap()
            .unwrap();
        assert_eq!(id.pub_key, "abc");
        assert_eq!(id.fqdn, "peer.example");
    }

    #[test]
    fn status_deserializes_without_new_fields() {
        let json = r#"{"ip":"10.0.0.1","pub_key":"k","management_state":"connected","signal_state":"connected"}"#;
        let s: Status = serde_json::from_str(json).unwrap();
        assert!(s.ipv6.is_empty());
        assert_eq!(s.wg_port, 0);
        assert!(!s.kernel_interface);
        assert!(!s.rosenpass_enabled);
        assert!(!s.lazy_connection_enabled);
    }

    #[test]
    fn peer_deserializes_without_new_fields() {
        let json = r#"{"ip":"10.0.0.2","pub_key":"k","conn_status":"connected"}"#;
        let p: Peer = serde_json::from_str(json).unwrap();
        assert!(p.ipv6.is_empty());
        assert_eq!(p.bytes_tx, 0);
        assert_eq!(p.bytes_rx, 0);
        assert!(!p.rosenpass_enabled);
        assert!(p.is_connected());
    }

    #[test]
    fn opt_numbers_use_negative_sentinel() {
        assert_eq!(opt_u16(None), -1);
        assert_eq!(opt_u16(Some(1400)), 1400);
        assert_eq!(opt_u32(None).unwrap(), -1);
        assert_eq!(opt_u32(Some(256)).unwrap(), 256);
        assert!(opt_u32(Some(u32::MAX)).is_err());
    }

    #[test]
    fn client_options_debug_redacts_secrets() {
        let opts = ClientOptions {
            setup_key: Some("setup-secret".into()),
            token: Some("jwt-secret".into()),
            private_key: Some("wg-secret".into()),
            pre_shared_key: Some("psk-secret".into()),
            management_url: Some("https://api.netbird.io".into()),
            ..Default::default()
        };
        let debug = format!("{opts:?}");
        assert!(!debug.contains("setup-secret"));
        assert!(!debug.contains("jwt-secret"));
        assert!(!debug.contains("wg-secret"));
        assert!(!debug.contains("psk-secret"));
        assert!(debug.contains("https://api.netbird.io"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn expose_request_debug_redacts_credentials() {
        let req = ExposeRequest {
            pin: Some("1234".into()),
            password: Some("hunter2".into()),
            port: 8080,
            ..Default::default()
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains("1234"));
        assert!(!debug.contains("hunter2"));
        assert!(debug.contains("8080"));
    }
}
