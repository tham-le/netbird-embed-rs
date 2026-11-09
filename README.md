# netbird-embed-rs

Rust bindings for [NetBird's `client/embed`](https://github.com/netbirdio/netbird/tree/main/client/embed) package via Go C-shared FFI.

Embeds a full NetBird node (WireGuard mesh networking) into any Rust application — no separate VPN client needed.

## Requirements

- **Rust** ≥ 1.85
- **Go** ≥ 1.26 (builds the C-shared library automatically via `build.rs`)

## Cross-platform support

Linux and macOS are supported and tested. Windows is **build- and link-supported
only**: the C-shared library cross-compiles, but there is no CI job that runs it,
and every socketpair-based method returns "not supported" because
`socketpair_windows.go` is a stub. On Windows only the core control-plane calls
and `start_proxy`/`start_reverse_proxy` (Go `net.Listen` on localhost) work.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
netbird-embed = "0.4"
```

### Connect and query peers

```rust
use netbird_embed::{Client, ClientOptions, ConnectionState};

let client = Client::new(ClientOptions {
    setup_key: Some("YOUR-SETUP-KEY".into()),
    management_url: Some("https://api.netbird.io".into()),
    device_name: Some("my-app".into()),
    ..Default::default()
})?;

client.start()?;

let status = client.status()?;
println!("Overlay IP: {}", status.ip);

for peer in client.peers()? {
    if peer.is_connected() {
        println!("{} ({})", peer.fqdn, peer.ip);
    }
}
```

### Proxy to a peer (cross-platform)

```rust
// Forward localhost:random → peer's 10.200.0.1:8080 through the mesh
let port = client.start_proxy("10.200.0.1:8080")?;
let stream = std::net::TcpStream::connect(("127.0.0.1", port))?;

// Expose a local service on the mesh (reverse proxy).
// Returns the bound port; pass 0 for a random one.
let port = client.start_reverse_proxy(9000, "127.0.0.1:8080")?;
```

### Direct mesh sockets (Unix only)

```rust
// Dial a peer — returns a UnixStream (socketpair)
let stream = client.dial("tcp", "10.200.0.1:8080")?;

// Listen on the mesh — returns a Listener that yields UnixStreams
let listener = client.listen(":8080")?;
let conn = listener.accept()?;

// UDP datagrams (boundaries preserved)
let sock = client.listen_udp(":9000")?;
let udp = client.dial_udp("10.200.0.1:9000")?;
```

Dropping a `Listener` closes the mesh listener. `start_proxy` binds an
unauthenticated `127.0.0.1` port: any local user can reach the peer through it,
so treat it like a loopback service.

The client is automatically stopped and freed on drop.

### Advanced options

```rust
use netbird_embed::{Client, ClientOptions, Performance};

let client = Client::new(ClientOptions {
    setup_key: Some("YOUR-SETUP-KEY".into()),
    disable_ipv6: true,
    block_lan_access: true,
    lazy_connection_enabled: Some(false),
    mtu: Some(1280),
    dns_labels: vec!["lab".into()],
    performance: Performance {
        preallocated_buffers_per_pool: Some(256),
        max_batch_size: None,
    },
    ..Default::default()
})?;
```

`set_performance` tunes the buffer pool at runtime, but only when
`preallocated_buffers_per_pool` was nonzero at construction.
`max_batch_size` is construction-only.

### Peer identity and exposed services

```rust
// Resolve an overlay IP to its public key and FQDN.
if let Some(identity) = client.identity_for_ip("10.200.0.2")? {
    println!("{} ({})", identity.fqdn, identity.pub_key);
}

// Expose a local service through the mesh.
let session = client.expose(netbird_embed::ExposeRequest {
    name_prefix: Some("api".into()),
    port: 8080,
    protocol: netbird_embed::ExposeProtocol::Https,
    ..Default::default()
})?;
println!("{} -> {}", session.service_url, session.domain);

// Explicit stop; dropping the session also stops it.
session.stop()?;
```

Stopping an expose session waits for its keep-alive task and may block for up
to ~10 seconds. `Client::stop()` and dropping the client cancel and wait for
all sessions.

### Packet capture

Capture writes to files (created `0600`, without following symlinks); set at
least one output path. `pcap_path` and `text_path` must differ.

```rust
let capture = client.start_capture(netbird_embed::CaptureOptions {
    pcap_path: Some("/tmp/netbird.pcap".into()),
    text_path: Some("/tmp/netbird.txt".into()),
    filter: "tcp port 443".into(),
    ..Default::default()
})?;

let stats = capture.stats()?;
println!("{} packets, {} bytes", stats.packets, stats.bytes);

// Stop flushes the files; dropping also stops the capture.
capture.stop()?;
```

Starting a new capture stops the previous one. Stats and stop calls for a
stale capture ID return an error.

## API

| Method | Platform | Description |
|--------|----------|-------------|
| `Client::new(opts)` | All | Create a NetBird node |
| `client.start()` | All | Join the mesh network |
| `client.stop()` | All | Leave the mesh network |
| `client.status()` | All | Local peer info, management/signal state, peer list |
| `client.peers()` | All | List of known peers with connection status |
| `client.identity_for_ip(ip)` | All | Resolve overlay IP → public key and FQDN |
| `client.set_log_level(level)` | All | Change runtime log level |
| `client.set_performance(perf)` | All | Retune the buffer pool at runtime |
| `client.expose(req)` | All | Expose a local service through the mesh |
| `client.start_capture(opts)` | All | Start a pcap/text packet capture |
| `capture.stats()` | All | Capture counters |
| `capture.stop()` | All | Stop and flush a capture |
| `client.start_proxy(target)` | All | Localhost TCP+UDP proxy → mesh peer, returns port |
| `client.start_reverse_proxy(port, addr)` | All | Mesh port → localhost service, returns bound port |
| `client.dial(net, addr)` | Unix | Dial a peer, returns `UnixStream` |
| `client.dial_udp(addr)` | Unix | Dial a peer over UDP, returns `UnixDatagram` |
| `client.listen(addr)` | Unix | Listen on mesh address, returns `Listener` |
| `client.listen_udp(addr)` | Unix | Listen for UDP datagrams, returns `UnixDatagram` |
| `listener.accept()` | Unix | Accept next connection, returns `UnixStream` |

## Architecture

```
┌─────────────────────────────┐
│  Your Rust application      │
│  ┌───────────────────────┐  │
│  │ netbird-embed (safe)  │  │
│  │  Client, Status, Peer │  │
│  └──────────┬────────────┘  │
│  ┌──────────▼────────────┐  │
│  │ FFI layer             │  │
│  │  extern "C" bindings  │  │
│  └──────────┬────────────┘  │
└─────────────┼───────────────┘
              │ integer handles + caller buffers
┌─────────────▼───────────────┐
│ libnetbird_embed.so (Go)    │
│  C-exported wrappers        │
│  └─► netbird/client/embed   │
│       └─► wireguard-go      │
└─────────────────────────────┘
```

**Key design decisions:**

- **Integer handles** — Go GC manages real objects. Rust holds an `i32` handle. No Go pointers cross FFI.
- **Caller-provided buffers** — Status/peers returned as JSON into Rust-allocated buffers. Returns `ERANGE` if too small; caller retries with larger buffer (handled automatically).
- **Socketpair for connections** — `dial()` creates a Unix socketpair. Go pumps data between the mesh connection and one end; Rust gets the other as a `UnixStream`.
- **Proxy for cross-platform** — `start_proxy()` / `start_reverse_proxy()` use Go's own `net.Listen` on localhost, avoiding platform-specific socketpair APIs.
- **No callbacks** — Status is polled. Avoids cross-runtime threading complexity.

## Building

```bash
# Build (Go C-shared library is compiled automatically by build.rs)
cargo build

# Run the example
NB_SETUP_KEY=your-key NB_MANAGEMENT_URL=https://api.netbird.io cargo run --example connect
```

### Cross-compilation

`build.rs` detects the Rust target and sets `GOOS`/`GOARCH` accordingly. For Windows cross-compilation, set `CC` to a MinGW-w64 compiler:

```bash
CC=x86_64-w64-mingw32-gcc cargo build --target x86_64-pc-windows-gnu
```

## Gotchas

| Issue | Detail |
|-------|--------|
| One Go runtime per process | Two Go `.so` files in the same process causes GC corruption. This must be the only Go library loaded. |
| Library size | The `.so` is ~50MB (Go runtime + NetBird + WireGuard). Strip with `go build -ldflags="-s -w"` to reduce. |
| CGo call overhead | ~60-100ns per FFI call. Negligible for control plane (start/stop/status). |
| Drop blocks | `Client::drop` calls Go `Stop()`, bounded to ~30 s. Call `client.stop()` explicitly if you need non-blocking cleanup. |
| Plaintext management | `http://` management URLs send the setup key in plaintext; the client logs a warning but does not reject them. |
| Local proxy auth | `start_proxy` binds `127.0.0.1:0` without authentication. |

## License

BSD-3-Clause (matching [NetBird's client license](https://github.com/netbirdio/netbird/blob/main/LICENSE)).
Bundled third-party components are listed in [NOTICE](NOTICE).

