# netbird-embed-rs

Rust bindings for [NetBird's `client/embed`](https://github.com/netbirdio/netbird/tree/main/client/embed) package via Go C-shared FFI.

Embeds a full NetBird node (WireGuard mesh networking) into any Rust application — no separate VPN client needed.

## Requirements

- **Rust** ≥ 1.85
- **Go** ≥ 1.25 (builds the C-shared library automatically via `build.rs`)

## Cross-platform support

The core API works on **all platforms** (Linux, macOS, Windows). Direct mesh sockets (`dial`/`listen`/`listen_udp`) require Unix (socketpair-based). On Windows, use `start_proxy` to get a localhost port forwarding to a mesh peer.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
netbird-embed = "0.3"
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

// Expose a local service on the mesh (reverse proxy)
client.start_reverse_proxy(9000, "127.0.0.1:8080")?;
```

### Direct mesh sockets (Unix only)

```rust
// Dial a peer — returns a UnixStream (socketpair)
let stream = client.dial("tcp", "10.200.0.1:8080")?;

// Listen on the mesh — returns a Listener that yields UnixStreams
let listener = client.listen(":8080")?;
let conn = listener.accept()?;

// UDP datagrams
let sock = client.listen_udp(":9000")?;
```

The client is automatically stopped and freed on drop.

## API

| Method | Platform | Description |
|--------|----------|-------------|
| `Client::new(opts)` | All | Create a NetBird node |
| `client.start()` | All | Join the mesh network |
| `client.stop()` | All | Leave the mesh network |
| `client.status()` | All | Local peer info, management/signal state, peer list |
| `client.peers()` | All | List of known peers with connection status |
| `client.set_log_level(level)` | All | Change runtime log level |
| `client.start_proxy(target)` | All | Localhost TCP+UDP proxy → mesh peer, returns port |
| `client.start_reverse_proxy(port, addr)` | All | Mesh port → localhost service |
| `client.dial(net, addr)` | Unix | Dial a peer, returns `UnixStream` |
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
| Drop blocks | `Client::drop` calls Go `Stop()` which may block while tearing down the tunnel. Call `client.stop()` explicitly if you need non-blocking cleanup. |

## License

BSD-3-Clause (matching [NetBird's client license](https://github.com/netbirdio/netbird/blob/main/LICENSE))
