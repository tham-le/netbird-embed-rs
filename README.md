# netbird-embed-rs

Rust bindings for [NetBird's `client/embed`](https://github.com/netbirdio/netbird/tree/main/client/embed) package via Go C-shared FFI.

Embeds a full NetBird node (WireGuard mesh networking) into any Rust application — no separate VPN client needed.

## Requirements

- **Rust** ≥ 1.75
- **Go** ≥ 1.25 (builds the C-shared library automatically via `build.rs`)
- **Linux** (Unix socketpair for `dial_tcp`/`listen_tcp`; status/peers work on all platforms)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
netbird-embed = { path = "../netbird-embed-rs" }
```

```rust
use netbird_embed::{Client, ClientOptions};

let client = Client::new(ClientOptions {
    setup_key: Some("YOUR-SETUP-KEY".into()),
    management_url: Some("https://api.netbird.io".into()),
    device_name: Some("my-app".into()),
    token: None,
})?;

client.start()?;

let status = client.status()?;
println!("Overlay IP: {}", status.ip);

for peer in client.peers()? {
    if peer.is_connected() {
        println!("{} ({})", peer.fqdn, peer.ip);
    }
}

// Dial a peer over the mesh
let stream = client.dial_tcp("10.200.0.1:8080")?;
```

The client is automatically stopped and freed on drop.

## API

| Method | Description |
|--------|-------------|
| `Client::new(opts)` | Create a NetBird node |
| `client.start()` | Join the mesh network |
| `client.stop()` | Leave the mesh network |
| `client.status()` | Local peer info, management/signal state, peer list |
| `client.peers()` | List of known peers with connection status |
| `client.dial_tcp(addr)` | Dial a peer, returns `TcpStream` (Unix only) |
| `client.listen_tcp(addr)` | Listen on mesh address, returns `TcpListener` (Unix only) |

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
- **Socketpair for connections** — `dial_tcp()` creates a Unix socketpair. Go pumps data between the mesh connection and one end; Rust gets the other as a raw file descriptor.
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

## License

MIT OR Apache-2.0
