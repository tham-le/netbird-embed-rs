# Changelog

## 0.4.0

Updated the bundled NetBird to v0.82.0, which requires Go 1.26 to build.

### Added
- `ClientOptions` fields: `disable_ipv6`, `enable_rosenpass`, `rosenpass_permissive`, `block_lan_access`, `lazy_connection_enabled`, `mtu`, `dns_labels`, `nat_external_ips`, and `performance`
- `Client::set_performance()` for runtime buffer-pool tuning
- `Client::identity_for_ip()` for peer public-key/FQDN lookups
- `Client::expose()` with `ExposeRequest`, `ExposeProtocol`, and `ExposeSession` for reverse-proxied services
- `Client::start_capture()` with `CaptureOptions`, `CaptureSession`, and `CaptureStats` for pcap/text packet capture
- `Client::dial_udp()` (Unix) for boundary-preserving UDP dials
- `hello_over_netbird` example: optional `NB_STATE_DIR` persistence so restarts reuse the same peer

### Changed
- `Client::start_reverse_proxy()` now returns the bound port (`Result<u16, Error>`); pass 0 for a random port
- `Debug` for `ClientOptions` and `ExposeRequest` redacts keys, tokens, PINs, and passwords
- The FFI declarations are generated from one table and verified against the cgo header at build time
- `go-lib/go.mod` mirrors NetBird's own `replace` directives (a dependency's replaces are ignored) instead of carrying stale ones
- Dependencies and CI images/toolchains are pinned; CI runs with read-only permissions

### Security
- Proxy relays are capped and use dial/idle deadlines; slow mesh peers can no longer exhaust goroutines or file descriptors
- Expose, dial, and stop use bounded contexts; `Client::drop` is bounded to ~30 s
- Packet captures are created `0600` without following symlinks, and may not share one path
- All FFI string inputs tolerate `NULL`; zero-length error buffers no longer panic
- Socketpair descriptors are close-on-exec; dropped listeners close the mesh port
- `wireguard_port` is range-checked; UDP reverse proxies demultiplex per peer
- The example HTTP server handles connections on threads, caps request size, uses a total deadline, escapes the management-supplied FQDN, and brackets IPv6 URLs
- New `Status` and `Peer` fields: IPv6 address, WireGuard port, kernel interface, Rosenpass state, lazy-connection state, latency jitter, byte counters, handshake time, ICE candidate types, relay address, and peer Rosenpass state

### Fixed
- `ClientOptions::device_name` is now sent during pre-registration, so the peer FQDN reflects it
- The embedded peer now reports the bundled NetBird release version instead of `development`
- `preRegisterPeer` now uses the v0.82 `Register(setupKey, jwtToken, sysInfo, pubSSHKey, dnsLabels)` signature

### Notes
- `ExposeSession::stop()` and the `ExposeSession` destructor wait for the keep-alive goroutine and may block for up to ~10 seconds. `Client::stop()` and `Client::drop()` cancel and wait for every expose session.
- `Client::set_performance()` returns an error unless `preallocated_buffers_per_pool` was nonzero at construction; `max_batch_size` is construction-only.
- Capture is file-based: at least one of `pcap_path` or `text_path` is required.

## 0.3.0

**Breaking:** `Status.state`, `Status.management_state`, `Status.signal_state`, and `Peer.conn_status` changed from `String` to `ConnectionState` enum.

### Migration from 0.2

```rust
// Before (0.2)
if status.management_state == "connected" { ... }
if peer.conn_status == "connected" { ... }

// After (0.3)
use netbird_embed::ConnectionState;
if status.management_state == ConnectionState::Connected { ... }
if peer.conn_status == ConnectionState::Connected { ... }
// or use the helper:
if peer.is_connected() { ... }
```

### Added
- `ConnectionState` enum with `Connected`, `Connecting`, `Disconnected`, `Unknown` variants
- Crate-level documentation with cross-platform usage examples
- `rust-version = "1.85"` in Cargo.toml (MSRV enforcement)

### Changed
- All connection state fields now use `ConnectionState` instead of `String`
- Removed `.expect()` in `listen()` — uses `c"tcp"` literal (infallible)
- Deduplicated error buffer reading into `read_error_buf` helper

### Removed
- Unused `tokio` dev-dependency

## 0.2.0

### Added
- `start_proxy()` / `start_reverse_proxy()` for cross-platform TCP+UDP proxying
- `listen_udp()` for mesh UDP datagrams
- `set_log_level()` for runtime log level changes

## 0.1.0

Initial release with `new`, `start`, `stop`, `status`, `peers`, `dial`, `listen`.
