# Changelog

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
