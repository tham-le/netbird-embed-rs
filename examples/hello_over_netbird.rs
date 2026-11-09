//! Serves a fancy "Hello World" page to other NetBird peers.
//!
//! The process connects to the mesh exactly like `connect.rs`, starts a local
//! HTTP server on a random loopback port, and reverse-proxies a mesh port to
//! it. Peers open `http://<your-overlay-ip>/` (port 80).
//!
//! Environment:
//! - `NB_SETUP_KEY` (required)
//! - `NB_MANAGEMENT_URL` (default `https://api.netbird.io`)
//! - `NB_DEVICE_NAME` (default `rust-hello-netbird`); also becomes the mesh FQDN
//! - `NB_MESH_PORT` (default `80`)
//! - `NB_STATE_DIR` (optional); persist identity/state there to keep the same
//!   peer across restarts. Without it the client is in-memory and registers a
//!   new peer on every start.
//!
//! To get a stable FQDN without the `-<ip-octets>` suffix that NetBird appends
//! to ephemeral peers, create the setup key with **Ephemeral disabled**, pick a
//! name that is not already used in the account, and set `NB_STATE_DIR` so
//! restarts reuse the same peer instead of registering a new one.
//!
//! Run with:
//! ```text
//! NB_SETUP_KEY=... cargo run --example hello_over_netbird
//! ```

use netbird_embed::{Client, ClientOptions, ConnectionState};
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Longest accepted request line.
const MAX_LINE: usize = 8 * 1024;
/// Longest accepted header block.
const MAX_HEADERS: usize = 16 * 1024;
/// Total time a client gets to send its request and receive the response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Concurrent connections served by the example.
const MAX_CONNS: usize = 64;

const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hello from Rust via NetBird</title>
<style>
  :root {
    color-scheme: dark;
    --ink: #f6f2ff;
    --muted: #b9b2cf;
    --edge: rgba(255, 255, 255, 0.14);
    --accent: #ff7a59;
    --accent-2: #7c6cff;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    display: grid;
    place-items: center;
    padding: 2rem;
    color: var(--ink);
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background:
      radial-gradient(60rem 40rem at 15% -10%, rgba(124, 108, 255, 0.35), transparent 60%),
      radial-gradient(50rem 35rem at 110% 110%, rgba(255, 122, 89, 0.28), transparent 60%),
      #0b0813;
  }
  .card {
    position: relative;
    width: min(44rem, 100%);
    padding: clamp(2rem, 6vw, 4rem);
    border: 1px solid var(--edge);
    border-radius: 1.5rem;
    background: linear-gradient(160deg, rgba(255,255,255,0.08), rgba(255,255,255,0.02));
    box-shadow: 0 2rem 6rem rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(14px);
    overflow: hidden;
  }
  .card::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: inherit;
    padding: 1px;
    background: linear-gradient(120deg, var(--accent-2), transparent 40%, var(--accent));
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    pointer-events: none;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
    margin: 0 0 2rem;
    padding: 0.4rem 0.8rem;
    border: 1px solid var(--edge);
    border-radius: 999px;
    color: var(--muted);
    font: 600 0.72rem/1 ui-monospace, SFMono-Regular, Menlo, monospace;
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }
  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: #4ade80;
    box-shadow: 0 0 0.8rem #4ade80;
  }
  h1 {
    margin: 0;
    font: 700 clamp(2.4rem, 8vw, 4.6rem)/0.98 ui-serif, Georgia, "Times New Roman", serif;
    letter-spacing: -0.035em;
  }
  h1 span {
    display: block;
    background: linear-gradient(100deg, var(--accent), var(--accent-2));
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }
  p {
    max-width: 34rem;
    margin: 1.5rem 0 0;
    color: var(--muted);
    font-size: clamp(1rem, 2.2vw, 1.15rem);
    line-height: 1.65;
  }
  code {
    color: var(--ink);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.9em;
    padding: 0.15rem 0.45rem;
    border: 1px solid var(--edge);
    border-radius: 0.45rem;
    background: rgba(0, 0, 0, 0.28);
  }
  footer {
    margin-top: 2.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid var(--edge);
    color: var(--muted);
    font: 500 0.78rem/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
  }
</style>
</head>
<body>
  <main class="card">
    <p class="badge"><span class="dot"></span> NetBird overlay</p>
    <h1>Hello World<span>from Rust via NetBird</span></h1>
    <p>
      This page is served by a Rust process over a WireGuard mesh.
      The HTTP server listens on loopback only; NetBird
      reverse-proxies it from <code>__URL__</code>.
    </p>
    <footer>netbird-embed · client/embed FFI · zero-buffer-copy local server</footer>
  </main>
</body>
</html>
"#;

fn main() -> Result<(), Box<dyn Error>> {
    let setup_key =
        std::env::var("NB_SETUP_KEY").expect("NB_SETUP_KEY environment variable required");
    let management_url =
        std::env::var("NB_MANAGEMENT_URL").unwrap_or_else(|_| "https://api.netbird.io".to_string());
    let device_name =
        std::env::var("NB_DEVICE_NAME").unwrap_or_else(|_| "rust-hello-netbird".to_string());
    let mesh_port: u16 = std::env::var("NB_MESH_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()
        .expect("NB_MESH_PORT must be a valid port");
    let state_dir = std::env::var_os("NB_STATE_DIR").map(PathBuf::from);

    if let Some(dir) = &state_dir {
        prepare_state_dir(dir)?;
        println!("Persisting identity and state in {}", dir.display());
    } else {
        println!("No NB_STATE_DIR set; using in-memory identity (new peer on each start)");
    }
    let (config_path, state_path) = state_files(state_dir.as_deref());

    println!("Connecting to NetBird as {device_name:?}...");
    let client = Client::new(ClientOptions {
        setup_key: Some(setup_key),
        management_url: Some(management_url),
        device_name: Some(device_name.clone()),
        config_path,
        state_path,
        ..Default::default()
    })?;
    client.start()?;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let local_port = listener.local_addr()?.port();

    let mut overlay_ip = String::new();
    let mut overlay_fqdn = String::new();
    for attempt in 0..30 {
        let status = client.status()?;
        overlay_ip = ip_only(&status.ip);
        overlay_fqdn = status.fqdn.trim_end_matches('.').to_string();
        if status.management_state == ConnectionState::Connected {
            break;
        }
        if attempt == 29 {
            eprintln!("Management still not connected; serving anyway on {overlay_ip:?}");
        }
        thread::sleep(Duration::from_secs(1));
    }

    let mesh_port = client.start_reverse_proxy(mesh_port, &format!("127.0.0.1:{local_port}"))?;

    if overlay_ip.is_empty() {
        overlay_ip = "<overlay-ip>".into();
    }
    let mesh_host = mesh_host(&overlay_fqdn, &overlay_ip);

    println!("Device name: {device_name}");
    println!("Local HTTP server: http://127.0.0.1:{local_port}/");
    println!(
        "Reachable from the mesh at: {}",
        mesh_url(&mesh_host, mesh_port)
    );
    if mesh_host != overlay_ip {
        println!("Overlay IP: {}", mesh_url(&overlay_ip, mesh_port));
    }
    println!("Press Ctrl+C to stop.");

    let page = Arc::new(PAGE.replace("__URL__", &html_escape(&mesh_url(&mesh_host, mesh_port))));
    let active = Arc::new(AtomicUsize::new(0));

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if active.load(Ordering::Relaxed) >= MAX_CONNS {
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let page = Arc::clone(&page);
                let active = Arc::clone(&active);
                thread::spawn(move || {
                    if let Err(err) = handle(stream, &page) {
                        eprintln!("request failed: {err}");
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }

    Ok(())
}

fn prepare_state_dir(dir: &Path) -> io::Result<()> {
    // Only tighten a directory we created ourselves; a pre-existing one such
    // as /tmp keeps its mode.
    let existed = dir.exists();
    fs::create_dir_all(dir)?;
    if !existed {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The config file contains the WireGuard private key.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn state_files(dir: Option<&Path>) -> (Option<String>, Option<String>) {
    match dir {
        Some(dir) => (
            Some(dir.join("config.json").to_string_lossy().into_owned()),
            Some(dir.join("state.json").to_string_lossy().into_owned()),
        ),
        None => (None, None),
    }
}

fn ip_only(ip: &str) -> String {
    ip.split('/').next().unwrap_or_default().to_string()
}

fn mesh_host(fqdn: &str, ip: &str) -> String {
    if fqdn.is_empty() {
        ip.to_string()
    } else {
        fqdn.to_string()
    }
}

fn mesh_url(host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 80 {
        format!("http://{host}/")
    } else {
        format!("http://{host}:{port}/")
    }
}

/// Minimal HTML text escaping for values interpolated into the page.
fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

enum RequestError {
    TooLarge,
    Timeout,
    Io(io::Error),
}

fn request_error(err: io::Error) -> RequestError {
    match err.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => RequestError::Timeout,
        _ => RequestError::Io(err),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, RequestError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(RequestError::Timeout);
    }
    Ok(left)
}

fn read_line_limited(
    reader: &mut BufReader<TcpStream>,
    buf: &mut String,
    max: usize,
) -> Result<usize, RequestError> {
    let n = reader
        .take(max as u64 + 1)
        .read_line(buf)
        .map_err(request_error)?;
    if n > max {
        return Err(RequestError::TooLarge);
    }
    Ok(n)
}

fn read_request(
    reader: &mut BufReader<TcpStream>,
    deadline: Instant,
) -> Result<(String, String, bool), RequestError> {
    reader
        .get_ref()
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(request_error)?;

    let mut request_line = String::new();
    if read_line_limited(reader, &mut request_line, MAX_LINE)? == 0 {
        return Err(RequestError::Io(io::ErrorKind::UnexpectedEof.into()));
    }

    let mut total = request_line.len();
    loop {
        reader
            .get_ref()
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(request_error)?;
        let mut line = String::new();
        let n = read_line_limited(reader, &mut line, MAX_LINE)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        total += n;
        if total > MAX_HEADERS {
            return Err(RequestError::TooLarge);
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let head_only = method == "HEAD";
    Ok((method, path, head_only))
}

fn handle(mut stream: TcpStream, page: &str) -> io::Result<()> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;

    let mut reader = BufReader::new(stream.try_clone()?);
    let (_method, _path, head_only, status, body) = match read_request(&mut reader, deadline) {
        Ok((method, path, head_only)) => {
            let (status, body) = route(&method, &path, page);
            (method, path, head_only, status, body)
        }
        Err(RequestError::TooLarge) => (
            String::new(),
            String::new(),
            false,
            "431 Request Header Fields Too Large",
            "Request too large.\n",
        ),
        Err(RequestError::Timeout) => (
            String::new(),
            String::new(),
            false,
            "408 Request Timeout",
            "Request timed out.\n",
        ),
        Err(RequestError::Io(err)) => return Err(err),
    };

    stream.set_write_timeout(Some(remaining(deadline).unwrap_or(REQUEST_TIMEOUT)))?;

    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )?;

    if !head_only {
        stream.write_all(body.as_bytes())?;
    }
    stream.flush()
}

fn route<'a>(method: &str, path: &str, page: &'a str) -> (&'static str, &'a str) {
    if method != "GET" && method != "HEAD" {
        return ("405 Method Not Allowed", METHOD_NOT_ALLOWED);
    }
    match path {
        "/" | "/index.html" | "/hello" => ("200 OK", page),
        "/favicon.ico" => ("204 No Content", ""),
        _ => ("404 Not Found", NOT_FOUND),
    }
}

const NOT_FOUND: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>404</title>
<body style="margin:0;display:grid;place-items:center;height:100vh;background:#0b0813;color:#f6f2ff;font-family:system-ui">
<main style="text-align:center">
<h1 style="font:700 4rem/1 ui-serif,Georgia,serif;margin:0">404</h1>
<p style="color:#b9b2cf">No such page on this mesh node.</p>
</main>
</body>
"#;

const METHOD_NOT_ALLOWED: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>405</title>
<body style="margin:0;display:grid;place-items:center;height:100vh;background:#0b0813;color:#f6f2ff;font-family:system-ui">
<main style="text-align:center">
<h1 style="font:700 4rem/1 ui-serif,Georgia,serif;margin:0">405</h1>
<p style="color:#b9b2cf">Only GET and HEAD are supported.</p>
</main>
</body>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_page_on_root() {
        let page = "hello";
        assert_eq!(route("GET", "/", page), ("200 OK", "hello"));
        assert_eq!(route("HEAD", "/hello", page), ("200 OK", "hello"));
    }

    #[test]
    fn rejects_unknown_path_and_method() {
        assert_eq!(route("GET", "/nope", "x").0, "404 Not Found");
        assert_eq!(route("POST", "/", "x").0, "405 Method Not Allowed");
        assert_eq!(route("GET", "/favicon.ico", "x").0, "204 No Content");
    }

    #[test]
    fn omits_default_port_from_url() {
        assert_eq!(mesh_url("10.0.0.2", 80), "http://10.0.0.2/");
        assert_eq!(mesh_url("10.0.0.2", 8080), "http://10.0.0.2:8080/");
    }

    #[test]
    fn brackets_ipv6_hosts() {
        assert_eq!(mesh_url("fd00::1", 80), "http://[fd00::1]/");
        assert_eq!(mesh_url("[fd00::1]", 8080), "http://[fd00::1]:8080/");
    }

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            html_escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(html_escape("plain.name"), "plain.name");
    }

    #[test]
    fn prefers_fqdn_but_falls_back_to_ip() {
        assert_eq!(
            mesh_host("rust.netbird.cloud", "10.0.0.2"),
            "rust.netbird.cloud"
        );
        assert_eq!(mesh_host("", "10.0.0.2"), "10.0.0.2");
    }

    #[test]
    fn strips_cidr_suffix_from_ip() {
        assert_eq!(ip_only("100.103.139.227/16"), "100.103.139.227");
        assert_eq!(ip_only("100.103.139.227"), "100.103.139.227");
    }

    #[test]
    fn state_files_are_absent_without_state_dir() {
        assert_eq!(state_files(None), (None, None));
    }

    #[test]
    fn state_files_live_inside_state_dir() {
        let dir = Path::new("/tmp/nb-embed-state");
        let (config, state) = state_files(Some(dir));
        assert_eq!(config.as_deref(), Some("/tmp/nb-embed-state/config.json"));
        assert_eq!(state.as_deref(), Some("/tmp/nb-embed-state/state.json"));
    }

    #[test]
    fn state_dir_is_private() {
        let dir = std::env::temp_dir().join(format!("nb-embed-state-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        prepare_state_dir(&dir).unwrap();
        assert!(dir.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn preexisting_state_dir_keeps_its_mode() {
        let dir = std::env::temp_dir().join(format!("nb-embed-state-keep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            prepare_state_dir(&dir).unwrap();
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
