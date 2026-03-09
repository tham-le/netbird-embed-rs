use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let go_lib_dir = manifest_dir.join("go-lib");

    let target = env::var("TARGET").expect("TARGET not set");
    let (goos, goarch) = parse_target(&target);

    let lib_name = "netbird_embed";
    let (lib_file, link_name) = lib_output_name(lib_name, &goos);

    // Build the Go C-shared library
    let mut cmd = Command::new("go");
    cmd.current_dir(&go_lib_dir)
        .env("CGO_ENABLED", "1")
        .env("GOOS", &goos)
        .env("GOARCH", &goarch)
        .arg("build")
        .arg("-buildmode=c-shared")
        .arg("-o")
        .arg(out_dir.join(&lib_file))
        .arg(".");

    // Set cross-compiler for Windows targets
    if goos == "windows" {
        if let Ok(cc) = env::var("CC") {
            cmd.env("CC", cc);
        } else {
            cmd.env("CC", "x86_64-w64-mingw32-gcc");
        }
    }

    let status = cmd.status().expect("failed to run `go build`");
    if !status.success() {
        panic!("go build failed with status: {status}");
    }

    // Verify the header file was generated
    let header_path = out_dir.join(header_name(lib_name, &goos));
    assert!(
        header_path.exists(),
        "Go build did not produce header file: {}",
        header_path.display()
    );

    // Generate Rust FFI bindings from the header
    generate_ffi_bindings(&header_path, &out_dir);

    // Tell cargo to link the library
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=dylib={link_name}");

    // Rerun if Go sources change
    println!("cargo:rerun-if-changed=go-lib/netbird_embed.go");
    println!("cargo:rerun-if-changed=go-lib/proxy.go");
    println!("cargo:rerun-if-changed=go-lib/socketpair_unix.go");
    println!("cargo:rerun-if-changed=go-lib/socketpair_windows.go");
    println!("cargo:rerun-if-changed=go-lib/go.mod");
    println!("cargo:rerun-if-changed=go-lib/go.sum");
}

fn parse_target(target: &str) -> (String, String) {
    let parts: Vec<&str> = target.split('-').collect();
    let arch = parts[0];
    let os_part = if target.contains("windows") {
        "windows"
    } else if target.contains("darwin") || target.contains("apple") {
        "darwin"
    } else {
        "linux"
    };

    let goarch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "i686" => "386",
        "arm" => "arm",
        other => panic!("unsupported architecture: {other}"),
    };

    (os_part.to_string(), goarch.to_string())
}

fn lib_output_name(name: &str, goos: &str) -> (String, String) {
    match goos {
        "windows" => (format!("{name}.dll"), name.to_string()),
        "darwin" => (format!("lib{name}.dylib"), name.to_string()),
        _ => (format!("lib{name}.so"), name.to_string()),
    }
}

fn header_name(name: &str, goos: &str) -> String {
    match goos {
        "windows" => format!("{name}.h"),
        _ => format!("lib{name}.h"),
    }
}

fn generate_ffi_bindings(_header_path: &Path, out_dir: &Path) {
    let bindings_path = out_dir.join("ffi_bindings.rs");

    // Manual FFI bindings matching the Go C-shared exports.
    let bindings = r#"// Auto-generated FFI bindings for libnetbird_embed
// Do not edit manually.

use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    pub fn nb_new(
        setup_key: *const c_char,
        management_url: *const c_char,
        device_name: *const c_char,
        token: *const c_char,
        private_key: *const c_char,
        pre_shared_key: *const c_char,
        log_level: *const c_char,
        config_path: *const c_char,
        state_path: *const c_char,
        wireguard_port: c_int,
        disable_client_routes: c_int,
        block_inbound: c_int,
        no_userspace: c_int,
    ) -> c_int;

    pub fn nb_create_errmsg(buf: *mut c_char, buf_len: c_int);

    pub fn nb_start(handle: c_int) -> c_int;

    pub fn nb_stop(handle: c_int) -> c_int;

    pub fn nb_status(handle: c_int, buf: *mut c_char, buf_len: c_int) -> c_int;

    pub fn nb_peers(handle: c_int, buf: *mut c_char, buf_len: c_int) -> c_int;

    pub fn nb_dial(handle: c_int, net_type: *const c_char, addr: *const c_char) -> c_int;

    pub fn nb_listen(handle: c_int, net_type: *const c_char, addr: *const c_char) -> c_int;

    pub fn nb_listen_udp(handle: c_int, addr: *const c_char) -> c_int;

    pub fn nb_set_log_level(handle: c_int, level: *const c_char) -> c_int;

    pub fn nb_errmsg(handle: c_int, buf: *mut c_char, buf_len: c_int);

    pub fn nb_free(handle: c_int);

    pub fn nb_proxy(handle: c_int, target_addr: *const c_char) -> c_int;

    pub fn nb_reverse_proxy(handle: c_int, mesh_port: c_int, local_addr: *const c_char) -> c_int;
}
"#;

    std::fs::write(&bindings_path, bindings)
        .unwrap_or_else(|e| panic!("failed to write bindings: {e}"));
}
