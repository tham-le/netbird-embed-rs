use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
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

    // Report the pinned NetBird release instead of the "development" default,
    // so management does not classify the embedded peer as a dev build.
    let netbird_version = netbird_version(&go_lib_dir.join("go.mod"));
    let ldflags = format!("-X github.com/netbirdio/netbird/version.version={netbird_version}");

    // Build the Go C-shared library
    let mut cmd = Command::new("go");
    cmd.current_dir(&go_lib_dir)
        .env("CGO_ENABLED", "1")
        .env("GOOS", &goos)
        .env("GOARCH", &goarch)
        .arg("build")
        .arg("-buildmode=c-shared")
        .arg("-ldflags")
        .arg(ldflags)
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

    // The cgo header is the authoritative ABI. Verify the declarations we
    // generate against it instead of trusting a hand-maintained string.
    let header_path = out_dir.join(header_name(lib_name, &goos));
    assert!(
        header_path.exists(),
        "Go build did not produce header file: {}",
        header_path.display()
    );
    verify_header(&header_path);

    generate_ffi_bindings(&out_dir);

    // Tell cargo to link the library
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=dylib={link_name}");

    // Rebuild when any Go source or module metadata changes.
    println!("cargo:rerun-if-changed=go-lib");
    println!("cargo:rerun-if-changed=build.rs");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    /// `*const c_char`
    CStr,
    /// `*mut c_char`
    Buf,
    /// `c_int`
    Int,
    /// No return value
    Void,
}

impl Ty {
    fn c_type(self) -> &'static str {
        match self {
            Ty::CStr | Ty::Buf => "char*",
            Ty::Int => "int",
            Ty::Void => "void",
        }
    }

    fn rust_type(self) -> &'static str {
        match self {
            Ty::CStr => "*const c_char",
            Ty::Buf => "*mut c_char",
            Ty::Int => "c_int",
            Ty::Void => "()",
        }
    }
}

struct Fn {
    name: &'static str,
    ret: Ty,
    params: &'static [(&'static str, Ty)],
}

const fn f(name: &'static str, ret: Ty, params: &'static [(&'static str, Ty)]) -> Fn {
    Fn { name, ret, params }
}

/// Every symbol the Rust side calls. The generated `extern "C"` block and the
/// header check are both derived from this table.
static FNS: &[Fn] = &[
    f(
        "nb_new",
        Ty::Int,
        &[
            ("setup_key", Ty::CStr),
            ("management_url", Ty::CStr),
            ("device_name", Ty::CStr),
            ("token", Ty::CStr),
            ("private_key", Ty::CStr),
            ("pre_shared_key", Ty::CStr),
            ("log_level", Ty::CStr),
            ("config_path", Ty::CStr),
            ("state_path", Ty::CStr),
            ("dns_labels_json", Ty::CStr),
            ("nat_external_ips_json", Ty::CStr),
            ("wireguard_port", Ty::Int),
            ("disable_client_routes", Ty::Int),
            ("block_inbound", Ty::Int),
            ("no_userspace", Ty::Int),
            ("disable_ipv6", Ty::Int),
            ("enable_rosenpass", Ty::Int),
            ("rosenpass_permissive", Ty::Int),
            ("block_lan_access", Ty::Int),
            ("lazy_connection_enabled", Ty::Int),
            ("mtu", Ty::Int),
            ("preallocated_buffers_per_pool", Ty::Int),
            ("max_batch_size", Ty::Int),
        ],
    ),
    f(
        "nb_create_errmsg",
        Ty::Void,
        &[("buf", Ty::Buf), ("buf_len", Ty::Int)],
    ),
    f("nb_start", Ty::Int, &[("handle", Ty::Int)]),
    f("nb_stop", Ty::Int, &[("handle", Ty::Int)]),
    f(
        "nb_status",
        Ty::Int,
        &[("handle", Ty::Int), ("buf", Ty::Buf), ("buf_len", Ty::Int)],
    ),
    f(
        "nb_peers",
        Ty::Int,
        &[("handle", Ty::Int), ("buf", Ty::Buf), ("buf_len", Ty::Int)],
    ),
    f(
        "nb_dial",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("net_type", Ty::CStr),
            ("addr", Ty::CStr),
        ],
    ),
    f(
        "nb_dial_udp",
        Ty::Int,
        &[("handle", Ty::Int), ("addr", Ty::CStr)],
    ),
    f(
        "nb_listen",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("net_type", Ty::CStr),
            ("addr", Ty::CStr),
        ],
    ),
    f(
        "nb_listen_udp",
        Ty::Int,
        &[("handle", Ty::Int), ("addr", Ty::CStr)],
    ),
    f("nb_listener_close", Ty::Void, &[("fd", Ty::Int)]),
    f(
        "nb_set_log_level",
        Ty::Int,
        &[("handle", Ty::Int), ("level", Ty::CStr)],
    ),
    f(
        "nb_set_performance",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("preallocated_buffers_per_pool", Ty::Int),
            ("max_batch_size", Ty::Int),
        ],
    ),
    f(
        "nb_identity_for_ip",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("ip", Ty::CStr),
            ("buf", Ty::Buf),
            ("buf_len", Ty::Int),
        ],
    ),
    f(
        "nb_expose",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("request_json", Ty::CStr),
            ("buf", Ty::Buf),
            ("buf_len", Ty::Int),
        ],
    ),
    f(
        "nb_expose_stop",
        Ty::Int,
        &[("handle", Ty::Int), ("domain", Ty::CStr)],
    ),
    f(
        "nb_capture_start",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("options_json", Ty::CStr),
            ("buf", Ty::Buf),
            ("buf_len", Ty::Int),
        ],
    ),
    f(
        "nb_capture_stats",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("capture_id", Ty::Int),
            ("buf", Ty::Buf),
            ("buf_len", Ty::Int),
        ],
    ),
    f(
        "nb_capture_stop",
        Ty::Int,
        &[("handle", Ty::Int), ("capture_id", Ty::Int)],
    ),
    f(
        "nb_errmsg",
        Ty::Void,
        &[("handle", Ty::Int), ("buf", Ty::Buf), ("buf_len", Ty::Int)],
    ),
    f("nb_free", Ty::Void, &[("handle", Ty::Int)]),
    f(
        "nb_proxy",
        Ty::Int,
        &[("handle", Ty::Int), ("target_addr", Ty::CStr)],
    ),
    f(
        "nb_reverse_proxy",
        Ty::Int,
        &[
            ("handle", Ty::Int),
            ("mesh_port", Ty::Int),
            ("local_addr", Ty::CStr),
        ],
    ),
];

fn verify_header(header: &Path) {
    let contents = std::fs::read_to_string(header)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", header.display()));

    let mut declared: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("extern ") else {
            continue;
        };
        if !rest.contains("nb_") {
            continue;
        }
        let rest = rest.strip_suffix(';').unwrap_or(rest);
        let (ret, call) = rest
            .split_once(' ')
            .unwrap_or_else(|| panic!("malformed declaration: {line}"));
        let (name, params) = call
            .split_once('(')
            .unwrap_or_else(|| panic!("malformed declaration: {line}"));
        let params = params
            .strip_suffix(')')
            .unwrap_or_else(|| panic!("malformed declaration: {line}"));

        let mut types = Vec::new();
        if !params.trim().is_empty() && params.trim() != "void" {
            for param in params.split(',') {
                let c_type = param
                    .split_whitespace()
                    .next()
                    .unwrap_or_else(|| panic!("malformed parameter in: {line}"));
                let canonical = match c_type {
                    "char*" => "char*",
                    "int" => "int",
                    other => panic!("unsupported parameter type {other:?} in: {line}"),
                };
                types.push(canonical.to_string());
            }
        }
        if declared
            .insert(name.to_string(), (ret.to_string(), types))
            .is_some()
        {
            panic!("duplicate declaration for {name}");
        }
    }

    for func in FNS {
        let Some((ret, types)) = declared.get(func.name) else {
            panic!("go header is missing export {}", func.name);
        };
        let expected_ret = match func.ret {
            Ty::Int => "int",
            _ => "void",
        };
        assert_eq!(
            ret, expected_ret,
            "return type mismatch for {}: header has {ret}, bindings expect {expected_ret}",
            func.name
        );
        let expected: Vec<String> = func
            .params
            .iter()
            .map(|(_, ty)| ty.c_type().to_string())
            .collect();
        assert_eq!(
            types, &expected,
            "parameter mismatch for {}: header has {types:?}, bindings expect {expected:?}",
            func.name
        );
    }

    for name in declared.keys() {
        if !FNS.iter().any(|f| f.name == name) {
            panic!("go header exports {name}, but the bindings table does not declare it");
        }
    }
}

/// Extract the pinned `github.com/netbirdio/netbird` module version from go.mod.
///
/// The value is injected into the Go version package so the peer reports the
/// NetBird release it is built against (e.g. `0.82.0`) rather than the
/// upstream `development` placeholder.
fn netbird_version(go_mod: &Path) -> String {
    const MODULE: &str = "github.com/netbirdio/netbird ";

    let contents = std::fs::read_to_string(go_mod)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", go_mod.display()));

    contents
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(MODULE))
        .and_then(|rest| rest.split_whitespace().next())
        .map(|version| version.trim_start_matches('v').to_string())
        .unwrap_or_else(|| panic!("no {MODULE} requirement found in {}", go_mod.display()))
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

fn generate_ffi_bindings(out_dir: &Path) {
    let bindings_path = out_dir.join("ffi_bindings.rs");

    let mut bindings = String::new();
    bindings.push_str("// Auto-generated FFI bindings for libnetbird_embed\n");
    bindings.push_str("// Do not edit manually.\n\n");
    bindings.push_str("use std::os::raw::{c_char, c_int};\n\n");
    bindings.push_str("unsafe extern \"C\" {\n");

    for func in FNS {
        let ret = match func.ret {
            Ty::Int => "c_int",
            _ => "()",
        };
        let params: Vec<String> = func
            .params
            .iter()
            .map(|(name, ty)| format!("{name}: {}", ty.rust_type()))
            .collect();
        writeln!(
            bindings,
            "    pub fn {}({}) -> {ret};",
            func.name,
            params.join(", ")
        )
        .unwrap();
    }
    bindings.push_str("}\n");

    std::fs::write(&bindings_path, bindings)
        .unwrap_or_else(|e| panic!("failed to write bindings: {e}"));
}
