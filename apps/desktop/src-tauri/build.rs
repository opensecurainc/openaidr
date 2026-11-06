#[cfg(target_os = "macos")]
#[path = "src/sensor_runtime.rs"]
mod sensor_runtime;
#[cfg(target_os = "macos")]
mod build_runtime;

fn main() {
    println!("cargo:rerun-if-env-changed=OPENAIDR_MACOS_UNIVERSAL");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // The Intel slice is built only as part of a universal app
        // (scripts/build_desktop.py --macos-universal), never on its own.
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH");
        let universal = std::env::var("OPENAIDR_MACOS_UNIVERSAL").as_deref() == Ok("1");
        assert!(arch.as_deref() == Ok("aarch64") || (universal && arch.as_deref() == Ok("x86_64")),
            "OpenAIDR for macOS requires Apple Silicon; Intel builds are not supported");
    }
    let path = std::path::Path::new("../../../build/desktop/_build.json");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(path)
        .expect("Run scripts/build_desktop.py --sidecar-only to generate build metadata first");
    let info: serde_json::Value = serde_json::from_str(&text).expect("Invalid build metadata");
    let root = std::path::Path::new("../../..");
    // The release channel fixes the update feed and its verification key at compile time.
    println!("cargo:rerun-if-env-changed=OPENAIDR_RELEASE_CHANNEL");
    let channel = std::env::var("OPENAIDR_RELEASE_CHANNEL").unwrap_or_else(|_| "openaidr".into());
    let key_file = match channel.as_str() {
        "openaidr" => "updater.pub",
        "openaidr-oss" => "updater-oss.pub",
        other => panic!("Unknown OPENAIDR_RELEASE_CHANNEL {other:?}; use openaidr or openaidr-oss"),
    };
    let key = std::fs::canonicalize(root.join("deploy/desktop").join(key_file))
        .unwrap_or_else(|_| panic!("The {channel} release channel requires deploy/desktop/{key_file}"));
    println!("cargo:rerun-if-changed={}", key.display());
    println!("cargo:rustc-env=OPENAIDR_RELEASE_CHANNEL={channel}");
    println!("cargo:rustc-env=OPENAIDR_UPDATER_PUBLIC_KEY_PATH={}", key.display());
    if root.join(".git").exists() {
        for (args, expected) in [
            (vec!["rev-parse", "HEAD"], info["source_commit"].as_str().expect("Missing source commit")),
            (vec!["status", "--porcelain"], ""),
        ] {
            let output = std::process::Command::new("git").args(args).current_dir(root)
                .output().expect("Cannot verify build source");
            assert!(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == expected,
                "Build from clean source and regenerate the sensor metadata before compiling the app");
        }
    }
    println!("cargo:rustc-env=OPENAIDR_VERSION={}", info["version"].as_str().expect("Missing build version"));
    println!("cargo:rustc-env=OPENAIDR_BUILD_INFO={}", text.trim());
    #[cfg(target_os = "macos")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=binaries");
        build_runtime::stage(
            std::path::Path::new("binaries"),
            &std::env::var("TARGET").expect("Cargo did not set TARGET"),
            std::path::Path::new(&std::env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR")),
        ).expect("Cannot stage the macOS sensor runtime for this Cargo build");
    }
    tauri_build::build();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Tauri links resources only into app binaries. Native GUI integration
        // tests also need its Common Controls v6 manifest to load on Windows.
        let resource = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("resource.lib");
        assert!(resource.is_file(), "Tauri did not generate Windows resources");
        println!("cargo:rustc-link-arg-tests={}", resource.display());
    }
}
