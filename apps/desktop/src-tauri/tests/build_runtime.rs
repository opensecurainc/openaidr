#![cfg(target_os = "macos")]

#[path = "../src/sensor_runtime.rs"]
mod sensor_runtime;
#[path = "../build_runtime.rs"]
mod build_runtime;

use std::{fs, path::Path};

#[test]
fn cargo_outputs_receive_validated_runtime_without_flattening_framework_links() {
    let scratch = tempfile::tempdir().unwrap();
    let binaries = scratch.path().join("binaries");
    let fixture = sensor_runtime::tests::fixture(&binaries, 'a', 1);
    let target = "aarch64-apple-darwin";
    let executable = binaries.join(format!("openaidr-{target}"));
    fs::rename(fixture, &executable).unwrap();
    let runtime = format!("openaidr-runtime-{}", "a".repeat(64));
    for output in ["target/debug", "custom/target/aarch64-apple-darwin/release"] {
        let output = scratch.path().join(output);
        let out_dir = output.join("build/openaidr-desktop-test/out");
        fs::create_dir_all(&out_dir).unwrap();
        build_runtime::stage(&binaries, target, &out_dir).unwrap();
        let staged = output.join(&runtime);
        assert_eq!(fs::read_link(staged.join("Python.framework/Versions/Current")).unwrap(), Path::new("3.14"));
        assert_eq!(fs::read(staged.join("Python")).unwrap(), b"runtime a");
        build_runtime::stage(&binaries, target, &out_dir).unwrap();
        fs::write(staged.join("Python"), "corrupted").unwrap();
        assert!(build_runtime::stage(&binaries, target, &out_dir).is_err());
        assert_eq!(fs::read(staged.join("Python")).unwrap(), b"corrupted");
    }
    fs::write(&executable, "legacy onefile executable").unwrap();
    let legacy = scratch.path().join("legacy/debug/build/openaidr-desktop-test/out");
    fs::create_dir_all(&legacy).unwrap();
    build_runtime::stage(&binaries, target, &legacy).unwrap();
    assert!(!legacy.ancestors().nth(3).unwrap().join(runtime).exists());
}
