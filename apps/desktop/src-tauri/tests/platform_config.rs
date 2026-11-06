use serde_json::{json, Value};
use std::path::Path;
use tauri::utils::{
    config::{parse::read_from, Config},
    platform::Target,
};

#[test]
fn native_bundle_targets_preserve_shared_app_and_sensor_settings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let shared: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    for (target, targets) in [
        (Target::MacOS, json!(["app", "dmg"])),
        (Target::Windows, json!(["nsis"])),
        (Target::Linux, json!(["deb", "appimage"])),
    ] {
        let (resolved, _) = read_from(target, root).unwrap();
        let _: Config = serde_json::from_value(resolved.clone()).unwrap();
        assert_eq!(resolved["bundle"]["targets"], targets);
        for key in ["productName", "identifier", "version", "app", "build"] {
            assert_eq!(resolved[key], shared[key], "{target:?}: {key}");
        }
        assert_eq!(resolved["bundle"]["active"], shared["bundle"]["active"]);
        let bundle = if target == Target::Windows {
            // Windows bundles a sensor runtime directory instead of a sidecar.
            serde_json::from_str::<Value>(include_str!("../tauri.windows.conf.json")).unwrap()
        } else {
            shared.clone()
        };
        if target == Target::Windows {
            assert_eq!(resolved["bundle"]["resources"]["binaries/openaidr-runtime"], "runtime");
        }
        for key in ["externalBin", "icon"] {
            assert_eq!(
                resolved["bundle"][key], bundle["bundle"][key],
                "{target:?}: {key}"
            );
        }
        if target == Target::MacOS {
            assert_eq!(resolved["bundle"]["macOS"]["minimumSystemVersion"], "12.0");
            let dmg = &resolved["bundle"]["macOS"]["dmg"];
            let background = std::fs::read(root.join(dmg["background"].as_str().unwrap())).unwrap();
            assert_eq!(&background[..8], b"\x89PNG\r\n\x1a\n");
            let width = u32::from_be_bytes(background[16..20].try_into().unwrap());
            let height = u32::from_be_bytes(background[20..24].try_into().unwrap());
            // The 144-DPI background has two pixels per logical Finder point.
            assert_eq!(dmg["windowSize"], json!({"width": width / 2, "height": height / 2}));
            for position in ["appPosition", "applicationFolderPosition"] {
                assert!(dmg[position]["x"].as_u64().unwrap() < u64::from(width / 2));
                assert!(dmg[position]["y"].as_u64().unwrap() < u64::from(height / 2));
            }
        } else {
            assert!(resolved["bundle"].get("macOS").is_none());
        }
    }
}
