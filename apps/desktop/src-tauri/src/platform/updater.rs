//! Shared desktop update interface and capability fallback.

#[cfg(any(target_os = "macos", windows, target_os = "linux", test))]
#[path = "rollout.rs"]
mod rollout;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
#[path = "manual_update.rs"]
mod manual_update;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
#[path = "update_check.rs"]
mod update_check;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
#[path = "update_download.rs"]
mod update_download;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
#[path = "sensor_handoff.rs"]
mod sensor_handoff;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Window,
    Check,
    Finish,
}

impl Mode {
    pub fn from_args() -> Self {
        match std::env::args().nth(1).as_deref() {
            Some("--background-update") => Self::Check,
            Some("--finish-update") => Self::Finish,
            _ => Self::Window,
        }
    }

    pub fn headless(self) -> bool {
        self != Self::Window
    }
}

#[cfg(target_os = "macos")]
#[path = "macos/updater.rs"]
mod native;
#[cfg(target_os = "macos")]
pub use native::*;

#[cfg(windows)]
#[path = "windows/updater.rs"]
mod native;
#[cfg(windows)]
pub use native::*;

#[cfg(target_os = "linux")]
#[path = "linux/updater.rs"]
mod native;
#[cfg(target_os = "linux")]
pub use native::*;

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod manual_unavailable {
    #[derive(Default)]
    pub struct ManualUpdate;

    pub async fn manual(_app: &tauri::AppHandle, _version: Option<String>) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({"state":"unavailable", "latest":"",
            "error":"Manual in-app updates are not supported on this platform yet. Automatic updates continue on supported installations."}))
    }

    pub fn cancel(_app: &tauri::AppHandle) -> Result<serde_json::Value, String> {
        Ok(serde_json::Value::Null)
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub use manual_unavailable::*;

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod unsupported {
    use super::Mode;
    use serde_json::Value;
    use tauri::{AppHandle, Config};

    pub struct OperationLock;

    pub fn enabled(_config: &Config) -> bool {
        false
    }

    pub fn removal_supported() -> bool {
        false
    }

    pub fn removal_status(_app: &AppHandle) -> Option<Value> {
        None
    }

    pub fn removal_lock(_app: &AppHandle) -> Result<OperationLock, String> {
        Err("Desktop removal is supported on macOS only.".into())
    }

    pub fn prepare_removal(_app: &AppHandle) -> Result<(), String> {
        Err("Desktop removal is supported on macOS only.".into())
    }

    pub fn resume_removal(_app: &AppHandle) -> Result<(), String> {
        Err("Desktop removal is supported on macOS only.".into())
    }

    pub fn trash_app(_app: &AppHandle) -> Result<(), String> {
        Err("Moving the app to Trash is supported on macOS only.".into())
    }

    pub fn operation_lock(_app: &AppHandle) -> Result<OperationLock, String> {
        Ok(OperationLock)
    }

    pub fn status(_app: &AppHandle) -> Option<Value> {
        None
    }

    pub fn read_status(_app: &AppHandle) -> Result<Option<Value>, String> {
        Ok(None)
    }

    pub fn restart_after_update(_app: &AppHandle) -> bool {
        false
    }

    pub fn initialize(app: &AppHandle, mode: Mode) {
        if mode.headless() {
            app.exit(0);
        }
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub use unsupported::*;
