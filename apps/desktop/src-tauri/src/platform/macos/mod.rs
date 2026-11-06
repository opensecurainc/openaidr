use std::path::{Path, PathBuf};

pub(crate) mod install_location;
#[path = "../menu_bar.rs"]
pub(crate) mod menu_bar;
pub(crate) mod single_instance;
pub(crate) mod window;

pub(crate) const SENSOR_BINARY: &str = "openaidr";

pub(crate) fn sensor_directory(_app: &tauri::AppHandle, home: &Path) -> Result<PathBuf, String> {
    Ok(home.join("Library/Application Support/OpenAIDR"))
}
