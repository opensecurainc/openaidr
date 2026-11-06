use std::path::{Path, PathBuf};
use tauri::Manager;

pub(crate) const SENSOR_BINARY: &str = "openaidr";

pub(crate) fn sensor_directory(app: &tauri::AppHandle, _home: &Path) -> Result<PathBuf, String> {
    app.path()
        .data_dir()
        .map(|directory| directory.join("openaidr"))
        .map_err(|e| e.to_string())
}
