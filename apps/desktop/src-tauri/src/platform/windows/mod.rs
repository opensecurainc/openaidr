use std::path::PathBuf;
use tauri::Manager;

/// Windows ships the sensor as a one-directory runtime resource, as ADR does.
/// The window runs it from the installation; installing the background
/// service stages a versioned per-user copy itself
/// (src/openaidr/sensor/windows_runtime.py).
pub(crate) fn bundled_sensor(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?;
    let directory = if directory.join("runtime").exists() { directory.join("runtime") }
        else { directory.join("sensor") };
    let canonical = directory.join("openaidr.exe");
    Ok(if canonical.symlink_metadata().is_ok() { canonical }
        else { directory.join("openaidr-sensor.exe") })
}
