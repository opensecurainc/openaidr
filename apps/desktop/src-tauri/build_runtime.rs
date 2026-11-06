use std::{fs, path::Path};

// tauri-build copies external executables for development, but macOS.files is
// applied only by the app bundler. Cargo output therefore needs its own runtime.
pub(crate) fn stage(binaries: &Path, target: &str, out_dir: &Path) -> Result<(), String> {
    let executable = binaries.join(format!("openaidr-{target}"));
    let bytes = fs::read(&executable).map_err(|error| format!("Cannot read the sensor: {error}"))?;
    if let Some(runtime) = crate::sensor_runtime::Runtime::inspect(&executable, &bytes)? {
        let output = out_dir.ancestors().nth(3).ok_or("Invalid Cargo output directory")?;
        runtime.stage(output)?;
    }
    Ok(())
}
