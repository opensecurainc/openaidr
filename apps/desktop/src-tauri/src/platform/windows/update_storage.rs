//! Private updater state, native file locks, and bounded Windows operations.

use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{fs::{MetadataExt, OpenOptionsExt}, io::AsRawHandle},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tauri::Manager;
use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
use windows_sys::Win32::{System::Com::CoTaskMemFree, UI::Shell::{SHGetKnownFolderPath, FOLDERID_LocalAppData}};

pub(super) struct Directory(PathBuf);
pub struct OperationLock { _file: File }
pub(super) const BUSY: &str = "A desktop update or sensor operation is in progress. Try again shortly.";
const REPARSE_POINT: u32 = 0x400;
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub(super) fn support(operation: &str, path: &Path) -> Result<(), String> {
    support_input(json!({"operation": operation, "path": path}))
}

pub(super) fn support_input(input: Value) -> Result<(), String> {
    let powershell = PathBuf::from(std::env::var_os("SystemRoot").ok_or("Cannot locate Windows tools.")?)
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut command = Command::new(powershell);
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", include_str!("update-support.ps1")])
        .env_remove("PSModulePath")
        .env("OPENAIDR_UPDATE_INPUT", input.to_string())
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(test)]
    command.stderr(Stdio::inherit());
    crate::hide_console(&mut command);
    let mut child = command.spawn().map_err(|_| "Cannot start the Windows update operation.")?;
    let (status, _) = crate::child_output(&mut child, Duration::from_secs(30), 65536)?;
    if !status.success() {
        return Err(format!("Windows could not complete the update {} operation.", input["operation"].as_str().unwrap_or("support")));
    }
    Ok(())
}

pub(super) fn directory(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Some(directory) = app.try_state::<Directory>() { return Ok(directory.0.clone()); }
    let path = private_directory()?;
    app.manage(Directory(path.clone()));
    Ok(path)
}

pub(super) fn private_directory() -> Result<PathBuf, String> {
    let local = local_data()?;
    let current = local.join("OpenAIDR/data");
    if current.exists() && local.join("OpenAIDR Sensor/sensor.yaml").exists() {
        return Err("Both Windows configurations exist. No configuration was selected.".into());
    }
    let legacy = local.join("OpenAIDR Sensor");
    let path = if current.exists() || !legacy.exists() { current } else { legacy }.join("desktop-update");
    support("directory", &path)?;
    Ok(path)
}

pub(super) fn local_data() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    let mut raw = std::ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut raw) } < 0 || raw.is_null() {
        return Err("Cannot locate private app data.".into());
    }
    let path = unsafe {
        let mut length = 0;
        while *raw.add(length) != 0 { length += 1; }
        let path = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(raw, length)));
        CoTaskMemFree(raw.cast());
        path
    };
    Ok(path)
}

pub(super) fn reject_links(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(info) if info.file_attributes() & REPARSE_POINT != 0 => return Err("Update paths cannot contain links.".into()),
            Ok(_) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => return Err("Cannot inspect the update path.".into()),
        }
    }
    Ok(())
}

fn regular(file: &File, limit: u64) -> Result<(), std::io::Error> {
    let metadata = file.metadata()?;
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 { return Err(std::io::Error::last_os_error()); }
    let info = unsafe { info.assume_init() };
    if !metadata.is_file() || metadata.file_attributes() & REPARSE_POINT != 0
        || info.nNumberOfLinks != 1 || metadata.len() > limit {
        return Err(std::io::Error::other("unsafe updater file"));
    }
    Ok(())
}

pub(super) fn open(path: &Path, limit: u64) -> Result<File, std::io::Error> {
    let file = OpenOptions::new().read(true).custom_flags(OPEN_REPARSE_POINT).open(path)?;
    regular(&file, limit)?;
    Ok(file)
}

pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let file = open(path, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(std::io::Error::other("oversized updater file")); }
    Ok(bytes)
}

pub(super) fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_from(path, &mut &bytes[..], bytes.len() as u64)
}

pub(super) fn write_from(path: &Path, source: &mut impl Read, limit: u64) -> Result<(), String> {
    let directory = path.parent().ok_or("Invalid update state path.")?;
    reject_links(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|_| "Cannot save update state.")?;
    let copied = std::io::copy(&mut source.take(limit + 1), &mut temporary).map_err(|_| "Cannot save update state.")?;
    if copied > limit { return Err("Oversized updater file".into()); }
    temporary.as_file().sync_all()
        .map_err(|_| "Cannot save update state.")?;
    temporary.persist(path).map_err(|_| "Cannot save update state.")?;
    Ok(())
}

pub(super) fn lock(directory: &Path, name: &str) -> Result<OperationLock, String> {
    let path = directory.join(name);
    reject_links(&path)?;
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .custom_flags(OPEN_REPARSE_POINT).open(&path).map_err(|_| "Cannot open the desktop operation lock.")?;
    regular(&file, 0).map_err(|_| "The desktop operation lock is unsafe.")?;
    file.try_lock().map_err(|_| BUSY)?;
    Ok(OperationLock { _file: file })
}

pub(super) fn installation_id(directory: &Path, _lock: &OperationLock) -> Result<String, String> {
    let path = directory.join("desktop-installation-id");
    match read(&path, 32) {
        Ok(bytes) => {
            support("identity", &path)?;
            let id = String::from_utf8(bytes).map_err(|_| "The private installation ID is invalid.")?;
            if !crate::platform::updater::rollout::valid_installation_id(&id) {
                return Err("The private installation ID is invalid.".into());
            }
            return Ok(id);
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(_) => return Err("Cannot read the private installation ID. The current app was kept.".into()),
    }
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "Cannot create a private installation ID.")?;
    let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|_| "Cannot save the installation ID.")?;
    temporary.write_all(id.as_bytes()).and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| "Cannot save the installation ID.")?;
    support("private-file", temporary.path())?;
    temporary.persist_noclobber(path).map_err(|_| "Cannot save the installation ID.")?;
    Ok(id)
}

pub(super) fn json_file(path: &Path) -> Result<Option<Value>, String> {
    match read(path, 64 * 1024) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| "Cannot read update state.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("Cannot read update state.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_identity_survives_restarts_and_rejects_unsafe_files() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop-update");
        support("directory", &directory).unwrap();
        let first = lock(&directory, "operation.lock").unwrap();
        assert!(lock(&directory, "operation.lock").is_err());
        let id = installation_id(&directory, &first).unwrap();
        drop(first);
        let next = lock(&directory, "operation.lock").unwrap();
        assert_eq!(installation_id(&directory, &next).unwrap(), id);
        let path = directory.join("desktop-installation-id");
        let other = directory.join("linked-id");
        fs::hard_link(&path, &other).unwrap();
        assert!(installation_id(&directory, &next).is_err());
        fs::remove_file(other).unwrap();
        fs::write(&path, b"invalid").unwrap();
        assert!(installation_id(&directory, &next).is_err());
        assert_eq!(fs::read(path).unwrap(), b"invalid");
    }

    #[test]
    fn state_replacement_is_complete_and_bounded() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop-update");
        support("directory", &directory).unwrap();
        let path = directory.join("state.json");
        assert!(json_file(&path).unwrap().is_none());
        write(&path, br#"{"state":"installing"}"#).unwrap();
        write(&path, br#"{"state":"idle"}"#).unwrap();
        assert_eq!(json_file(&path).unwrap(), Some(json!({"state":"idle"})));
        assert!(read(&path, 1).is_err());
        fs::write(&path, b"{").unwrap();
        assert!(json_file(&path).is_err());
    }
}
