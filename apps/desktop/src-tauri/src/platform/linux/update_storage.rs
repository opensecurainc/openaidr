//! Private per-user AppImage state with durable replacement and native locks.

use serde_json::Value;
use std::{fs::{self, File, OpenOptions}, io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}};

pub struct OperationLock { _file: File }
impl Drop for OperationLock {
    fn drop(&mut self) {
        // A fork can retain this file description until exec. Closing our
        // descriptor alone would leave the completed operation locked.
        let _ = self._file.unlock();
    }
}
pub(super) const BUSY: &str = "A desktop update or sensor operation is in progress. Try again shortly.";

pub(super) fn data_home() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Ok(path);
    }
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute())
        .map(|p| p.join(".local/share")).ok_or("Cannot locate user application data.".into())
}

pub(super) fn directory() -> Result<PathBuf, String> {
    if unsafe { libc::geteuid() } == 0 { return Err("Run OpenAIDR as your normal desktop user.".into()); }
    let path = data_home()?.join("openaidr/desktop");
    private_directory(&path)?;
    Ok(path)
}

pub(super) fn reject_links(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return Err("Update paths must be absolute without parent components.".into());
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(info) if info.file_type().is_symlink() => return Err("Update paths cannot contain links.".into()),
            Ok(_) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => return Err("Cannot inspect the update path.".into()),
        }
    }
    Ok(())
}

pub(super) fn private_directory(path: &Path) -> Result<(), String> {
    reject_links(path)?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
        .map_err(|_| "Cannot create private update data.")?;
    let info = fs::metadata(path).map_err(|_| "Cannot inspect private update data.")?;
    if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 {
        return Err("Update data must be private to this account.".into());
    }
    Ok(())
}

pub(super) fn open(path: &Path, limit: u64) -> Result<File, std::io::Error> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let info = file.metadata()?;
    if !info.is_file() || info.nlink() != 1 || info.len() > limit
        || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o022 != 0 {
        return Err(std::io::Error::other("Unsafe or oversized updater file"));
    }
    Ok(file)
}

pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let file = open(path, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(std::io::Error::other("Oversized updater file")); }
    Ok(bytes)
}

pub(super) fn sync(directory: &Path) -> Result<(), String> {
    File::open(directory).and_then(|file| file.sync_all()).map_err(|_| "Cannot save update state durably.".into())
}

pub(super) fn write(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    write_from(path, &mut &bytes[..], bytes.len() as u64, executable)
}

pub(super) fn write_from(path: &Path, source: &mut impl Read, limit: u64, executable: bool) -> Result<(), String> {
    let directory = path.parent().ok_or("Invalid update path.")?;
    reject_links(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|_| "Cannot save update state.")?;
    let copied = std::io::copy(&mut source.take(limit + 1), &mut temporary).map_err(|_| "Cannot save update state.")?;
    if copied > limit { return Err("Oversized updater file".into()); }
    temporary.as_file().set_permissions(fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }))
        .and_then(|_| temporary.as_file().sync_all()).map_err(|_| "Cannot save update state.")?;
    temporary.persist(path).map_err(|_| "Cannot replace update state.")?;
    sync(directory)
}

pub(super) fn json_file(path: &Path) -> Result<Option<Value>, String> {
    match read(path, 64 * 1024) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| "Cannot read update state.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("Cannot read update state.".into()),
    }
}

pub(super) fn lock(directory: &Path, name: &str) -> Result<OperationLock, String> {
    private_directory(directory)?;
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(directory.join(name))
        .map_err(|_| "Cannot open the desktop operation lock.")?;
    let info = file.metadata().map_err(|_| "Cannot inspect the desktop operation lock.")?;
    if !info.is_file() || info.nlink() != 1 || info.len() != 0 || info.mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() } {
        return Err("The desktop operation lock is unsafe.".into());
    }
    file.try_lock().map_err(|_| BUSY)?;
    Ok(OperationLock { _file: file })
}

pub(super) fn installation_id(directory: &Path, _guard: &OperationLock) -> Result<String, String> {
    let path = directory.join("desktop-installation-id");
    match read(&path, 32) {
        Ok(bytes) => {
            let info = fs::symlink_metadata(&path).map_err(|_| "Cannot inspect the installation ID.")?;
            let id = String::from_utf8(bytes).map_err(|_| "The installation ID is invalid.")?;
            if info.mode() & 0o077 != 0 || !crate::platform::updater::rollout::valid_installation_id(&id) {
                return Err("The private installation ID is invalid. The current app was kept.".into());
            }
            return Ok(id);
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(_) => return Err("Cannot read the private installation ID. The current app was kept.".into()),
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| "Cannot create an installation ID.")?;
    let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|_| "Cannot save the installation ID.")?;
    temporary.write_all(id.as_bytes()).and_then(|_| temporary.as_file().sync_all()).map_err(|_| "Cannot save the installation ID.")?;
    temporary.persist_noclobber(&path).map_err(|_| "Cannot save the installation ID.")?;
    sync(directory)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_atomic_state_survive_restarts_and_reject_unsafe_files() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop");
        private_directory(&directory).unwrap();
        let guard = lock(&directory, "operation.lock").unwrap();
        assert!(lock(&directory, "operation.lock").is_err());
        let id = installation_id(&directory, &guard).unwrap();
        let inherited = guard._file.try_clone().unwrap();
        drop(guard);
        let guard = lock(&directory, "operation.lock").unwrap();
        drop(inherited);
        assert!(lock(&directory, "operation.lock").is_err());
        assert_eq!(installation_id(&directory, &guard).unwrap(), id);
        let path = directory.join("state.json");
        write(&path, br#"{"state":"installing"}"#, false).unwrap();
        write(&path, br#"{"state":"idle"}"#, false).unwrap();
        assert_eq!(json_file(&path).unwrap().unwrap()["state"], "idle");
        let identity = directory.join("desktop-installation-id");
        let linked = directory.join("linked-id");
        fs::hard_link(&identity, &linked).unwrap();
        assert!(installation_id(&directory, &guard).is_err());
        fs::remove_file(linked).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(installation_id(&directory, &guard).is_err());
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&identity, b"invalid").unwrap();
        assert!(installation_id(&directory, &guard).is_err());
        assert_eq!(fs::read(&identity).unwrap(), b"invalid");
        fs::remove_file(&identity).unwrap();
        std::os::unix::fs::symlink(&path, &identity).unwrap();
        assert!(installation_id(&directory, &guard).is_err());
    }
}
