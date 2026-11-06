//! A retained executable repairs interrupted NSIS updates outside the install folder.

use super::{current_build, key, load, Pending, State, JOURNAL, MAX_DOWNLOAD};
use super::update_storage as storage;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant}};

#[derive(Deserialize, Serialize)]
struct Installation {
    executable: PathBuf,
    worker: PathBuf,
}

fn worker_name(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
        name.strip_prefix("worker-").and_then(|name| name.strip_suffix(".exe"))
            .is_some_and(|sha| sha.len() == 40 && sha.bytes().all(|c| c.is_ascii_hexdigit()))
    })
}

fn installation(directory: &Path) -> Result<Installation, String> {
    let record = installation_record(directory)?;
    storage::support("identity", record.executable.parent().unwrap())?;
    Ok(record)
}

fn installation_record(directory: &Path) -> Result<Installation, String> {
    let value = storage::json_file(&directory.join("installation.json"))?
        .ok_or("The update installation record is missing.")?;
    let record: Installation = serde_json::from_value(value).map_err(|_| "The update installation record is invalid.")?;
    validate_installation_path(directory, &record.executable)?;
    if record.worker.parent() != Some(directory) || !worker_name(&record.worker) {
        return Err("The saved update worker path is invalid.".into());
    }
    storage::reject_links(&record.worker)?;
    Ok(record)
}

fn validate_installation(directory: &Path, executable: &Path) -> Result<(), String> {
    validate_installation_path(directory, executable)?;
    storage::support("identity", executable.parent().unwrap())
}

fn validate_installation_path(directory: &Path, executable: &Path) -> Result<(), String> {
    let root = executable.parent().ok_or("The installed app path is invalid.")?;
    let text = executable.to_str().ok_or("Automatic updates require a Unicode installation path.")?;
    if !executable.is_absolute() || executable.file_name() != Some("openaidr-desktop.exe".as_ref())
        || directory.starts_with(root) || root.starts_with(directory)
        || text.contains(['"', '\r', '\n'])
        || !matches!(executable.components().next(), Some(std::path::Component::Prefix(prefix))
            if matches!(prefix.kind(), std::path::Prefix::Disk(_)))
        || executable.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return Err("Automatic updates require a separate, private app installation folder.".into());
    }
    storage::reject_links(executable)
}

pub(super) fn register(directory: &Path, executable: &Path) -> Result<(), String> {
    validate_installation(directory, executable)?;
    if directory.join("installation.json").exists() && installation(directory)?.executable != executable {
        return Err("Another OpenAIDR installation owns this account's update schedule.".into());
    }
    let worker = retain(directory, executable, &current_build())?;
    let record = Installation { executable: executable.into(), worker: worker.clone() };
    storage::write(&directory.join("installation.json"), &serde_json::to_vec(&record).map_err(|_| "Cannot retain the update installation.")?)?;
    storage::support_input(json!({"operation":"schedule", "path":worker, "directory":directory}))?;
    if directory.join("removed").exists() {
        fs::remove_file(directory.join("removed")).map_err(|_| "Cannot restore automatic updates.")?;
    }
    if load(directory)?.pending.is_none() {
        retire_workers(directory, Some(&worker));
    }
    Ok(())
}

pub(super) fn retain(directory: &Path, executable: &Path, build: &Value) -> Result<PathBuf, String> {
    let commit = build["source_commit"].as_str().ok_or("The app has no source identity.")?;
    if commit.len() != 40 || !commit.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("The app has invalid source identity.".into());
    }
    let worker = directory.join(format!("worker-{commit}.exe"));
    let bytes = storage::read(executable, MAX_DOWNLOAD).map_err(|_| "Cannot retain the update recovery worker.")?;
    if worker.exists() {
        if storage::read(&worker, MAX_DOWNLOAD).ok().as_deref() != Some(&bytes) {
            return Err("The retained update worker differs from this app. The current app was kept.".into());
        }
    } else {
        storage::write(&worker, &bytes)?;
    }
    storage::support("signature", &worker)?;
    Ok(worker)
}

fn retire_workers(directory: &Path, keep: Option<&Path>) {
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            if keep != Some(path.as_path()) && worker_name(&path) && storage::reject_links(&path).is_ok() {
                // A running worker remains locked by Windows. A later healthy
                // registration retries cleanup without blocking this update.
                let _ = fs::remove_file(path);
            }
        }
    }
}

pub(super) fn launch(directory: &Path) -> Result<(), String> {
    let record = installation(directory)?;
    storage::support("signature", &record.worker)?;
    if let Some(pending) = load(directory)?.pending {
        let release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
        if release.layout == 2 && directory == storage::local_data()?.join("OpenAIDR Sensor/desktop-update") {
            return super::update_layout::stage(directory, &record.executable, &record.worker);
        }
    }
    spawn(&record.worker, "--update-worker")
}

pub(super) fn spawn(executable: &Path, argument: &str) -> Result<(), String> {
    let mut command = Command::new(executable);
    command.arg(argument).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    crate::hide_console(&mut command);
    command.spawn().map(|_| ()).map_err(|_| "Cannot start the automatic update worker.".into())
}

pub(super) fn app_build(executable: &Path) -> Result<Value, String> {
    storage::reject_links(executable)?;
    storage::support("signature", executable)?;
    let mut command = Command::new(executable);
    command.arg("--update-build-info").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    crate::hide_console(&mut command);
    let mut child = command.spawn().map_err(|_| "Cannot read installed app metadata.")?;
    let (status, bytes) = crate::child_output(&mut child, Duration::from_secs(30), 16 * 1024)?;
    if !status.success() { return Err("Cannot read installed app metadata.".into()); }
    let build: Value = serde_json::from_slice(&bytes).map_err(|_| "The installed app metadata is invalid.")?;
    if crate::build_order(build["version"].as_str().unwrap_or(""), &build).is_none() {
        return Err("The installed app metadata is invalid.".into());
    }
    Ok(build)
}

pub(super) fn verified_build(executable: &Path, pending: &Pending) -> Result<Option<Value>, String> {
    let build = match app_build(executable) {
        Ok(build) => build,
        Err(_) if pending.install_started => {
            // Repair only a transaction this worker began. If readable resource
            // metadata identifies another installation, preserve it.
            let resource = storage::json_file(&executable.parent().unwrap().join("build.json"))?;
            if resource.as_ref().is_some_and(|build| build != &pending.previous && build != &pending.release.build) {
                return Err("Another app build is present. Its current installation was kept.".into());
            }
            return Ok(None);
        },
        Err(error) => return Err(error),
    };
    let root = executable.parent().unwrap();
    let sensor = if root.join("runtime").exists() { root.join("runtime/openaidr.exe") }
        else { root.join("sensor/openaidr.exe") };
    storage::reject_links(&sensor)?;
    installed_builds(&build, &crate::sensor_build(&sensor), pending)
}

fn installed_builds(build: &Value, sensor_build: &Value, pending: &Pending) -> Result<Option<Value>, String> {
    let version = build["version"].as_str().ok_or("The installed app version is invalid.")?;
    let later = crate::newer_build(
        version, &pending.release.version, &build, &pending.release.build,
    );
    if version != pending.release.version && !later {
        if version != pending.previous["version"].as_str().unwrap_or("") || build != &pending.previous {
            return Err("The installed app changed during the update. Its current version was kept.".into());
        }
        return Ok(None);
    }
    if version == pending.release.version && build != &pending.release.build {
        return Err("The installed app has different metadata from its signed publication.".into());
    }
    if later && sensor_build != build {
        return Err("A newer app is installed but its sensor is incomplete. Reinstall that release to repair it.".into());
    }
    Ok((sensor_build == build).then(|| build.clone()))
}

pub(super) fn installer_idle(path: &Path) -> Result<(), String> {
    storage::reject_links(path)?;
    // Windows denies write access while an executable is mapped into a
    // running process. Do not launch a second retained installer after the
    // worker timed out or exited while the first installer kept running.
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(_) => Ok(()), // Check access only; never truncate or write the file.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(5 | 32)) => Err(storage::BUSY.into()),
        Err(_) => Err("Cannot inspect the retained Windows installer.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsis_directory_preserves_migration_and_custom_paths() {
        for (directory, expected) in [
            (r"C:\Users\Lamps\AppData\Local\OpenAIDR/app", r"/D=C:\Users\Lamps\AppData\Local\OpenAIDR\app"),
            (r"C:\Users\Lamp Smith\AppData\Local\OpenAIDR/app", r"/D=C:\Users\Lamp Smith\AppData\Local\OpenAIDR\app"),
            (r"D:\Apps\OpenAIDR's app", r"/D=D:\Apps\OpenAIDR's app"),
        ] {
            assert_eq!(nsis_directory_argument(Path::new(directory)), expected);
        }
    }

    #[test]
    fn uninstall_preserves_identity_and_releases_the_installation_path() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("updates");
        let root = scratch.path().join("installation");
        storage::support("directory", &directory).unwrap();
        storage::support("directory", &root).unwrap();
        let executable = root.join("openaidr-desktop.exe");
        fs::write(&executable, b"installed app").unwrap();
        let worker = directory.join(format!("worker-{}.exe", "a".repeat(40)));
        fs::write(&worker, b"retained worker").unwrap();
        fs::write(directory.join("installer.exe"), b"retained installer").unwrap();
        let record = Installation { executable:executable.clone(), worker };
        storage::write(&directory.join("installation.json"), &serde_json::to_vec(&record).unwrap()).unwrap();
        let identity = {
            let guard = storage::lock(&directory, "operation.lock").unwrap();
            storage::installation_id(&directory, &guard).unwrap()
        };
        let enrollment = scratch.path().join("sensor.yaml");
        fs::write(&enrollment, b"retained enrollment").unwrap();
        assert!(remove_installation(&directory, &scratch.path().join("other/openaidr-desktop.exe")).is_err());
        assert!(!directory.join("removed").exists());
        assert!(installation(&directory).is_ok());
        let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let drift = Command::new(powershell).args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", r#"
            $ErrorActionPreference = 'Stop'
            $acl = Get-Acl -LiteralPath $env:OPENAIDR_TEST_INSTALLATION
            $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($everyone, 'Read', 'Allow'))
            Set-Acl -LiteralPath $env:OPENAIDR_TEST_INSTALLATION -AclObject $acl
        "#]).env_remove("PSModulePath").env("OPENAIDR_TEST_INSTALLATION", &root).status().unwrap();
        assert!(drift.success());
        assert!(installation(&directory).is_err());
        assert!(validate_installation(&directory, &executable).is_err());
        fs::remove_file(&executable).unwrap();
        // Cleanup also remains possible when the interrupted journal itself
        // is unreadable; it never needs to execute that retained transaction.
        fs::write(directory.join(JOURNAL), b"{").unwrap();
        remove_installation(&directory, &executable).unwrap();
        assert!(directory.join("removed").exists());
        assert!(!directory.join("installation.json").exists());
        assert!(!record.worker.exists());
        assert!(!directory.join("installer.exe").exists());
        assert!(!directory.join(JOURNAL).exists());
        assert_eq!(fs::read(&enrollment).unwrap(), b"retained enrollment");
        let guard = storage::lock(&directory, "operation.lock").unwrap();
        assert_eq!(storage::installation_id(&directory, &guard).unwrap(), identity);
    }

    #[test]
    fn recovery_waits_for_running_installer_images_without_changing_files() {
        assert_eq!(installer_idle(&std::env::current_exe().unwrap()).unwrap_err(), storage::BUSY);
        let scratch = tempfile::tempdir().unwrap();
        let retained = scratch.path().join("installer.exe");
        assert!(installer_idle(&retained).is_ok());
        fs::write(&retained, b"retained installer").unwrap();
        installer_idle(&retained).unwrap();
        assert_eq!(fs::read(&retained).unwrap(), b"retained installer");
    }

    #[test]
    fn worker_cleanup_preserves_active_worker_and_retries_locked_files() {
        use std::os::windows::fs::OpenOptionsExt;
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path();
        let current = directory.join(format!("worker-{}.exe", "a".repeat(40)));
        let prior = directory.join(format!("worker-{}.exe", "b".repeat(40)));
        let unrelated = directory.join("settings.json");
        for path in [&current, &prior, &unrelated] { fs::write(path, b"retained").unwrap(); }
        let running = fs::OpenOptions::new().read(true).share_mode(0).open(&prior).unwrap();
        retire_workers(directory, Some(&current));
        assert!(prior.exists() && current.exists() && unrelated.exists());
        drop(running);
        retire_workers(directory, Some(&current));
        assert!(!prior.exists());
        assert!(current.exists() && unrelated.exists());
    }

    #[test]
    fn recovery_preserves_newer_and_unrecognized_installations() {
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let release = super::super::release::from_manifest(&fixture["manifest"], fixture["key"].as_str().unwrap()).unwrap();
        let mut previous = release.build.clone();
        previous["version"] = json!("2026.10.6+0000000");
        previous["source_commit"] = json!("0".repeat(40));
        previous["publication_timestamp"] = json!(1791338400);
        previous["published_at"] = json!("2026-10-07T02:00:00+00:00");
        let pending = Pending { release, previous:previous.clone(), reopen_window:true, install_started:true, manual:false };
        assert!(installed_builds(&previous, &previous, &pending).unwrap().is_none());
        assert_eq!(installed_builds(&pending.release.build, &pending.release.build, &pending).unwrap(), Some(pending.release.build.clone()));
        assert!(installed_builds(&pending.release.build, &Value::Null, &pending).unwrap().is_none());
        let mut later = previous.clone();
        later["publication_timestamp"] = json!(1791345600);
        later["published_at"] = json!("2026-10-07T04:00:00+00:00");
        // Folder migration must use this verified newer build for its helper
        // and retained worker, rather than the older pending release's build.
        assert_eq!(installed_builds(&later, &later, &pending).unwrap(), Some(later.clone()));
        assert!(installed_builds(&later, &Value::Null, &pending).is_err());
        previous["built_at"] = json!("changed");
        assert!(installed_builds(&previous, &previous, &pending).is_err());
        assert!(installed_builds(&Value::Null, &Value::Null, &pending).is_err());
    }
}

fn nsis_directory_argument(directory: &Path) -> String {
    // NSIS removes forward slashes instead of treating them as path separators.
    format!("/D={}", directory.display().to_string().replace('/', "\\"))
}

pub(super) fn install(directory: &Path, executable: &Path, pending: &Pending) -> Result<(), String> {
    let release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
    if !crate::newer_build(&release.version, pending.previous["version"].as_str().unwrap_or(""), &release.build, &pending.previous) {
        return Err("The retained update has no later signed publication order.".into());
    }
    let installer = directory.join("installer.exe");
    let mut file = storage::open(&installer, MAX_DOWNLOAD).map_err(|_| "The retained installer is unavailable. Reopen OpenAIDR to retry.")?;
    release.verify_file(&mut file, &key())?;
    storage::support("signature", &installer)?;
    validate_installation(directory, executable)?;
    // NSIS requires /D to be the final raw argument, even when the path has spaces.
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(&installer);
    command.args(["/S", "/UPDATE"])
        .raw_arg(nsis_directory_argument(executable.parent().unwrap()))
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    crate::hide_console(&mut command);
    let mut child = command.spawn().map_err(|_| "Cannot start the signed installer. The update was retained for retry.")?;
    wait_installer(&mut child)
}

pub(super) fn wait_installer(child: &mut std::process::Child) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    loop {
        if let Some(status) = child.try_wait().map_err(|_| "Cannot check the running installer.")? {
            if !status.success() { return Err("The signed installer did not finish. The update was retained for retry.".into()); }
            return Ok(());
        }
        if Instant::now() >= deadline {
            // Do not terminate an installer while it is replacing files.
            return Err("The signed installer is still running. The update was retained for recovery.".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn recover(directory: &Path, record: &Installation, state: &mut State) -> Result<(), String> {
    let Some(mut pending) = state.pending.clone() else { return spawn(&record.executable, "--background-update"); };
    pending.release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
    let _window = wait_lock(directory, "window.lock", Duration::from_secs(10))?;
    let _operation = storage::lock(directory, "operation.lock")?;
    installer_idle(&directory.join("installer.exe"))?;
    if verified_build(&record.executable, &pending)?.is_none() {
        state.pending.as_mut().unwrap().install_started = true;
        state.set(directory, "installing")?;
        install(directory, &record.executable, &pending)?;
        if verified_build(&record.executable, &pending)?.is_none() {
            return Err("The installed app or sensor did not match the signed update. The installer was retained for recovery.".into());
        }
    }
    state.set(directory, "restarting")?;
    spawn(&record.executable, "--finish-update")
}

pub(super) fn run() -> Result<(), String> {
    let directory = storage::private_directory()?;
    let _guard = wait_lock(&directory, "updater.lock", Duration::from_secs(30))?;
    if directory.join("removed").exists() { return Ok(()); }
    let record = installation(&directory)?;
    let mut state = load(&directory)?;
    if let Err(error) = recover(&directory, &record, &mut state) {
        if error != storage::BUSY { state.fail(&directory, error.clone()); }
        return Err(error);
    }
    Ok(())
}

pub(super) fn wait_lock(directory: &Path, name: &str, timeout: Duration) -> Result<storage::OperationLock, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match storage::lock(directory, name) {
            Ok(guard) => return Ok(guard),
            Err(error) if error == storage::BUSY && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn remove() -> Result<(), String> {
    let directory = storage::private_directory()?;
    // NSIS runs an embedded copy outside the installation, which can already
    // be missing or damaged. The private record still authorizes only its path.
    let executable = match std::env::args_os().nth(2) {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe().map_err(|_| "Cannot locate this installation.")?,
    };
    remove_installation(&directory, &executable)
}

fn remove_installation(directory: &Path, executable: &Path) -> Result<(), String> {
    let record = if directory.join("installation.json").exists() {
        // An installation's ACL may have drifted since registration. Never
        // install into that folder, but allow its owner to stop and remove the
        // private worker without depending on the app remaining executable.
        let record = installation_record(directory)?;
        if record.executable != executable { return Err("Another installation owns automatic updates.".into()); }
        Some(record)
    } else { None };
    // Keep the marker even when removal needs a retry; a scheduled worker must
    // not reinstall the app after its normal uninstaller removed it.
    storage::write(&directory.join("removed"), b"removed\n")?;
    if let Some(record) = record {
        storage::support("remove", &record.worker)?;
    }
    let _guard = storage::lock(&directory, "updater.lock")?;
    let _operation = storage::lock(&directory, "operation.lock")?;
    // Preserve the installation ID, enrollment, and settings for a reinstall.
    for name in ["installer.exe", JOURNAL, "installation.json"] {
        if directory.join(name).exists() { fs::remove_file(directory.join(name)).map_err(|_| "Cannot remove retained update files.")?; }
    }
    retire_workers(&directory, None);
    Ok(())
}
