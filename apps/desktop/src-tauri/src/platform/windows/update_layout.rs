//! The compatibility worker survives relocation of both the app and its data.

use super::{load, save, key, JOURNAL, MAX_DOWNLOAD, update_storage as storage, update_worker as worker};
use serde_json::json;
use std::{fs, path::{Path, PathBuf}, process::{Command, Stdio}, time::Duration};

fn directory() -> Result<PathBuf, String> { Ok(storage::local_data()?.join("OpenAIDR/migration")) }

pub(super) fn pending() -> Result<bool, String> {
    let path = directory()?;
    storage::reject_links(&path)?;
    Ok(path.join(JOURNAL).exists() && !path.join("complete").exists())
}

fn retained_worker(directory: &Path) -> Result<PathBuf, String> {
    let record = storage::json_file(&directory.join("installation.json"))?.ok_or("Missing migration worker.")?;
    let path = PathBuf::from(record["worker"].as_str().ok_or("Invalid migration worker.")?);
    if path.parent() != Some(directory) || !path.file_name().and_then(|s| s.to_str()).is_some_and(|s|
        s.strip_prefix("worker-").and_then(|s| s.strip_suffix(".exe"))
            .is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))) {
        return Err("Invalid migration worker location.".into());
    }
    storage::reject_links(&path)?;
    storage::support("signature", &path)?;
    Ok(path)
}

pub(super) fn launch(reopen: bool) -> Result<bool, String> {
    let recovery = directory()?;
    storage::support("identity", &recovery)?;
    let guard = worker::wait_lock(&recovery, "updater.lock", Duration::from_secs(30))?;
    // If another worker finished while this launch waited, let the caller
    // open the installed app normally instead of dropping the window request.
    if recovery.join("complete").exists() { return Ok(false); }
    let mut state = load(&recovery)?;
    let pending = state.pending.as_mut().ok_or("Missing migration transaction.")?;
    pending.release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
    if pending.release.layout != 2 { return Err("The signed release does not authorize this folder migration.".into()); }
    let executable = std::env::current_exe().map_err(|_| "Cannot locate the installed app.")?;
    let target = storage::local_data()?.join("OpenAIDR/app/openaidr-desktop.exe");
    let mut binary = retained_worker(&recovery)?;
    // A manual corrective install must replace the worker that kept retrying
    // the failed transaction. Keep the original signed release record intact.
    if executable == target {
        if let Some(build) = worker::verified_build(&target, pending)? {
            let previous = worker::app_build(&binary)?;
            if crate::newer_build(build["version"].as_str().unwrap_or(""),
                previous["version"].as_str().unwrap_or(""), &build, &previous) {
                let mut record = storage::json_file(&recovery.join("installation.json"))?
                    .ok_or("Missing migration source.")?;
                let source = PathBuf::from(record["source_executable"].as_str().ok_or("Invalid migration source.")?);
                if source != storage::local_data()?.join("OpenAIDR/openaidr-desktop.exe") && source != target {
                    return Err("Invalid migration source location.".into());
                }
                binary = worker::retain(&recovery, &target, &build)?;
                record["worker"] = json!(binary);
                storage::write(&recovery.join("installation.json"), &serde_json::to_vec(&record).unwrap())?;
            }
        }
    }
    pending.reopen_window |= reopen;
    save(&recovery, &state)?;
    drop(guard);
    worker::spawn(&binary, "--update-worker")?;
    Ok(true)
}

pub(super) fn preserve_disabled(version: &str) -> Result<bool, String> {
    let directory = directory()?;
    if !directory.join("complete").exists() { return Ok(false); }
    if load(&directory)?.latest != version {
        return Ok(false);
    }
    Ok(storage::json_file(&directory.join("sensor-migration.json"))?
        .is_some_and(|state| state["complete"] == true && state["task"]["state"] == "Disabled"))
}

fn schedule(directory: &Path, executable: &Path, previous: &Path) -> Result<(), String> {
    storage::support_input(json!({"operation":"schedule", "path":executable,
        "directory":directory, "previous_directory":previous}))
}

pub(super) fn stage(source: &Path, executable: &Path, retained: &Path) -> Result<(), String> {
    let local = storage::local_data()?;
    if executable != local.join("OpenAIDR/openaidr-desktop.exe")
        && executable != local.join("OpenAIDR/app/openaidr-desktop.exe") {
        return Err("Automatic folder migration requires the standard per-user installation.".into());
    }
    let target = directory()?;
    if local.join("OpenAIDR/data").exists() {
        return Err("Both Windows data locations exist. No installation was changed.".into());
    }
    if local.join("OpenAIDR/app").exists() && !target.join(JOURNAL).exists()
        && executable != local.join("OpenAIDR/app/openaidr-desktop.exe") {
        return Err("The new application directory already exists. Its files were kept.".into());
    }
    storage::support("directory", &target)?;
    let _lock = storage::lock(&target, "updater.lock")?;
    if target.join("complete").exists() {
        return Err("Windows folder migration is already complete. Reopen the installed app.".into());
    }
    let state = load(source)?;
    let pending = state.pending.as_ref().ok_or("Missing Windows migration release.")?;
    let release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
    if release.layout != 2 || worker::app_build(executable)? != pending.previous {
        return Err("The app changed before Windows migration. Its data was kept.".into());
    }
    let root = executable.parent().unwrap();
    let sensor = if root.join("runtime").exists() { root.join("runtime/openaidr.exe") }
        else { root.join("sensor/openaidr.exe") };
    sensor_command(&sensor, &pending.previous, true)?;
    if target.join(JOURNAL).exists() {
        let previous = load(&target)?;
        if previous.pending.as_ref().map(|p| &p.release.version) != Some(&release.version) {
            return Err("Another Windows migration is pending.".into());
        }
    }
    let mut installer = storage::open(&source.join("installer.exe"), MAX_DOWNLOAD)
        .map_err(|_| "Cannot retain the migration installer.")?;
    release.verify_file(&mut installer, &key())?;
    let binary = target.join(retained.file_name().ok_or("Invalid retained worker.")?);
    storage::write_from(&binary, &mut storage::open(retained, MAX_DOWNLOAD).map_err(|_| "Cannot retain the migration worker.")?, MAX_DOWNLOAD)?;
    storage::support("signature", &binary)?;
    storage::write_from(&target.join("installer.exe"), &mut installer, MAX_DOWNLOAD)?;
    if executable == local.join("OpenAIDR/openaidr-desktop.exe") {
        let uninstaller = executable.parent().unwrap().join("uninstall.exe");
        storage::reject_links(&uninstaller)?;
        storage::support("signature", &uninstaller)?;
        let retained = target.join("previous-uninstall.exe");
        storage::write_from(&retained, &mut storage::open(&uninstaller, MAX_DOWNLOAD)
            .map_err(|_| "Cannot retain the previous signed uninstaller.")?, MAX_DOWNLOAD)?;
        storage::support("signature", &retained)?;
    }
    storage::write(&target.join("installation.json"),
        &serde_json::to_vec(&json!({"worker":binary, "source_executable":executable})).unwrap())?;
    // Persist the full transaction before moving the recovery schedule.
    save(&target, &state)?;
    schedule(&target, &binary, source)?;
    worker::spawn(&binary, "--update-worker")
}

pub(super) fn run() -> Result<(), String> {
    let recovery = directory()?;
    storage::support("directory", &recovery)?;
    let _lock = worker::wait_lock(&recovery, "updater.lock", Duration::from_secs(30))?;
    if recovery.join("complete").exists() { return Ok(()); }
    let mut state = load(&recovery)?;
    let result = resume(&recovery, &mut state);
    if let Err(error) = &result { state.fail(&recovery, error.clone()); }
    result
}

fn resume(recovery: &Path, state: &mut super::State) -> Result<(), String> {
    let mut pending = state.pending.clone().ok_or("Missing migration transaction.")?;
    pending.release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
    if pending.release.layout != 2 { return Err("The signed release does not authorize this folder migration.".into()); }
    let local = storage::local_data()?;
    let legacy = local.join("OpenAIDR Sensor/desktop-update");
    let current = local.join("OpenAIDR/data/desktop-update");
    let target = local.join("OpenAIDR/app/openaidr-desktop.exe");
    let record = storage::json_file(&recovery.join("installation.json"))?.ok_or("Missing migration source.")?;
    let old_app = PathBuf::from(record["source_executable"].as_str().ok_or("Invalid migration source.")?);
    if old_app != local.join("OpenAIDR/openaidr-desktop.exe") && old_app != target {
        return Err("Invalid migration source location.".into());
    }
    schedule(recovery, &retained_worker(recovery)?, if legacy.exists() { &legacy } else { &current })?;
    worker::installer_idle(&recovery.join("installer.exe"))?;
    worker::installer_idle(&recovery.join("previous-uninstall.exe"))?;
    let mut guards = Vec::new();
    if legacy.exists() {
        storage::support("identity", &legacy)?;
        for name in ["updater.lock", "window.lock"] {
            guards.push(worker::wait_lock(&legacy, name, Duration::from_secs(30))?);
        }
        guards.push(storage::lock(&legacy, "operation.lock")?);
    }
    if !pending.install_started && worker::app_build(&old_app)? != pending.previous {
        return Err("The installed app changed before migration. Its data was kept.".into());
    }
    pending.install_started = true;
    state.pending = Some(pending.clone());
    state.set(recovery, "installing")?;
    if old_app != target && !recovery.join("old-app-removed").exists() {
        remove_old_app(recovery, &old_app, &pending)?;
        storage::write(&recovery.join("old-app-removed"), b"removed\n")?;
    }
    let installed = match worker::verified_build(&target, &pending)? {
        Some(build) => build,
        None => {
            storage::support("directory", target.parent().unwrap())?;
            worker::install(recovery, &target, &pending)?;
            worker::verified_build(&target, &pending)?
                .ok_or("The migrated app does not match its signed release. Recovery was retained.")?
        },
    };
    // Prevent any delayed pre-bridge worker from repairing the old install.
    if legacy.exists() { storage::write(&legacy.join("removed"), b"layout migration\n")?; }
    drop(guards);
    // All executables involved in the rename now live outside the old data.
    let sensor = target.parent().unwrap().join("runtime/openaidr.exe");
    sensor_command(&sensor, &installed, false)?;
    storage::support("directory", &current)?;
    let _updater = storage::lock(&current, "updater.lock")?;
    let _operation = storage::lock(&current, "operation.lock")?;
    let binary = worker::retain(&current, &target, &installed)?;
    storage::write(&current.join("installation.json"),
        &serde_json::to_vec(&json!({"executable":target, "worker":binary})).unwrap())?;
    state.latest = installed["version"].as_str().ok_or("Missing migrated app version.")?.into();
    state.set(&current, "restarting")?;
    if current.join("removed").exists() {
        fs::remove_file(current.join("removed")).map_err(|_| "Cannot activate migrated updates.")?;
    }
    schedule(&current, &binary, recovery)?;
    save(recovery, state)?;
    storage::write(&recovery.join("complete"), b"2\n")?;
    worker::spawn(&target, "--finish-update")
}

fn sensor_command(sensor: &Path, build: &serde_json::Value, check: bool) -> Result<(), String> {
    storage::reject_links(sensor)?;
    storage::support("signature", sensor)?;
    if crate::sensor_build(sensor) != *build {
        return Err("The migration helper differs from its signed app build.".into());
    }
    let mut command = Command::new(sensor);
    command.arg("windows-layout-migrate").env("LOCALAPPDATA", storage::local_data()?)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if check { command.arg("--check"); }
    crate::hide_console(&mut command);
    let mut child = command.spawn().map_err(|_| "Cannot start Windows data migration.")?;
    let (status, _) = crate::child_output(&mut child, Duration::from_secs(120), 65536)?;
    if !status.success() {
        return Err(if check {
            "Windows folder migration requires standard task paths, a single data directory, and no linked state folders."
        } else {
            "Windows data migration has not finished. Close coding agents and reopen OpenAIDR to retry."
        }.into());
    }
    Ok(())
}

fn remove_old_app(recovery: &Path, executable: &Path, pending: &super::Pending) -> Result<(), String> {
    let root = executable.parent().ok_or("Invalid previous installation.")?;
    storage::support("identity", root)?;
    if executable.exists() && worker::app_build(executable)? != pending.previous {
        return Err("The previous installation changed. Its files were kept.".into());
    }
    // A prior attempt may already have removed every recorded app file.
    // Replaying its uninstaller would delete a corrective install's registry
    // entry, even though that app is in the new directory.
    if !executable.exists() && !root.join("uninstall.exe").exists()
        && sensor_metadata_only(&root.join("sensor"))? {
        return preserve_sensor_metadata(root, recovery);
    }
    // The signed previous uninstaller removes only its recorded app files.
    // /UPDATE preserves data, background tasks, and shortcuts. Run its retained
    // copy so it can also remove the original uninstaller before registration
    // of the new app. _?= must be the final raw NSIS argument.
    let uninstaller = recovery.join("previous-uninstall.exe");
    storage::reject_links(&uninstaller)?;
    storage::support("signature", &uninstaller)?;
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(&uninstaller);
    command.args(["/S", "/UPDATE"]).raw_arg(format!("_?={}", root.display()))
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    crate::hide_console(&mut command);
    let mut child = command.spawn().map_err(|_| "Cannot remove the previous app. Recovery was retained.")?;
    worker::wait_installer(&mut child)?;
    preserve_sensor_metadata(root, recovery)?;
    if executable.exists() || root.join("sensor").exists() || root.join("uninstall.exe").exists() {
        return Err("The previous app still has locked files. Close coding agents and retry OpenAIDR.".into());
    }
    Ok(())
}

fn preserve_sensor_metadata(root: &Path, recovery: &Path) -> Result<(), String> {
    let sensor = root.join("sensor");
    if !sensor_metadata_only(&sensor)? {
        return Err("The previous app contains files that could not be removed. Its files were kept.".into());
    }
    if !sensor.exists() { return Ok(()); }
    // NSIS removes only files recorded by its own version. Metadata from
    // older upgrades can remain without any executable or locked file.
    let backup = recovery.join("previous-sensor-metadata");
    storage::reject_links(&backup)?;
    if backup.exists() { return Err("A previous sensor metadata backup already exists. Its files were kept.".into()); }
    fs::rename(&sensor, &backup).map_err(|_| "The previous app metadata could not be preserved. Close coding agents and retry OpenAIDR.".into())
}

fn sensor_metadata_only(sensor: &Path) -> Result<bool, String> {
    storage::reject_links(sensor)?;
    if !sensor.exists() { return Ok(true); }
    let remaining = "The previous app contains files that could not be removed. Its files were kept.";
    let mut directories = vec![sensor.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| remaining)? {
            let path = entry.map_err(|_| remaining)?.path();
            storage::reject_links(&path)?;
            let relative = path.strip_prefix(sensor).map_err(|_| remaining)?;
            let parts: Vec<_> = relative.iter().collect();
            if parts[0] != "_internal" || (parts.len() > 1 && !parts[1].to_str().is_some_and(|name|
                name.strip_prefix("openaidr-").and_then(|name| name.strip_suffix(".dist-info"))
                    .is_some_and(|version| !version.is_empty()))) {
                return Ok(false);
            }
            let metadata = fs::metadata(&path).map_err(|_| remaining)?;
            if metadata.is_dir() {
                directories.push(path);
            } else if !metadata.is_file() || parts.len() < 3 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_package_metadata_is_preserved_and_recovery_is_repeatable() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("app");
        let recovery = scratch.path().join("migration");
        fs::create_dir(&recovery).unwrap();
        storage::support("directory", &root).unwrap();
        for version in ["2026.10.14+d019dda", "2026.10.19+73302c5"] {
            let directory = root.join(format!("sensor/_internal/openaidr-{version}.dist-info"));
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("METADATA"), version).unwrap();
            fs::write(directory.join("RECORD"), b"retained package metadata").unwrap();
        }
        let enrollment = root.join("sensor.yaml");
        fs::write(&enrollment, b"retained enrollment").unwrap();
        let corrected = root.join("app/openaidr-desktop.exe");
        fs::create_dir(corrected.parent().unwrap()).unwrap();
        fs::write(&corrected, b"corrective installation").unwrap();
        // If cleanup replays the old uninstaller, this invalid file makes the
        // test fail before it can remove a corrective install's registration.
        fs::write(recovery.join("previous-uninstall.exe"), b"must not run").unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let release = super::super::release::from_manifest(&fixture["manifest"], fixture["key"].as_str().unwrap()).unwrap();
        let pending = super::super::Pending { previous:release.build.clone(), release,
            reopen_window:false, install_started:true, manual:false };
        remove_old_app(&recovery, &root.join("openaidr-desktop.exe"), &pending).unwrap();
        preserve_sensor_metadata(&root, &recovery).unwrap();
        assert!(!root.join("sensor").exists());
        for version in ["2026.10.14+d019dda", "2026.10.19+73302c5"] {
            let directory = recovery.join(format!("previous-sensor-metadata/_internal/openaidr-{version}.dist-info"));
            assert_eq!(fs::read(directory.join("METADATA")).unwrap(), version.as_bytes());
            assert_eq!(fs::read(directory.join("RECORD")).unwrap(), b"retained package metadata");
        }
        assert_eq!(fs::read(enrollment).unwrap(), b"retained enrollment");
        assert_eq!(fs::read(corrected).unwrap(), b"corrective installation");
    }

    #[test]
    fn remaining_runtime_and_conflicting_backups_are_never_moved() {
        for name in ["openaidr.exe", "_internal/python3.dll", "_internal/other.dist-info/METADATA"] {
            let scratch = tempfile::tempdir().unwrap();
            let path = scratch.path().join("sensor").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"keep original").unwrap();
            let recovery = scratch.path().join("migration");
            fs::create_dir(&recovery).unwrap();
            assert!(preserve_sensor_metadata(scratch.path(), &recovery).is_err());
            assert_eq!(fs::read(path).unwrap(), b"keep original");
            assert!(!recovery.join("previous-sensor-metadata").exists());
        }
        let scratch = tempfile::tempdir().unwrap();
        fs::create_dir(scratch.path().join("sensor")).unwrap();
        let recovery = scratch.path().join("migration");
        let backup = recovery.join("previous-sensor-metadata");
        fs::create_dir_all(&backup).unwrap();
        fs::write(backup.join("retained"), b"previous backup").unwrap();
        assert!(preserve_sensor_metadata(scratch.path(), &recovery).is_err());
        assert!(scratch.path().join("sensor").exists());
        assert_eq!(fs::read(backup.join("retained")).unwrap(), b"previous backup");
    }

    #[test]
    fn metadata_junction_keeps_the_source_and_target_untouched() {
        let scratch = tempfile::tempdir().unwrap();
        let internal = scratch.path().join("sensor").join("_internal");
        let outside = scratch.path().join("outside");
        let recovery = scratch.path().join("migration");
        fs::create_dir_all(&internal).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir(&recovery).unwrap();
        fs::write(outside.join("METADATA"), b"unrelated data").unwrap();
        let junction = internal.join("openaidr-2026.10.14+d019dda.dist-info");
        let status = Command::new("cmd").args(["/c", "mklink", "/J"])
            .arg(&junction).arg(&outside).stdout(Stdio::null()).status().unwrap();
        assert!(status.success());
        assert!(preserve_sensor_metadata(scratch.path(), &recovery).is_err());
        assert!(junction.exists());
        assert_eq!(fs::read(outside.join("METADATA")).unwrap(), b"unrelated data");
        assert!(!recovery.join("previous-sensor-metadata").exists());
    }

    #[test]
    fn edited_journal_cannot_authorize_a_folder_migration() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        // Use the fixture's key to recover the authoritative release before
        // checking the layout. The production key rejects this test artifact.
        let mut release = super::super::release::from_manifest(
            &fixture["manifest"], fixture["key"].as_str().unwrap()).unwrap();
        release.layout = 2;
        assert_eq!(release.revalidate(fixture["key"].as_str().unwrap()).unwrap().layout, 0);
        let scratch = tempfile::tempdir().unwrap();
        let mut state = super::super::State {
            pending: Some(super::super::Pending {
                previous: release.build.clone(), release, reopen_window: false,
                install_started: true, manual: false,
            }),
            ..Default::default()
        };
        assert!(resume(scratch.path(), &mut state).is_err());
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
    }
}
