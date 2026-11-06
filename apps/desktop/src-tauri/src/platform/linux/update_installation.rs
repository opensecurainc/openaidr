//! Verified AppImage setup and per-user desktop/timer registration.

use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct SetupStatus(Mutex<Option<Value>>);

pub(super) fn needed() -> bool {
    cfg!(target_arch = "x86_64") && !cfg!(debug_assertions)
        && current_build()["published_at"].is_string()
        && std::env::var_os("APPIMAGE").is_some() && !managed_location()
}

pub(super) fn status(app: &AppHandle) -> Result<Option<Value>, String> {
    app.state::<SetupStatus>().0.lock().map(|state| state.clone())
        .map_err(|_| "Cannot read app setup status.".into())
}

pub(super) fn start_setup(app: &AppHandle) -> Result<Value, String> {
    let setup = app.state::<SetupStatus>();
    let mut state = setup.0.lock().map_err(|_| "Cannot read app setup status.")?;
    if let Some(value) = state.as_ref().filter(|value| value["state"] == "installing") {
        return Ok(value.clone());
    }
    let value = json!({"state":"installing", "latest":current_build()["version"], "setup":true});
    *state = Some(value.clone());
    let app = app.clone();
    std::thread::spawn(move || {
        let result = (|| {
            // Setup and enrollment share the sensor. Finish any current sensor
            // request before copying the app or handing off its sensor runtime.
            let gate = app.state::<Mutex<()>>();
            let _gate = gate.lock().map_err(|_| "Cannot start app setup.")?;
            let directory = storage::directory()?;
            if !installed_is_current(&directory, &current_build(), &key())? {
                bootstrap()?;
            }
            remember_session(&directory)?;
            reopen(&directory)
        })();
        match result {
            Ok(()) => app.exit(0),
            Err(error) => {
                if let Ok(mut state) = app.state::<SetupStatus>().0.lock() {
                    *state = Some(json!({"state":"error", "latest":current_build()["version"], "setup":true,
                        "error":format!("{error} Check updates to try setup again.")}));
                }
            },
        }
    });
    Ok(value)
}

fn installed_is_current(directory: &Path, build: &Value, public_key: &str) -> Result<bool, String> {
    let state = load(directory)?;
    if !directory.join(RECORD).exists() || state.state.is_empty() { return Ok(false); }
    let installed = record_with_key(directory, public_key)?;
    let repair = || format!("The installed AppImage failed verification. Restore the signed AppImage for {} at {}, then reopen this download. Enrollment and settings were kept.",
        installed.version, directory.join(IMAGE).display());
    if let Some(pending) = state.pending {
        let next = pending.release.revalidate(public_key).map_err(str::to_owned)?;
        let previous = pending.previous.revalidate(public_key).map_err(str::to_owned)?;
        if !crate::newer_build(&next.version, &previous.version, &next.build, &previous.build) {
            return Err("The pending AppImage has no later signed publication order.".into());
        }
        // A pending update owns replacement. Open either verified side of its
        // rename so the managed worker can resume, even from an older download.
        return if verified_image(&directory.join(IMAGE), &next, public_key).is_ok()
            || verified_image(&directory.join(IMAGE), &previous, public_key).is_ok() {
            Ok(true)
        } else { Err(repair()) };
    }
    verified_image(&directory.join(IMAGE), &installed, public_key).map_err(|_| repair())?;
    // Reopening an old download must neither downgrade the installed app nor
    // re-enable checks that the user disabled in the installed copy.
    Ok(!crate::newer_build(build["version"].as_str().unwrap_or(""), &installed.version, build, &installed.build))
}

const MARKER: &str = "# OpenAIDR AppImage updates\n";
const SESSION: &[&str] = &["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"];

fn config_home() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|path| path.is_absolute()) {
        return Ok(path);
    }
    std::env::var_os("HOME").map(PathBuf::from).filter(|path| path.is_absolute())
        .map(|path| path.join(".config")).ok_or("Cannot locate the user configuration directory.".into())
}

fn text_path(path: &Path) -> Result<&str, String> {
    let text = path.to_str().ok_or("AppImage installation requires a Unicode path.")?;
    if text.chars().any(char::is_control) { return Err("Installation paths cannot contain control characters.".into()); }
    Ok(text)
}

fn unit_quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%"))
}

fn desktop_quote(text: &str) -> String {
    // Desktop-entry string escaping is applied before Exec argument escaping.
    let escaped: String = text.chars().flat_map(|c| {
        if matches!(c, '\\' | '"' | '`' | '$') { vec!['\\', c] } else { vec![c] }
    }).collect();
    format!("\"{}\"", escaped.replace('\\', "\\\\").replace('%', "%%"))
}

fn command(mut command: Command) -> Result<(), String> {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "Cannot start the user service manager.")?;
    let (status, _) = crate::child_output(&mut child, Duration::from_secs(30), 64 * 1024)?;
    if !status.success() { return Err("The user service manager could not configure automatic updates.".into()); }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/systemctl");
    child.arg("--user").args(args);
    command(child)
}

pub(super) fn start() -> Result<(), String> {
    // Keep the worker in its own unit when the window exits for replacement.
    systemctl(&["start", "--no-block", "openaidr-update.service"])
}

fn owned_file(path: &Path) -> Result<(), String> {
    storage::reject_links(path)?;
    match storage::read(path, 64 * 1024) {
        Ok(bytes) if bytes.starts_with(MARKER.as_bytes()) => Ok(()),
        Ok(_) => Err("An existing desktop entry or update service belongs to another installation.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Cannot inspect the existing desktop entry or update service.".into()),
    }
}

fn registration(directory: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let units = config_home()?.join("systemd/user");
    let image = directory.join(IMAGE);
    let path = text_path(&image)?;
    let mut environment = String::from("Environment=APPIMAGE_EXTRACT_AND_RUN=1\n");
    for (name, value) in [("XDG_DATA_HOME", storage::data_home()?), ("XDG_CONFIG_HOME", config_home()?)] {
        environment.push_str(&format!("Environment={}\n", unit_quote(&format!("{name}={}", text_path(&value)?))));
    }
    let service = format!("{MARKER}[Unit]\nDescription=OpenAIDR automatic updates\n\n[Service]\nType=oneshot\n{environment}ExecStart={} --background-update\nTimeoutStartSec=20min\nRestart=on-failure\nRestartSec=5min\n",
        unit_quote(path));
    let timer = format!("{MARKER}[Unit]\nDescription=Check OpenAIDR updates\n\n[Timer]\nOnStartupSec=2min\nOnUnitInactiveSec=3h\nUnit=openaidr-update.service\n\n[Install]\nWantedBy=timers.target\n");
    let desktop = format!("{MARKER}[Desktop Entry]\nType=Application\nName=OpenAIDR\nExec=/usr/bin/env APPIMAGE_EXTRACT_AND_RUN=1 {}\nTerminal=false\nCategories=Utility;\n", desktop_quote(path));
    Ok(vec![(units.join("openaidr-update.service"), service), (units.join("openaidr-update.timer"), timer),
        (storage::data_home()?.join("applications/OpenAIDR.desktop"), desktop)])
}

fn register(directory: &Path) -> Result<(), String> {
    let files = registration(directory)?;
    for (path, _) in &files { owned_file(path)?; }
    // Check the user manager before changing launchers. A system-managed DEB
    // remains untouched, including when the manager is unavailable.
    systemctl(&["show-environment"])?;
    for (path, text) in files {
        let parent = path.parent().unwrap();
        storage::reject_links(parent)?;
        fs::create_dir_all(parent).map_err(|_| "Cannot create the user desktop or service directory.")?;
        let info = fs::metadata(parent).map_err(|_| "Cannot inspect the user desktop or service directory.")?;
        if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o022 != 0 {
            return Err("Desktop entries and user services must belong to this account.".into());
        }
        storage::write(&path, text.as_bytes(), false)?;
    }
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", "openaidr-update.timer"])
}

pub(super) fn remember_session(directory: &Path) -> Result<(), String> {
    let values: serde_json::Map<String, Value> = SESSION.iter().filter_map(|name| {
        std::env::var(name).ok().filter(|value| value.len() <= 8192 && !value.chars().any(char::is_control))
            .map(|value| ((*name).into(), json!(value)))
    }).collect();
    storage::write(&directory.join("window-session.json"), &serde_json::to_vec(&values).unwrap(), false)
}

pub(super) fn reopen(directory: &Path) -> Result<(), String> {
    match storage::lock(directory, "window.lock") {
        Ok(_) => {},
        Err(error) if error == storage::BUSY => return Ok(()),
        Err(error) => return Err(error),
    }
    let session = storage::json_file(&directory.join("window-session.json"))?.unwrap_or(json!({}));
    // Start a separate user unit so completion of the update service cannot
    // terminate the window it reopens.
    let mut launch = Command::new("/usr/bin/systemd-run");
    launch.args(["--user", "--collect", "--quiet", "--property=Type=exec"])
        .arg(format!("--unit=openaidr-desktop-{}-{}", timestamp(), std::process::id()));
    for name in SESSION {
        if let Some(value) = session[name].as_str().filter(|value| value.len() <= 8192 && !value.chars().any(char::is_control)) {
            launch.arg(format!("--setenv={name}={value}"));
        }
    }
    for (name, value) in [("XDG_DATA_HOME", storage::data_home()?), ("XDG_CONFIG_HOME", config_home()?)] {
        launch.arg(format!("--setenv={name}={}", text_path(&value)?));
    }
    launch.arg("--setenv=APPIMAGE_EXTRACT_AND_RUN=1").arg(directory.join(IMAGE));
    command(launch)?;
    wait_for_window(directory, Duration::from_secs(60), || std::thread::sleep(Duration::from_millis(100)))
}

fn wait_for_window(directory: &Path, timeout: Duration, mut pause: impl FnMut()) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match storage::lock(directory, "window.lock") {
            Err(error) if error == storage::BUSY => return Ok(()),
            Err(error) => return Err(error),
            Ok(_) if Instant::now() >= deadline => return Err("The updated window did not start. Its restart will be retried.".into()),
            Ok(_) => {},
        }
        // The window must acquire this lock during startup. Drop the probe's
        // temporary guard before waiting so startup does not see a duplicate.
        pause();
    }
}

fn install_image(directory: &Path, release: &release::Release, file: &mut impl std::io::Read, public_key: &str) -> Result<State, String> {
    let mut state = load(directory)?;
    if let Some(pending) = &state.pending {
        let next = pending.release.revalidate(public_key).map_err(str::to_owned)?;
        if next.build != release.build || next.sha256 != release.sha256 {
            return Err("Finish the pending AppImage update before installing a different release.".into());
        }
    } else if directory.join(RECORD).exists() {
        let existing = record_with_key(directory, public_key)?;
        verified_image(&directory.join(IMAGE), &existing, public_key)?;
        if release.version == existing.version {
            if release.build != existing.build || release.sha256 != existing.sha256 {
                return Err("This release identity is already installed with different signed bytes.".into());
            }
            return Ok(state);
        }
        if !crate::newer_build(&release.version, &existing.version, &release.build, &existing.build) {
            return Err("A newer AppImage is already installed. Its installation was kept.".into());
        }
        state.pending = Some(Pending { release:release.clone(), previous:existing, reopen_window:false, manual:false });
    } else {
        if directory.join(IMAGE).exists() && verified_image(&directory.join(IMAGE), release, public_key).is_err() {
            return Err("An unrecognized AppImage already occupies the installation path.".into());
        }
        storage::write_from(&directory.join(IMAGE), file, MAX_DOWNLOAD, true)?;
        save_record(directory, release)?;
        return Ok(state);
    }
    storage::write_from(&candidate_path(directory, release), file, MAX_DOWNLOAD, true)?;
    state.set(directory, "installing")?;
    replace_image(directory, state.pending.as_ref().unwrap(), public_key)?;
    Ok(state)
}

fn verified_download(source: &Path, build: &Value, public_key: &str,
    download: impl Fn(&str) -> Result<Vec<u8>, String>) -> Result<(release::Release, fs::File), String> {
    storage::reject_links(source)?;
    let parent = source.parent().ok_or("Cannot locate the AppImage download.")?;
    let version = build["version"].as_str().ok_or("The AppImage build identity is missing.")?;
    if crate::build_order(version, build).is_none() { return Err("The AppImage build identity is invalid.".into()); }
    let prefix = format!("{}/{version}/linux/", crate::platform::RELEASE_PREFIX);
    let read = |path: PathBuf, filename: &str| match storage::read(&path, 64 * 1024) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => download(&format!("{prefix}{filename}")),
        Err(_) => Err("Cannot read the AppImage verification files safely.".into()),
    };
    let metadata = read(parent.join("appimage.json"), "appimage.json")?;
    let metadata_signature = read(parent.join("appimage.json.sig"), "appimage.json.sig")?;
    let signature = read(PathBuf::from(format!("{}.sig", text_path(source)?)), &format!("OpenAIDR_{version}_amd64.AppImage.sig"))?;
    release::verify_signature(&metadata, std::str::from_utf8(&metadata_signature).map_err(|_| "Invalid metadata signature.")?.trim(), public_key).map_err(str::to_owned)?;
    let info: Value = serde_json::from_slice(&metadata).map_err(|_| "Invalid AppImage metadata.")?;
    let release = release::from_manifest(&json!({"version":info["version"],"pub_date":info["build"]["published_at"],
        "platforms": {release::TARGET: {
            "url":format!("{}/{}/linux/{}", crate::platform::RELEASE_PREFIX, info["version"].as_str().unwrap_or(""), info["filename"].as_str().unwrap_or("")),
            "metadata":STANDARD.encode(&metadata),
            "metadata_signature":std::str::from_utf8(&metadata_signature).map_err(|_| "Invalid metadata signature.")?.trim(),
            "signature":std::str::from_utf8(&signature).map_err(|_| "Invalid AppImage signature.")?.trim(),
        }}}), public_key).map_err(str::to_owned)?;
    if release.build != *build { return Err("The download differs from the running AppImage.".into()); }
    let bytes = verified_image(source, &release, public_key)?;
    Ok((release, bytes))
}

pub(super) fn bootstrap() -> Result<(), String> {
    if !cfg!(target_arch = "x86_64") || cfg!(debug_assertions) { return Err("Install the signed Linux x64 release AppImage.".into()); }
    let source = std::env::var_os("APPIMAGE").map(PathBuf::from).ok_or("Open the signed AppImage to install it.")?;
    let (release, mut file) = verified_download(&source, &current_build(), &key(), |url|
        tauri::async_runtime::block_on(fetch(url, 64 * 1024, Duration::from_secs(30), |_, _| {})))?;
    let directory = storage::directory()?;
    let _guard = storage::lock(&directory, "updater.lock")?;
    let _window = storage::lock(&directory, "window.lock")?;
    let _operation = storage::lock(&directory, "operation.lock")?;
    for (path, _) in registration(&directory)? { owned_file(&path)?; }
    systemctl(&["show-environment"])?;
    storage::installation_id(&directory, &_operation)?;
    let mut state = install_image(&directory, &release, &mut file, &key())?;
    remember_session(&directory)?;
    drop(_operation);
    run_image(&directory.join(IMAGE), "--update-sensor", Duration::from_secs(300))?;
    register(&directory)?;
    if directory.join("disabled").exists() { fs::remove_file(directory.join("disabled")).map_err(|_| "Cannot enable automatic updates.")?; }
    state.pending = None;
    state.latest = release.version.clone();
    state.set(&directory, "idle")?;
    cleanup(&directory);
    // Existing enrollment, sensor configuration, hooks, and system DEB files
    // are preserved. The installed app uses the same sensor staging path.
    println!("Installed OpenAIDR {} with automatic updates at {}", release.version, directory.join(IMAGE).display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_launch_verifies_online_or_offline_downloads_before_installation() {
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let key = fixture["key"].as_str().unwrap();
        let release = release::from_manifest(&fixture["manifest"], key).unwrap();
        let bytes = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        for offline in [false, true] {
            let scratch = tempfile::tempdir().unwrap();
            let source = scratch.path().join(&release.filename);
            fs::write(&source, &bytes).unwrap();
            let files = [
                ("appimage.json".to_owned(), STANDARD.decode(&release.metadata).unwrap()),
                ("appimage.json.sig".to_owned(), release.metadata_signature.as_bytes().to_vec()),
                (format!("{}.sig", release.filename), release.signature.as_bytes().to_vec()),
            ];
            if offline {
                for (name, value) in &files { fs::write(scratch.path().join(name), value).unwrap(); }
            }
            let download = |url: &str| {
                assert!(!offline, "Offline setup must use the retained verification files");
                let prefix = format!("{}/{}/linux/", crate::platform::RELEASE_PREFIX, release.version);
                let name = url.strip_prefix(&prefix).expect("Only the running release's official location is allowed");
                Ok(files.iter().find(|(file, _)| file == name).unwrap().1.clone())
            };
            let (verified, mut image) = verified_download(&source, &release.build, key, download).unwrap();
            assert_eq!(verified.build, release.build);
            let mut actual = Vec::new();
            std::io::Read::read_to_end(&mut image, &mut actual).unwrap();
            assert_eq!(actual, bytes);
            let mut changed = bytes.clone();
            changed[0] ^= 1;
            fs::write(&source, changed).unwrap();
            assert!(verified_download(&source, &release.build, key, download).is_err());
            fs::write(&source, &bytes).unwrap();
            let mut wrong_build = release.build.clone();
            wrong_build["built_at"] = json!("2026-10-01T00:00:00Z");
            assert!(verified_download(&source, &wrong_build, key, download).is_err());
            fs::write(scratch.path().join("appimage.json.sig"), b"tampered").unwrap();
            assert!(verified_download(&source, &release.build, key, download).is_err());
            fs::remove_file(scratch.path().join("appimage.json.sig")).unwrap();
            std::os::unix::fs::symlink(&source, scratch.path().join("appimage.json.sig")).unwrap();
            assert!(verified_download(&source, &release.build, key, download).is_err());
        }
        let scratch = tempfile::tempdir().unwrap();
        let source = scratch.path().join(&release.filename);
        fs::write(&source, &bytes).unwrap();
        assert!(verified_download(&source, &release.build, key, |_| Err("offline".into())).is_err());
        assert!(!scratch.path().join(RECORD).exists());
    }

    #[test]
    fn reopening_downloads_keeps_newer_installs_and_disabled_checks() {
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let key = fixture["key"].as_str().unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let bytes = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop");
        storage::private_directory(&directory).unwrap();
        assert!(!installed_is_current(&directory, &previous.build, key).unwrap());
        install_image(&directory, &next, &mut bytes.as_slice(), key).unwrap();
        assert!(!installed_is_current(&directory, &next.build, key).unwrap(), "Incomplete setup must finish registration");
        State::default().set(&directory, "idle").unwrap();
        storage::write(&directory.join("disabled"), b"disabled\n", false).unwrap();
        for build in [&previous.build, &next.build] {
            assert!(installed_is_current(&directory, build, key).unwrap());
            assert!(directory.join("disabled").exists());
            assert_eq!(fs::read(directory.join(IMAGE)).unwrap(), bytes);
        }
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        storage::write(&directory.join(IMAGE), &changed, true).unwrap();
        let error = installed_is_current(&directory, &next.build, key).unwrap_err();
        assert!(error.contains("Restore the signed AppImage"));
        assert!(error.contains(&next.version));
        assert!(error.contains(directory.join(IMAGE).to_str().unwrap()));
    }

    #[test]
    fn older_download_reopens_either_verified_side_of_a_pending_update() {
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let key = fixture["key"].as_str().unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let before = STANDARD.decode(fixture["previous"]["installer"].as_str().unwrap()).unwrap();
        let after = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop");
        storage::private_directory(&directory).unwrap();
        install_image(&directory, &previous, &mut before.as_slice(), key).unwrap();
        let mut state = State { pending:Some(Pending {
            release:next, previous:previous.clone(), reopen_window:true, manual:false,
        }), ..State::default() };
        state.set(&directory, "installing").unwrap();
        for image in [&before, &after] {
            storage::write(&directory.join(IMAGE), image, true).unwrap();
            assert!(installed_is_current(&directory, &previous.build, key).unwrap());
            assert!(load(&directory).unwrap().pending.is_some());
            assert_eq!(fs::read(directory.join(IMAGE)).unwrap(), *image);
        }
        storage::write(&directory.join(IMAGE), b"damaged", true).unwrap();
        assert!(installed_is_current(&directory, &previous.build, key).unwrap_err().contains("Restore the signed AppImage"));
    }

    #[test]
    fn reopening_releases_the_probe_lock_while_waiting_for_window_startup() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop");
        let mut window = None;
        wait_for_window(&directory, Duration::from_secs(5), || {
            window = Some(storage::lock(&directory, "window.lock")
                .expect("The window must be able to acquire its startup lock between probes."));
        }).unwrap();
        assert!(window.is_some());
        drop(window);
        assert!(wait_for_window(&directory, Duration::ZERO, || panic!("Expired wait must not pause."))
            .unwrap_err().contains("did not start"));
        fs::remove_file(directory.join("window.lock")).unwrap();
        fs::create_dir(directory.join("window.lock")).unwrap();
        assert!(wait_for_window(&directory, Duration::from_secs(5), || panic!("Unsafe lock must not pause.")).is_err());
    }

    #[test]
    fn native_service_manager_accepts_registration_with_quoted_paths() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("installation with spaces $cash %n");
        storage::private_directory(&directory).unwrap();
        storage::write(&directory.join(IMAGE), b"#!/bin/sh\nexit 0\n", true).unwrap();
        let mut verify = Command::new("/usr/bin/systemd-analyze");
        verify.args(["--user", "verify"]).env("XDG_RUNTIME_DIR", &directory);
        for (path, text) in registration(&directory).unwrap().into_iter().take(2) {
            let target = directory.join(path.file_name().unwrap());
            fs::write(&target, text).unwrap();
            verify.arg(target);
        }
        let result = verify.output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    }

    #[test]
    fn manual_installation_retries_an_interrupted_replacement_without_losing_identity() {
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let key = fixture["key"].as_str().unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let before = STANDARD.decode(fixture["previous"]["installer"].as_str().unwrap()).unwrap();
        let after = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        for interrupted in [false, true] {
            let scratch = tempfile::tempdir().unwrap();
            let directory = scratch.path().join("desktop");
            let guard = storage::lock(&directory, "operation.lock").unwrap();
            let id = storage::installation_id(&directory, &guard).unwrap();
            install_image(&directory, &previous, &mut before.as_slice(), key).unwrap();
            if interrupted {
                let mut state = State { pending:Some(Pending {
                    release:next.clone(), previous:previous.clone(), reopen_window:false, manual:false,
                }), ..State::default() };
                state.set(&directory, "installing").unwrap();
                // The replacement succeeded but the installation record still names A.
                storage::write(&directory.join(IMAGE), &after, true).unwrap();
                assert!(install_image(&directory, &previous, &mut before.as_slice(), key).is_err());
            }
            let pending = install_image(&directory, &next, &mut after.as_slice(), key).unwrap();
            assert!(pending.pending.is_some());
            install_image(&directory, &next, &mut after.as_slice(), key).unwrap();
            assert_eq!(record_with_key(&directory, key).unwrap().build, next.build);
            assert_eq!(fs::read(directory.join(IMAGE)).unwrap(), after);
            assert_eq!(storage::installation_id(&directory, &guard).unwrap(), id);
            let retained = directory.join("settings.json");
            fs::write(&retained, b"keep settings").unwrap();
            cleanup(&directory);
            assert!(!candidate_path(&directory, &next).exists());
            assert!(!directory.join("previous.AppImage").exists());
            assert_eq!(fs::read(retained).unwrap(), b"keep settings");
        }
    }
}

pub(super) fn disable() -> Result<(), String> {
    let directory = storage::directory()?;
    if !managed_location() { return Err("Run the installed AppImage with --disable-updates.".into()); }
    let _guard = storage::lock(&directory, "updater.lock")?;
    for (path, _) in registration(&directory)?.into_iter().take(2) { owned_file(&path)?; }
    storage::write(&directory.join("disabled"), b"disabled\n", false)?;
    systemctl(&["disable", "--now", "openaidr-update.timer"])?;
    systemctl(&["stop", "openaidr-update.service"])?;
    println!("Automatic updates are disabled. OpenAIDR, enrollment, settings, and installation identity were kept.");
    Ok(())
}
