//! Native macOS updates. The webview cannot choose endpoints, paths, or keys.

use serde_json::Value;
use tauri::{AppHandle, Config};

use super::Mode;

pub use super::manual_update::ManualUpdate;

pub async fn manual(app: &AppHandle, version: Option<String>) -> Result<Value, String> {
    if !enabled(app.config()) {
        return Ok(serde_json::json!({"state":"unavailable", "latest":"",
            "error":"In-app updates are not configured for this build."}));
    }
    macos::manual(app, version).await
}

pub fn cancel(app: &AppHandle) -> Result<Value, String> {
    macos::cancel(app)
}

pub fn enabled(config: &Config) -> bool {
    !cfg!(debug_assertions)
        && config
            .plugins
            .0
            .get("updater")
            .and_then(|v| v.get("pubkey"))
            .and_then(Value::as_str)
            .is_some_and(|key| !key.trim().is_empty())
}

pub struct OperationLock {
    _file: std::fs::File,
}

pub fn removal_supported() -> bool {
    return macos::removal_user_supported(unsafe { libc::geteuid() });
}

pub fn removal_status(app: &AppHandle) -> Option<Value> {
    if let Ok(directory) = macos::directory(app) {
        let path = directory.join("desktop-removal.json");
        if path.exists() {
            return Some(read_removal_status(&path));
        }
    }
    None
}

fn read_removal_status(path: &std::path::Path) -> Value {
    let saved = std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if let Some(saved) = saved.filter(|saved| {
        matches!(saved["state"].as_str(), Some("pending" | "complete"))
            && saved["errors"].as_array().is_some_and(|errors| errors.iter().all(Value::is_string))
            && saved["preferences"].as_object().is_some_and(|preferences| {
                preferences.len() == 2 && ["hooks", "telemetry"].iter().all(|section| {
                    preferences.get(*section).and_then(Value::as_array).is_some_and(|agents| {
                        agents.iter().all(|agent| matches!(agent.as_str(), Some("codex" | "claude")))
                    })
                })
            })
    }) {
        return serde_json::json!({"state":saved["state"], "errors":saved["errors"], "retained_data":saved["retained_data"],
            "data_deletion_started":saved["data_deletion_started"], "data_deleted":saved["data_deleted"]});
    }
    serde_json::json!({"state":"pending", "errors":["Cannot read the removal record. Retry removal to recover it before setting up again."]})
}

pub fn removal_lock(app: &AppHandle) -> Result<OperationLock, String> {
    return macos::removal_lock_for_user(unsafe { libc::geteuid() }, || macos::directory(app));
}

pub fn prepare_removal(app: &AppHandle) -> Result<(), String> {
    return macos::prepare_removal(app);
}

pub fn resume_removal(app: &AppHandle) -> Result<(), String> {
    return macos::resume_removal(app);
}

// The caller holds both removal and operation locks while moving the bundle.
pub fn validate_trash_app(app: &AppHandle) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|_| "Cannot locate OpenAIDR's app bundle.")?;
    macos::removed_bundle(&executable, &app.config().identifier, &removal_status(app).unwrap_or(Value::Null)).map(|_| ())
}

pub fn trash_app(app: &AppHandle) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|_| "Cannot locate OpenAIDR. Quit and move the app to Trash in Finder.")?;
    let removal = removal_status(app).unwrap_or(Value::Null);
    macos::trash_removed_bundle(&executable, &app.config().identifier, &removal).map(|_| ())
}

pub fn operation_lock(app: &AppHandle) -> Result<OperationLock, String> {
    return macos::lock(&macos::directory(app)?);
}

pub fn status(app: &AppHandle) -> Option<Value> {
    if !enabled(app.config()) {
        return None;
    }
    return macos::directory(app)
        .ok()
        .map(|path| macos::load(&path).public());
}

pub fn read_status(app: &AppHandle) -> Result<Option<Value>, String> {
    if !enabled(app.config()) {
        return Ok(None);
    }
    let directory = macos::directory(app)?;
    if directory.join("desktop-removal.json").exists() {
        return Ok(None);
    }
    macos::read_status(&directory).map(Some)
}

pub fn restart_after_update(app: &AppHandle) -> bool {
    if enabled(app.config()) {
        return macos::restart_after_update(app);
    }
    false
}

pub fn initialize(app: &AppHandle, mode: Mode) {
    if mode == Mode::Window && removal_supported() {
        // Failed validation keeps the removal barrier and its manual recovery UI.
        let _ = macos::directory(app).and_then(|directory| macos::clear_deleted_removal(&directory, mode));
    }
    if enabled(app.config()) {
        macos::initialize(app.clone(), mode);
        return;
    }
    if mode.headless() {
        app.exit(0);
    }
}

mod macos {
    use super::*;
    use super::super::manual_update::{Intent, ManualTask};
    use crate::platform::updater::rollout::{valid_installation_id, Policy};
    use plist::Dictionary;
    use semver::Version;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{ffi::OsStrExt, fs::DirBuilderExt, fs::MetadataExt, fs::OpenOptionsExt},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use tauri::Manager;
    use tauri_plugin_updater::{Update, UpdaterExt};

    const ENDPOINT: &str = crate::platform::RELEASE_FEED;
    const INSTALLATION_ID: &str = "desktop-installation-id";
    const INTERVAL: u64 = 3 * 60 * 60;
    const WAKE_INTERVAL: u64 = 5 * 60;
    const LABEL: &str = "com.opensecura.openaidr.updater";
    const JOURNAL: &str = "desktop-update.json";
    const MAX_DOWNLOAD: u64 = 1024 * 1024 * 1024;
    const OPERATION_BUSY: &str = "A desktop update or sensor operation is in progress. Try again shortly.";
    const OPERATION_WAIT: Duration = Duration::from_secs(180);

    pub(super) fn cancel(app: &AppHandle) -> Result<Value, String> {
        let manual = app.state::<ManualUpdate>();
        let active = manual.0.lock().map_err(|_| "Cannot cancel the update.")?;
        active.as_ref().ok_or("There is no cancellable update running.")?.cancel()?;
        Ok(Value::Null)
    }

    pub(super) async fn manual(app: &AppHandle, version: Option<String>) -> Result<Value, String> {
        let manual = app.state::<ManualUpdate>();
        let task = Arc::new(ManualTask::default());
        {
            let mut active = manual.0.lock().map_err(|_| OPERATION_BUSY)?;
            if active.is_some() { return Err(OPERATION_BUSY.into()); }
            *active = Some(task.clone());
        }
        let result = async {
            let directory = directory(app)?;
            let guard = lock_file(&directory, "desktop-updater.lock")?;
            if directory.join("desktop-removal.json").exists() {
                return Err("OpenAIDR was uninstalled. Set it up again before updating.".into());
            }
            let mut state = read_state(&directory).map_err(|_| "Cannot read update status.")?;
            if state.pending.is_some() {
                return Err("Reopen OpenAIDR to finish the pending update before checking again.".into());
            }
            let installed = match installed(app) {
                Ok(installed) => installed,
                Err(error) => {
                    state.set(&directory, "unavailable")?;
                    state.error = Some(error);
                    save(&directory, &state)?;
                    return Ok(state.public());
                }
            };
            let intent = version.as_deref().map_or(Intent::Check, Intent::Install);
            let result = check(app, &installed, &directory, &mut state, intent, Some(&task)).await;
            if task.phase.load(Ordering::SeqCst) == 1 {
                state.latest = installed.version.to_string();
                state.set(&directory, "idle")?;
            } else {
                match result {
                    Ok(true) => {
                        let next = bundle(&installed.path, &app.config().identifier)?;
                        drop(guard);
                        if let Err(error) = handoff(&next) {
                            let _guard = lock_file(&directory, "desktop-updater.lock")?;
                            state.fail(&directory, error);
                        }
                    }
                    Ok(false) => {}
                    Err(error) => state.fail(&directory, error),
                }
            }
            Ok(state.public())
        }.await;
        if let Ok(mut active) = manual.0.lock() { *active = None; }
        result
    }

    #[derive(Clone, Default, Deserialize, Serialize)]
    #[serde(default)]
    pub(super) struct State {
        state: String,
        latest: String,
        error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        downloaded_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        total_bytes: Option<u64>,
        attempted_at: Option<u64>,
        check_health: crate::platform::updater::update_check::CheckHealth,
        recovery_attempted_at: Option<u64>,
        completed_version: String,
        pending: Option<Pending>,
        retained: Vec<Pending>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct Pending {
        app: PathBuf,
        staging: PathBuf,
        version: String,
        previous: String,
        #[serde(default)]
        build: Value,
    }

    impl State {
        pub(super) fn public(&self) -> Value {
            let mut value = json!({
                "state": if self.state.is_empty() { "idle" } else { &self.state },
                "latest": self.latest,
                "error": self.error,
            });
            if self.state == "error" && self.check_health.warning_deferred(self.error.as_deref(), timestamp()) {
                value["warning_deferred"] = json!(true);
            }
            if self.state == "downloading" {
                if let Some(downloaded) = self.downloaded_bytes {
                    value["downloaded_bytes"] = json!(downloaded);
                }
                if let Some(total) = self.total_bytes.filter(|total| *total > 0) {
                    value["total_bytes"] = json!(total);
                }
            }
            value
        }

        fn set(&mut self, directory: &Path, state: &str) -> Result<(), String> {
            self.state = state.into();
            self.error = None;
            self.downloaded_bytes = if state == "downloading" { Some(0) } else { None };
            self.total_bytes = None;
            save(directory, self)
        }

        fn fail(&mut self, directory: &Path, error: String) {
            self.state = "error".into();
            self.error = Some(error);
            self.downloaded_bytes = None;
            self.total_bytes = None;
            let _ = save(directory, self);
        }

        fn recover_interrupted_check(&mut self, directory: &Path) {
            // Call only while holding the updater lock. No live worker can own
            // these phases, and no pending app replacement needs recovery.
            if self.pending.is_none() && matches!(self.state.as_str(), "checking" | "downloading" | "installing") {
                self.fail(directory, "The previous update was interrupted. Check for updates to try again.".into());
            }
        }
    }

    pub(super) fn directory(app: &AppHandle) -> Result<PathBuf, String> {
        Ok(app
            .path()
            .home_dir()
            .map_err(|_| "Cannot locate the update state directory.")?
            .join("Library/Application Support/OpenAIDR"))
    }

    fn private_directory(path: &Path) -> Result<(), String> {
        reject_links(path)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|_| "Cannot create the update state directory.")?;
        let metadata = fs::metadata(path).map_err(|_| "Cannot read the update directory.")?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err("The update directory must belong to the current user.".into());
        }
        Ok(())
    }

    fn reject_links(path: &Path) -> Result<(), String> {
        for ancestor in path.ancestors() {
            if fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err("Automatic updates do not use symbolic installation paths.".into());
            }
        }
        Ok(())
    }

    pub(super) fn lock(directory: &Path) -> Result<OperationLock, String> {
        lock_file(directory, "desktop-operation.lock")
    }

    pub(super) fn lock_file(directory: &Path, name: &str) -> Result<OperationLock, String> {
        try_lock_file(directory, name)?.ok_or_else(|| OPERATION_BUSY.into())
    }

    fn try_lock_file(directory: &Path, name: &str) -> Result<Option<OperationLock>, String> {
        private_directory(directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(name))
            .map_err(|_| "Cannot open the desktop operation lock.")?;
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err("Cannot acquire the desktop operation lock.".into());
        }
        Ok(Some(OperationLock { _file: file }))
    }

    async fn update_operation_lock(directory: &Path, timeout: Duration) -> Result<OperationLock, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(guard) = try_lock_file(directory, "desktop-operation.lock")? {
                if directory.join("desktop-removal.json").exists() {
                    return Err("Removal was requested. Automatic updates remain paused.".into());
                }
                return Ok(guard);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(OPERATION_BUSY.into());
            }
            // The open window may be reading status or completing setup when
            // the update worker arrives. Keep its pending handoff and retry.
            tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
        }
    }

    fn installation_id(directory: &Path, _operation: &OperationLock) -> Result<String, String> {
        let path = directory.join(INSTALLATION_ID);
        let read = || -> Result<String, std::io::Error> {
            let file = OpenOptions::new().read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 || metadata.len() != 32 {
                return Err(std::io::Error::other("invalid installation ID file"));
            }
            let mut id = String::new();
            file.take(33).read_to_string(&mut id)?;
            if !valid_installation_id(&id) {
                return Err(std::io::Error::other("invalid installation ID"));
            }
            Ok(id)
        };
        match read() {
            Ok(id) => return Ok(id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Cannot read the private installation ID. The current app was kept.".into()),
        }
        let mut random = [0u8; 16];
        if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
            return Err("Cannot generate an installation ID. The current app was kept.".into());
        }
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let save = || -> Result<(), std::io::Error> {
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            temporary.write_all(id.as_bytes())?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(&path).map_err(|error| error.error)?;
            File::open(directory)?.sync_all()
        };
        save().map_err(|_| "Cannot save the private installation ID. The current app was kept.")?;
        Ok(id)
    }

    pub(super) fn load(directory: &Path) -> State {
        read_state(directory).unwrap_or_default()
    }

    pub(super) fn read_status(directory: &Path) -> Result<Value, String> {
        read_state(directory).map(|state| state.public())
            .map_err(|_| "Cannot read automatic-update status.".into())
    }

    fn read_state(directory: &Path) -> Result<State, std::io::Error> {
        let result = (|| {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(directory.join(JOURNAL))?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::other("invalid update state file"));
            }
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                return Err(std::io::Error::other("oversized update state"));
            }
            serde_json::from_slice(&bytes).map_err(std::io::Error::other)
        })();
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            other => other,
        }
    }

    fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let parent = path.parent().ok_or("Invalid update state path.")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| "Cannot save automatic-update state.")?;
        temporary
            .write_all(bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| "Cannot save automatic-update state.")?;
        temporary
            .persist(path)
            .map_err(|_| "Cannot save automatic-update state.")?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Cannot save automatic-update state.".into())
    }

    fn save(directory: &Path, state: &State) -> Result<(), String> {
        atomic_write(
            &directory.join(JOURNAL),
            &serde_json::to_vec(state).map_err(|_| "Cannot encode automatic-update state.")?,
        )
    }

    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn due(previous: Option<u64>, now: u64, interval: u64) -> bool {
        previous.map_or(true, |previous| {
            now < previous || now - previous >= interval
        })
    }

    struct Bundle {
        path: PathBuf,
        executable: PathBuf,
        version: Version,
        build: Value,
    }

    fn bundle(path: &Path, identifier: &str) -> Result<Bundle, String> {
        reject_links(path)?;
        let info_path = path.join("Contents/Info.plist");
        reject_links(&info_path)?;
        let info: Dictionary = plist::from_file(info_path)
            .map_err(|_| "The application bundle has invalid version metadata.")?;
        let text = |key: &str| info.get(key).and_then(plist::Value::as_string);
        let same_product = |id| matches!(id,
            "com.opensecura.openaidr" | "com.opensecura.openaidr.sensor");
        if text("CFBundleIdentifier") != Some(identifier)
            && !(same_product(identifier) && text("CFBundleIdentifier").is_some_and(same_product))
        {
            return Err("The update belongs to a different application.".into());
        }
        let executable =
            text("CFBundleExecutable").ok_or("The update has no application executable.")?;
        if Path::new(executable).components().count() != 1
            || executable == "."
            || executable == ".."
        {
            return Err("The update has an invalid application executable.".into());
        }
        let executable = path.join("Contents/MacOS").join(executable);
        reject_links(&executable)?;
        if !executable.is_file() {
            return Err("The update has no application executable.".into());
        }
        let version = Version::parse(text("OpenAIDRVersion").or_else(|| text("CFBundleShortVersionString")).unwrap_or(""))
            .map_err(|_| "The application bundle has an invalid version.")?;
        let build = info.get("OpenAIDRBuild")
            .and_then(|value| serde_json::to_value(value).ok()).unwrap_or(Value::Null);
        if crate::build_order(&version.to_string(), &build).is_none() {
            return Err("The application bundle has invalid source metadata.".into());
        }
        Ok(Bundle {
            path: path.into(),
            executable,
            version,
            build,
        })
    }

    fn installed(app: &AppHandle) -> Result<Bundle, String> {
        let executable = tauri::process::current_binary(&app.env())
            .map_err(|_| "Cannot locate the installed application.")?;
        let path = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or("Cannot locate the installed application.")?;
        let home = app
            .path()
            .home_dir()
            .map_err(|_| "Cannot locate the home directory.")?;
        installed_path(path, &home)?;
        bundle(path, &app.config().identifier)
    }

    pub(super) fn removed_bundle(executable: &Path, identifier: &str, removal: &Value) -> Result<PathBuf, String> {
        if removal["state"] != "complete" || !removal["errors"].as_array().is_some_and(Vec::is_empty) {
            return Err("Finish removing collection before moving the app to Trash.".into());
        }
        let invalid = "Cannot locate OpenAIDR's app bundle. Quit and move the app to Trash in Finder.";
        let path = executable.parent().and_then(Path::parent).and_then(Path::parent).ok_or(invalid)?;
        if path.extension().map_or(true, |extension| extension != "app") {
            return Err(invalid.into());
        }
        let installed = bundle(path, identifier).map_err(|_| invalid)?;
        if installed.executable != executable {
            return Err(invalid.into());
        }
        Ok(path.to_path_buf())
    }

    pub(super) fn trash_removed_bundle(executable: &Path, identifier: &str, removal: &Value) -> Result<PathBuf, String> {
        let path = removed_bundle(executable, identifier, removal)?;
        let url = objc2_foundation::NSURL::from_directory_path(&path).ok_or("Cannot locate OpenAIDR's app bundle.")?;
        let mut trashed = None;
        objc2_foundation::NSFileManager::defaultManager()
            .trashItemAtURL_resultingItemURL_error(&url, Some(&mut trashed))
            .map_err(|_| "Could not move OpenAIDR to Trash. Quit and move it to Trash in Finder.")?;
        Ok(trashed.and_then(|url| url.to_file_path()).unwrap_or_default())
    }

    pub(super) fn restart_after_update(app: &AppHandle) -> bool {
        let Ok(directory) = directory(app) else {
            return false;
        };
        let state = load(&directory);
        if state.pending.is_some() || state.completed_version.is_empty() {
            return false;
        }
        let Ok(installed) = installed(app) else {
            return false;
        };
        crate::newer_build(&installed.version.to_string(), &app.package_info().version.to_string(),
            &installed.build, &serde_json::from_str(env!("OPENAIDR_BUILD_INFO")).unwrap_or(Value::Null))
            && installed.version.to_string() == state.completed_version
    }

    fn installed_path(path: &Path, home: &Path) -> Result<(), String> {
        reject_links(path)?;
        if path.extension().map_or(true, |v| v != "app")
            || ![PathBuf::from("/Applications"), home.join("Applications")]
                .iter()
                .any(|directory| path.parent() == Some(directory.as_path()))
        {
            return Err("Move the app to Applications or your home Applications folder to enable automatic updates.".into());
        }
        let metadata = fs::metadata(path).map_err(|_| "Cannot read the installed application.")?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("Automatic updates require an application owned by your user. Ask your administrator to update this installation.".into());
        }
        let parent = path.parent().unwrap();
        tempfile::Builder::new().prefix(".openaidr-write-check-")
            .tempdir_in(parent)
            .map_err(|_| "The Applications folder is not writable. Ask your administrator to update this installation.")?;
        Ok(())
    }

    fn command_ok(program: &Path, args: &[&std::ffi::OsStr], seconds: u64) -> Result<(), String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Cannot start the update operation.")?;
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) => return Err("The update operation failed.".into()),
                Err(_) => return Err("Cannot check the update operation.".into()),
                _ => {}
            }
            if started.elapsed() >= Duration::from_secs(seconds) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The update operation timed out.".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn register(app: &AppHandle, installed: &Bundle) -> Result<(), String> {
        let home = app
            .path()
            .home_dir()
            .map_err(|_| "Cannot locate login services.")?;
        let minute = u64::from(Sha256::digest(home.as_os_str().as_bytes())[0]) % 5;
        let agents = home.join("Library/LaunchAgents");
        private_directory(&agents)?;
        let path = agents.join(format!("{LABEL}.plist"));
        let document = json!({
            "Label": LABEL,
            "ProgramArguments": [installed.executable, "--background-update"],
            "RunAtLoad": true,
            "StartInterval": WAKE_INTERVAL,
            "StartCalendarInterval": (minute..60).step_by(5)
                .map(|minute| json!({"Minute": minute})).collect::<Vec<_>>(),
            "ProcessType": "Background",
            "LimitLoadToSessionType": "Aqua",
        });
        let mut bytes = Vec::new();
        plist::to_writer_xml(&mut bytes, &document)
            .map_err(|_| "Cannot prepare the update schedule.")?;
        let domain = format!("gui/{}", unsafe { libc::geteuid() });
        let label = format!("{domain}/{LABEL}");
        register_schedule(&path, &bytes, &directory(app)?.join("desktop-removal.json"), &domain, &label, std::process::id(), |args| {
            let mut command = Command::new("/bin/launchctl");
            command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            let mut child = command.spawn().map_err(|_| "Cannot inspect the update service.")?;
            let (status, output) = crate::child_output(&mut child, Duration::from_secs(10), 1024 * 1024)?;
            Ok((status.code(), output))
        })
    }

    fn register_schedule(
        path: &Path, bytes: &[u8], marker: &Path, domain: &str, label: &str, pid: u32,
        mut run: impl FnMut(&[&std::ffi::OsStr]) -> Result<(Option<i32>, Vec<u8>), String>,
    ) -> Result<(), String> {
        if marker.exists() {
            return Ok(());
        }
        reject_links(path)?;
        // launchd retains disable overrides even if all local app data was
        // deleted. A clean installation must enable the label before bootstrap.
        if run(&["enable".as_ref(), label.as_ref()])?.0 != Some(0) {
            return Err("Cannot enable the automatic-update schedule. Reopen the app to retry.".into());
        }
        let (status, output) = run(&["print".as_ref(), label.as_ref()])?;
        if !matches!(status, Some(0 | 113)) {
            return Err("Cannot inspect the automatic-update schedule. Reopen the app to retry.".into());
        }
        let loaded = status == Some(0);
        let own_pid = format!("pid = {pid}");
        let own_worker = String::from_utf8_lossy(&output).lines().any(|line| line.trim() == own_pid);
        if fs::read(path).ok().as_deref() != Some(bytes) {
            atomic_write(path, bytes)?;
            if loaded {
                // Set up again may run in the same updater window that removal
                // deliberately kept alive. Restore its plist without killing it.
                if own_worker {
                    return Ok(());
                }
                if run(&["bootout".as_ref(), label.as_ref()])?.0 != Some(0) {
                    return Err("Cannot replace the automatic-update schedule. Reopen the app to retry.".into());
                }
            }
        } else if loaded {
            return Ok(());
        }
        if run(&["bootstrap".as_ref(), domain.as_ref(), path.as_os_str()])?.0 != Some(0) {
            return Err("Cannot start the automatic-update schedule. Reopen the app to retry.".into());
        }
        Ok(())
    }

    pub(super) fn removal_user_supported(uid: libc::uid_t) -> bool {
        uid != 0
    }

    pub(super) fn removal_lock_for_user(
        uid: libc::uid_t, directory: impl FnOnce() -> Result<PathBuf, String>,
    ) -> Result<OperationLock, String> {
        if !removal_user_supported(uid) {
            return Err("Desktop removal supports the current user's macOS installation only. Open the app without root privileges.".into());
        }
        lock_file(&directory()?, "desktop-updater.lock")
    }

    pub(super) fn resume_removal(app: &AppHandle) -> Result<(), String> {
        let label = format!("gui/{}/{LABEL}", unsafe { libc::geteuid() });
        command_ok(Path::new("/bin/launchctl"), &["enable".as_ref(), label.as_ref()], 10)?;
        fs::remove_file(directory(app)?.join("desktop-removal.json"))
            .map_err(|_| "Cannot clear the removal record. Retry setup.".into())
    }

    pub(super) fn clear_deleted_removal(directory: &Path, mode: Mode) -> Result<(), String> {
        let marker = directory.join("desktop-removal.json");
        if mode != Mode::Window || !marker.exists() {
            return Ok(());
        }
        let _updater = lock_file(directory, "desktop-updater.lock")?;
        let _operation = lock(directory)?;
        reject_links(&marker)?;
        let saved = read_removal_status(&marker);
        if saved["state"] != "complete" || !saved["errors"].as_array().is_some_and(Vec::is_empty)
            || saved["data_deletion_started"] != true || saved["data_deleted"] != true {
            return Ok(());
        }
        // A completed purge has no configuration to restore. A later window
        // launch starts fresh, while the uninstalling process stays stopped.
        match fs::symlink_metadata(directory.join("sensor.yaml")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            _ => return Ok(()),
        }
        fs::remove_file(marker).map_err(|_| "Cannot clear the removal record. Retry setup.".into())
    }

    pub(super) fn prepare_removal(app: &AppHandle) -> Result<(), String> {
        let directory = directory(app)?;
        let marker = directory.join("desktop-removal.json");
        reject_links(&marker)?;
        if !marker.exists() {
            atomic_write(&marker, br#"{"state":"pending","errors":[]}"#)?;
        }
        let home = app.path().home_dir().map_err(|_| "Cannot locate login services.")?;
        let label = format!("gui/{}/{LABEL}", unsafe { libc::geteuid() });
        let path = home.join(format!("Library/LaunchAgents/{LABEL}.plist"));
        remove_schedule(&path, &label, std::process::id(), |args| {
            let mut command = Command::new("/bin/launchctl");
            command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            let mut child = command.spawn().map_err(|_| "Cannot inspect the update service.")?;
            let (status, output) = crate::child_output(&mut child, Duration::from_secs(10), 1024 * 1024)?;
            Ok((status.code(), output))
        })
    }

    fn remove_schedule(
        path: &Path, label: &str, pid: u32,
        mut run: impl FnMut(&[&str]) -> Result<(Option<i32>, Vec<u8>), String>,
    ) -> Result<(), String> {
        reject_links(path)?;
        // A user can open the window in this launchd worker. Disable future
        // starts before unlinking its plist, but do not kill our own window.
        if run(&["disable", label])?.0 != Some(0) {
            return Err("Cannot stop the update schedule. Retry removal.".into());
        }
        let (status, output) = run(&["print", label])?;
        if status == Some(0) {
            let own_pid = format!("pid = {pid}");
            let own_worker = String::from_utf8_lossy(&output).lines().any(|line| line.trim() == own_pid);
            if !own_worker && run(&["bootout", label])?.0 != Some(0) {
                return Err("Cannot stop the update service. Retry removal.".into());
            }
        } else if status != Some(113) {
            return Err("Cannot inspect the update service. Retry removal.".into());
        }
        fs::remove_file(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(error) }
        }).map_err(|_| "Cannot remove the update service registration. Retry removal.".into())
    }

    fn swap(first: &Path, second: &Path) -> Result<(), String> {
        let first =
            CString::new(first.as_os_str().as_bytes()).map_err(|_| "Invalid application path.")?;
        let second =
            CString::new(second.as_os_str().as_bytes()).map_err(|_| "Invalid update path.")?;
        // Atomic exchange always leaves a complete app at the installed path.
        if unsafe { libc::renamex_np(first.as_ptr(), second.as_ptr(), libc::RENAME_SWAP) } != 0 {
            return Err(
                "Cannot replace this application. The current installation was kept.".into(),
            );
        }
        Ok(())
    }

    fn validate_pending(pending: &Pending, installed: &Bundle) -> Result<PathBuf, String> {
        if pending.app != installed.path
            || pending.staging.parent() != installed.path.parent()
            || !pending
                .staging
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".openaidr-update-"))
        {
            return Err("The saved update belongs to another installation. Open that installed app to finish its update.".into());
        }
        reject_links(&pending.staging)?;
        Ok(pending.staging.join(
            installed
                .path
                .file_name()
                .ok_or("Invalid application path.")?,
        ))
    }

    fn staged_version(staged: &Path, identifier: &str, advertised: &str) -> Result<Bundle, String> {
        let result = bundle(staged, identifier)?;
        if result.version.to_string() != advertised {
            return Err("The signed app version does not match the release announcement. The current app was kept.".into());
        }
        let directory = result.path.join("Contents/MacOS");
        let mut sensors = Vec::new();
        for name in ["openaidr", "openaidr-sensor"] {
            let sensor = directory.join(name);
            if sensor.symlink_metadata().is_err() { continue; }
            reject_links(&sensor)?;
            let bytes = fs::read(&sensor).map_err(|_| "The updated sensor could not be read. The current app was kept.")?;
            crate::sensor_runtime::Runtime::inspect(&sensor, &bytes)?;
            sensors.push(sensor);
        }
        if sensors.is_empty() {
            return Err("The updated sensor is missing. The current app was kept.".into());
        }
        for sensor in sensors {
            let metadata = crate::sensor_metadata(&sensor);
            let sensor_version = metadata.version
                .ok_or("The updated sensor could not report its version. The current app was kept.")?;
            let matches = if advertised.contains('+') { sensor_version == advertised }
                else { crate::version_key(&sensor_version) == crate::version_key(advertised) };
            if !matches {
                return Err("The signed app and bundled sensor have different versions. The current app was kept.".into());
            }
            if advertised.contains('+') && metadata.build != result.build {
                return Err("The signed app and bundled sensor have different build metadata. The current app was kept.".into());
            }
        }
        Ok(result)
    }

    async fn download(update: &Update, directory: &Path, state: &mut State, key: &str) -> Result<tempfile::NamedTempFile, String> {
        let mut saved_at = None;
        crate::platform::updater::update_download::download(update, directory, key, MAX_DOWNLOAD, |total, announced| {
            state.downloaded_bytes = Some(total);
            state.total_bytes = announced.filter(|size| *size > 0);
            let now = Instant::now();
            if saved_at.map_or(true, |last| now.duration_since(last) >= Duration::from_secs(1)) {
                // Progress persistence is advisory; phase saves still fail safely.
                let _ = save(directory, state);
                saved_at = Some(now);
            }
        }).await
    }

    async fn download_if_eligible(
        update: &Update, directory: &Path, state: &mut State, now: i64, key: &str,
    ) -> Result<Option<tempfile::NamedTempFile>, String> {
        if !prepare_download(update, directory, state, now, Intent::Automatic).await? {
            return Ok(None);
        }
        download(update, directory, state, key).await.map(Some)
    }

    fn unpack(file: &mut fs::File, staged: &Path) -> Result<(), String> {
        let failed = "Cannot unpack the signed update. The current app was kept.";
        let temporary = tempfile::tempdir_in(staged.parent().ok_or(failed)?).map_err(|_| failed)?;
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
        archive.unpack(temporary.path()).map_err(|_| failed)?;
        let mut roots = fs::read_dir(temporary.path()).map_err(|_| failed)?;
        let root = roots.next().ok_or(failed)?.map_err(|_| failed)?;
        if roots.next().is_some() || !root.file_type().map_err(|_| failed)?.is_dir()
            || root.path().extension().and_then(|s| s.to_str()) != Some("app") {
            return Err(failed.into());
        }
        // The caller supplies only an empty staging app beside the installation.
        fs::remove_dir(staged).map_err(|_| failed)?;
        fs::rename(root.path(), staged).map_err(|_| failed)?;
        Ok(())
    }

    async fn prepare_download(
        update: &Update, directory: &Path, state: &mut State, now: i64, intent: Intent<'_>,
    ) -> Result<bool, String> {
        let policy = Policy::from_manifest(&update.raw_json)?;
        if update.raw_json["version"].as_str() != Some(update.version.as_str()) {
            return Err("The release version is not canonical. The current app was kept.".into());
        }
        match intent {
            Intent::Automatic => {
                let id = {
                    let operation = update_operation_lock(directory, OPERATION_WAIT).await?;
                    installation_id(directory, &operation)?
                };
                if !policy.eligible(&update.version, &id, now) {
                    state.set(directory, "idle")?;
                    return Ok(false);
                }
            }
            Intent::Check => {
                state.latest = update.version.clone();
                state.set(directory, "available")?;
                return Ok(false);
            }
            Intent::Install(version) if version != update.version => {
                return Err("The available release changed. Check for updates again before installing.".into());
            }
            Intent::Install(_) => {}
        }
        state.latest = update.version.clone();
        state.set(directory, "downloading")?;
        Ok(true)
    }

    async fn check(
        app: &AppHandle,
        installed: &Bundle,
        directory: &Path,
        state: &mut State,
        intent: Intent<'_>,
        task: Option<&ManualTask>,
    ) -> Result<bool, String> {
        if matches!(intent, Intent::Automatic) && !due(state.attempted_at, timestamp(), INTERVAL) {
            return Ok(false);
        }
        state.attempted_at = Some(timestamp());
        state.set(directory, "checking")?;
        let staging = tempfile::Builder::new()
            .prefix(".openaidr-update-")
            .tempdir_in(installed.path.parent().unwrap())
            .map_err(|_| "Cannot stage an update beside the installed application.")?;
        let staged = staging.path().join(installed.path.file_name().unwrap());
        fs::create_dir(&staged).map_err(|_| "Cannot create the staged application.")?;
        let current = installed.version.clone();
        let publication = installed.build["publication_timestamp"].as_i64().unwrap_or(0);
        // The selected proxy also carries the archive download (update.proxy).
        let proxy = super::super::update_download::release_proxy(crate::bundled_binary(app).ok(), ENDPOINT).await;
        let mut builder = app
            .updater_builder()
            .endpoints(vec![ENDPOINT.parse().unwrap()])
            .map_err(|_| "The update endpoint is invalid.")?
            .executable_path(staged.join("Contents/MacOS/openaidr-desktop"))
            .version_comparator(move |_, remote| {
                if !remote.version.build.is_empty() {
                    remote.version != current && remote.pub_date.is_some_and(|date| date.unix_timestamp() > publication)
                } else {
                    current.build.is_empty() && remote.version > current
                }
            })
            .timeout(Duration::from_secs(30))
            .configure_client(|client| {
                client
                    .https_only(true)
                    .danger_accept_invalid_certs(false)
                    .danger_accept_invalid_hostnames(false)
                    .connect_timeout(Duration::from_secs(15))
            });
        if let Some(proxy) = proxy {
            builder = builder.proxy(proxy);
        }
        let updater = builder
            .build()
            .map_err(|_| "Cannot initialize signed updates.")?;
        let lookup = state.check_health.check(&updater, timestamp());
        let Some(mut update) = (match task {
            Some(task) => task.run(lookup).await,
            None => lookup.await,
        })?
        else {
            state.latest = installed.version.to_string();
            state.set(directory, "idle")?;
            return Ok(false);
        };
        if update.download_url.scheme() != "https"
            || update.download_url.host_str() != Some("releases.opensecura.ai")
            || !update.download_url.path().starts_with(crate::platform::RELEASE_PATH)
            || !update.download_url.username().is_empty()
            || update.download_url.password().is_some()
        {
            return Err(
                "The release has an unsupported download address. The current app was kept.".into(),
            );
        }
        state.latest = installed.version.to_string();
        update.timeout = Some(Duration::from_secs(15 * 60));
        let key = app.config().plugins.0.get("updater").and_then(|value| value["pubkey"].as_str())
            .ok_or("Signed updates are not configured for this build.")?;
        let mut file = if let Some(task) = task {
            if !prepare_download(&update, directory, state, timestamp() as i64, intent).await? {
                return Ok(false);
            }
            let bytes = task.run(download(&update, directory, state, key)).await?;
            task.begin_install()?;
            bytes
        } else {
            let Some(bytes) = download_if_eligible(&update, directory, state, timestamp() as i64, key).await? else {
                return Ok(false);
            };
            bytes
        };
        state.set(directory, "installing")?;
        unpack(file.as_file_mut(), &staged)?;
        let next = staged_version(&staged, &app.config().identifier, &update.version)?;
        if !next.version.build.is_empty() {
            let announced = update.date.map(|date| date.unix_timestamp());
            if announced.is_none() || announced != next.build["publication_timestamp"].as_i64()
                || announced.unwrap_or(0) <= publication {
                return Err("The signed publication order does not match the update feed. The current app was kept.".into());
            }
        }
        command_ok(
            Path::new("/usr/bin/codesign"),
            &[
                "--verify".as_ref(),
                "--deep".as_ref(),
                "--strict".as_ref(),
                next.path.as_os_str(),
            ],
            60,
        )
        .map_err(|_| {
            "The updated app failed macOS signature validation. The current app was kept."
        })?;
        let pending = Pending {
            app: installed.path.clone(),
            staging: staging.keep(),
            version: update.version,
            previous: installed.version.to_string(),
            build: next.build.clone(),
        };
        let replaced = save_pending(directory, state, pending)?;
        let _operation = update_operation_lock(directory, OPERATION_WAIT).await?;
        let current = self::installed(app)?;
        if current.version != installed.version || current.build != installed.build {
            if let Some(pending) = state.pending.take() {
                let _ = fs::remove_dir_all(pending.staging);
            }
            if replaced.is_some() {
                state.retained.pop();
            }
            state.pending = replaced;
            return Err(
                "The installed app changed during the download. Its current version was kept."
                    .into(),
            );
        }
        swap(&installed.path, &staged)?;
        state.set(directory, "restarting")?;
        Ok(true)
    }

    fn save_pending(
        directory: &Path,
        state: &mut State,
        pending: Pending,
    ) -> Result<Option<Pending>, String> {
        let replaced = state.pending.replace(pending);
        if let Some(replaced) = &replaced {
            state.retained.push(replaced.clone());
        }
        state.recovery_attempted_at = None;
        // Keep the staged app if saving reports an error: the rename may
        // already have persisted the journal before its directory sync failed.
        state.set(directory, "installing")?;
        Ok(replaced)
    }

    fn resume(identifier: &str, installed: &Bundle, pending: &Pending) -> Result<Bundle, String> {
        let backup = validate_pending(pending, installed)?;
        let installed = bundle(&installed.path, identifier)?;
        let expected = Version::parse(&pending.version)
            .map_err(|_| "The saved update has an invalid version.")?;
        if installed.version == expected || crate::newer_build(
            &installed.version.to_string(), &pending.version, &installed.build, &pending.build,
        ) {
            return Ok(installed);
        }
        if installed.version.to_string() != pending.previous {
            return Err(
                "The app changed during its update. The current installation was kept.".into(),
            );
        }
        let next = staged_version(&backup, identifier, &pending.version)?;
        if next.build != pending.build || !crate::newer_build(
            &pending.version, &installed.version.to_string(), &next.build, &installed.build,
        ) {
            return Err("The saved update has no verified later publication order. The current app was kept.".into());
        }
        swap(&installed.path, &backup)?;
        bundle(&installed.path, identifier)
    }

    fn finish(
        app: &AppHandle,
        installed: &Bundle,
        directory: &Path,
        state: &mut State,
    ) -> Result<(), String> {
        let pending = state.pending.clone().ok_or("There is no pending update.")?;
        validate_pending(&pending, installed)?;
        let installed = self::installed(app)?;
        let pending_version = Version::parse(&pending.version)
            .map_err(|_| "The saved update has an invalid version.")?;
        if (installed.version != pending_version && !crate::newer_build(
            &installed.version.to_string(), &pending.version, &installed.build, &pending.build,
        )) || app.package_info().version != installed.version {
            return Err("Reopen the updated app to finish its sensor update.".into());
        }
        state.recovery_attempted_at = Some(timestamp());
        state.latest = installed.version.to_string();
        state.set(directory, "restarting")?;
        staged_version(
            &installed.path,
            &app.config().identifier,
            &installed.version.to_string(),
        )?;
        let executable = crate::stable_binary(app)?;
        finish_sensor(&executable, &installed.version.to_string(), Duration::from_secs(120))?;
        if self::installed(app)?.version != installed.version {
            return Err(
                "The installed app changed during sensor setup. Its current version was kept."
                    .into(),
            );
        }
        complete(&app.config().identifier, &installed, directory, state)
    }

    fn complete(
        identifier: &str,
        installed: &Bundle,
        directory: &Path,
        state: &mut State,
    ) -> Result<(), String> {
        let pending = state
            .pending
            .as_ref()
            .ok_or("There is no pending update.")?;
        // The old bundle is retained until the new executable completes its
        // service handoff. Queue and enrollment paths are never removed.
        let retained = std::iter::once(pending)
            .chain(state.retained.iter())
            .map(|record| retained_path(record, installed, identifier))
            .collect::<Result<Vec<_>, _>>()?;
        state.pending = None;
        state.retained.clear();
        state.completed_version = installed.version.to_string();
        state.set(directory, "updated")?;
        // A cleanup failure must not undo the completed service handoff or
        // make a partially removed backup block future updates.
        for path in retained {
            let _ = fs::remove_dir_all(&path);
            if let Some(directory) = path.parent() {
                let _ = fs::remove_dir(directory);
            }
        }
        Ok(())
    }

    fn retained_path(
        pending: &Pending,
        installed: &Bundle,
        identifier: &str,
    ) -> Result<PathBuf, String> {
        let backup = validate_pending(pending, installed)?;
        if backup.exists() {
            let version = bundle(&backup, identifier)?.version.to_string();
            // A manual installation can supersede a downloaded app before
            // exchange, so either side of the recorded exchange is valid.
            if version != pending.previous && version != pending.version {
                return Err(
                    "The retained application changed. Update recovery needs administrator help."
                        .into(),
                );
            }
        }
        Ok(backup)
    }

    fn finish_sensor(executable: &Path, expected: &str, grace: Duration) -> Result<(), String> {
        super::super::sensor_handoff::finish(expected, grace, |payload| crate::bridge(executable, payload))
    }

    fn handoff(next: &Bundle) -> Result<(), String> {
        use std::os::unix::process::CommandExt;
        Command::new(&next.executable).arg("--finish-update")
            .process_group(0)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().map(|_| ())
            .map_err(|_| "The app was updated, but its sensor update could not start. Reopen the app to retry.".into())
    }

    pub(super) fn initialize(app: AppHandle, mode: Mode) {
        tauri::async_runtime::spawn(async move {
            let result = async {
                let directory = directory(&app)?;
                let guard = lock_file(&directory, "desktop-updater.lock")?;
                if directory.join("desktop-removal.json").exists() {
                    return Ok::<_, String>(());
                }
                let mut state = load(&directory);
                state.recover_interrupted_check(&directory);
                let installed = match installed(&app) {
                    Ok(installed) => installed,
                    Err(error) => {
                        state.state = "unavailable".into();
                        state.error = Some(error);
                        state.downloaded_bytes = None;
                        state.total_bytes = None;
                        save(&directory, &state)?;
                        return Ok::<_, String>(());
                    }
                };
                let operation = async {
                    if mode == Mode::Window {
                        register(&app, &installed)?;
                    }
                    if let Some(pending) = state.pending.clone() {
                        if mode == Mode::Check
                            && !due(state.recovery_attempted_at, timestamp(), 5 * 60)
                        {
                            return Ok(None);
                        }
                        let next = {
                            let _operation = update_operation_lock(&directory, OPERATION_WAIT).await?;
                            let current = self::installed(&app)?;
                            let next = resume(&app.config().identifier, &current, &pending)?;
                            if mode == Mode::Finish {
                                finish(&app, &next, &directory, &mut state)?;
                                return Ok(None);
                            }
                            next
                        };
                        // A broken sensor in one release must not prevent a
                        // later signed release from repairing the installation.
                        if check(&app, &next, &directory, &mut state, Intent::Automatic, None).await? {
                            Ok(Some(bundle(&next.path, &app.config().identifier)?))
                        } else {
                            Ok(Some(next))
                        }
                    } else if mode != Mode::Finish
                        && check(&app, &installed, &directory, &mut state, Intent::Automatic, None).await?
                    {
                        Ok(Some(bundle(&installed.path, &app.config().identifier)?))
                    } else {
                        Ok(None)
                    }
                }
                .await;
                match operation {
                    Ok(next) => {
                        drop(guard);
                        if let Some(next) = next {
                            if let Err(error) = handoff(&next) {
                                if let Ok(_guard) = lock_file(&directory, "desktop-updater.lock") {
                                    load(&directory).fail(&directory, error);
                                }
                            }
                        }
                    }
                    Err(error) => state.fail(&directory, error),
                }
                Ok(())
            }
            .await;
            // Contention simply means another desktop operation owns this
            // attempt. Never wait indefinitely or start another installer.
            let _ = result;
            if mode.headless() {
                let handle = app.clone();
                let _ = app.run_on_main_thread(move || {
                    if handle.webview_windows().is_empty() {
                        handle.exit(0);
                    }
                });
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use base64::{engine::general_purpose::STANDARD, Engine};
        use std::{
            net::TcpListener,
            os::unix::fs::{symlink, PermissionsExt},
            sync::{Barrier, Mutex},
            sync::atomic::{AtomicBool, Ordering},
            thread,
        };

        const ID: &str = "com.opensecura.openaidr.sensor";

        #[test]
        fn installation_identity_is_private_and_stable_under_concurrent_first_use() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let barrier = Barrier::new(4);
            let ids = thread::scope(|scope| {
                let workers: Vec<_> = (0..4).map(|_| scope.spawn(|| {
                    barrier.wait();
                    tauri::async_runtime::block_on(async {
                        let operation = update_operation_lock(&root, Duration::from_secs(5)).await.unwrap();
                        installation_id(&root, &operation).unwrap()
                    })
                })).collect();
                workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
            });
            assert!(valid_installation_id(&ids[0]));
            assert!(ids.iter().all(|id| id == &ids[0]));
            assert_eq!(fs::read_to_string(root.join(INSTALLATION_ID)).unwrap(), ids[0]);
            assert_eq!(fs::metadata(root.join(INSTALLATION_ID)).unwrap().mode() & 0o777, 0o600);
            tauri::async_runtime::block_on(async {
                // Parallel tests can briefly inherit the flock while spawning a child.
                let operation = update_operation_lock(&root, Duration::from_secs(5)).await.unwrap();
                assert_eq!(installation_id(&root, &operation).unwrap(), ids[0]);
            });
        }

        #[test]
        fn invalid_identity_files_are_never_followed_or_replaced() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let operation = lock(&root).unwrap();
            let path = root.join(INSTALLATION_ID);
            for invalid in ["", "0123456789abcdef0123456789abcdeF", "0123456789abcdef0123456789abcdef\n"] {
                fs::write(&path, invalid).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                assert!(installation_id(&root, &operation).is_err());
                assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
            }
            let id = "0123456789abcdef0123456789abcdef";
            fs::write(&path, id).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(installation_id(&root, &operation).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::hard_link(&path, root.join("linked-id")).unwrap();
            assert!(installation_id(&root, &operation).is_err());
            fs::remove_file(&path).unwrap();
            for target in [root.join("linked-id"), root.join("missing")] {
                symlink(&target, &path).unwrap();
                assert!(installation_id(&root, &operation).is_err());
                assert_eq!(fs::read_link(&path).unwrap(), target);
                fs::remove_file(&path).unwrap();
            }
            assert_eq!(fs::read_to_string(root.join("linked-id")).unwrap(), id);
            let pipe = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
            assert!(installation_id(&root, &operation).is_err());
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            assert!(installation_id(&root, &operation).is_err());
        }

        #[test]
        fn root_cannot_acquire_removal_access_or_touch_the_state_directory() {
            assert!(!removal_user_supported(0));
            assert!(removal_lock_for_user(0, || panic!("root must be rejected before any directory access")).is_err());
            assert!(removal_user_supported(501));
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().canonicalize().unwrap();
            let _guard = removal_lock_for_user(501, || Ok(directory.clone())).unwrap();
            assert!(directory.join("desktop-updater.lock").exists());
        }

        #[test]
        fn trash_requires_completed_removal_and_the_matching_app_bundle() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let app = fixture(&root.join("OpenAIDR.app"), "0.1.0");
            for removal in [Value::Null, json!({"state":"pending","errors":[]}), json!({"state":"complete"}), json!({"state":"complete","errors":["Still stopping"]})] {
                assert!(trash_removed_bundle(&app.executable, ID, &removal).is_err());
                assert!(app.path.exists());
            }
            let complete = json!({"state":"complete","errors":[]});
            for executable in [&app.executable, &root.join("target/debug/openaidr-desktop"), &app.path.join("Contents/MacOS/openaidr"), &app.path.join("Contents/MacOS/openaidr-sensor")] {
                let identifier = if executable == &app.executable { "another.application" } else { ID };
                assert!(trash_removed_bundle(executable, identifier, &complete).is_err());
            }
            let linked = root.join("Linked.app");
            symlink(&app.path, &linked).unwrap();
            assert!(trash_removed_bundle(&linked.join("Contents/MacOS/openaidr-desktop"), ID, &complete).is_err());
            assert!(app.path.exists());
        }

        #[test]
        fn trash_moves_only_the_disposable_bundle_and_preserves_local_data() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let app = fixture(&root.join("OpenAIDR's test app.app"), "0.1.0");
            let data = root.join("retained-data");
            fs::write(&data, "retained records").unwrap();
            let removal = json!({"state":"complete","errors":[],"retained_data":data});
            assert_eq!(removed_bundle(&app.executable, ID, &removal).unwrap(), app.path);
            assert!(app.path.exists());
            let trashed = trash_removed_bundle(&app.executable, ID, &removal).unwrap();
            let source_gone = !app.path.exists();
            let moved_bundle = trashed.join("Contents/MacOS/openaidr-desktop").is_file();
            // Restore our own fixture so TempDir cleans it without leaving Trash entries.
            fs::rename(&trashed, &app.path).unwrap();
            assert!(source_gone);
            assert!(moved_bundle);
            assert_eq!(fs::read_to_string(&data).unwrap(), "retained records");
        }

        #[test]
        fn fresh_launch_clears_only_completed_data_deletion() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let marker = root.join("desktop-removal.json");
            let deleted = json!({"state":"complete", "errors":[], "preferences":{"hooks":[],"telemetry":[]},
                "data_deletion_started":true, "data_deleted":true});
            for mode in [Mode::Check, Mode::Finish, Mode::Window] {
                fs::write(&marker, serde_json::to_vec(&deleted).unwrap()).unwrap();
                clear_deleted_removal(&root, mode).unwrap();
                assert_eq!(marker.exists(), mode != Mode::Window);
                assert!(!root.join("sensor.yaml").exists());
            }
            for (field, value) in [("state", json!("pending")), ("errors", json!(["Cleanup failed"])),
                ("data_deletion_started", json!(false)), ("data_deleted", json!(false)),
                ("data_deleted", Value::Null), ("preferences", Value::Null)] {
                let mut saved = deleted.clone();
                saved[field] = value;
                let bytes = serde_json::to_vec(&saved).unwrap();
                fs::write(&marker, &bytes).unwrap();
                clear_deleted_removal(&root, Mode::Window).unwrap();
                assert_eq!(fs::read(&marker).unwrap(), bytes);
            }
            fs::write(&marker, b"damaged record").unwrap();
            clear_deleted_removal(&root, Mode::Window).unwrap();
            assert_eq!(fs::read(&marker).unwrap(), b"damaged record");
        }

        #[test]
        fn fresh_launch_preserves_configuration_and_active_removal_locks() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let marker = root.join("desktop-removal.json");
            let config = root.join("sensor.yaml");
            let bytes = br#"{"state":"complete","errors":[],"preferences":{"hooks":[],"telemetry":[]},"data_deletion_started":true,"data_deleted":true}"#;
            fs::write(&marker, bytes).unwrap();
            fs::write(&config, "retained configuration").unwrap();
            clear_deleted_removal(&root, Mode::Window).unwrap();
            assert_eq!(fs::read(&marker).unwrap(), bytes);
            assert_eq!(fs::read_to_string(&config).unwrap(), "retained configuration");
            fs::remove_file(&config).unwrap();
            symlink(root.join("missing.yaml"), &config).unwrap();
            clear_deleted_removal(&root, Mode::Window).unwrap();
            assert_eq!(fs::read(&marker).unwrap(), bytes);
            fs::remove_file(&config).unwrap();
            for name in ["desktop-updater.lock", "desktop-operation.lock"] {
                let _guard = lock_file(&root, name).unwrap();
                assert!(clear_deleted_removal(&root, Mode::Window).is_err());
                assert_eq!(fs::read(&marker).unwrap(), bytes);
            }
            let target = root.join("saved-removal.json");
            fs::rename(&marker, &target).unwrap();
            symlink(&target, &marker).unwrap();
            assert!(clear_deleted_removal(&root, Mode::Window).is_err());
            assert_eq!(fs::read(&target).unwrap(), bytes);
        }

        #[test]
        fn clean_reinstall_enables_schedule_but_retained_removal_blocks_it() {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let path = root.join("updater.plist");
            let marker = root.join("desktop-removal.json");
            fs::write(&marker, b"damaged record").unwrap();
            register_schedule(&path, b"registration", &marker, "gui/501", "gui/501/updater", 42, |_| {
                panic!("a retained removal record must prevent registration")
            }).unwrap();
            assert!(!path.exists());
            fs::remove_file(&marker).unwrap();
            let mut disabled = true;
            let mut loaded = false;
            register_schedule(&path, b"registration", &marker, "gui/501", "gui/501/updater", 42, |args| {
                match args[0].to_str().unwrap() {
                    "enable" => disabled = false,
                    "print" => return Ok((Some(113), Vec::new())),
                    "bootstrap" => {
                        assert!(!disabled);
                        assert_eq!(fs::read(args[2]).unwrap(), b"registration");
                        loaded = true;
                    }
                    _ => panic!("unexpected launchctl command"),
                }
                Ok((Some(0), Vec::new()))
            }).unwrap();
            assert!(loaded);
            assert!(register_schedule(&path, b"registration", &marker, "gui/501", "gui/501/updater", 42, |args| {
                assert_eq!(args[0], "enable");
                Ok((Some(1), Vec::new()))
            }).is_err());
        }

        #[test]
        fn setup_again_preserves_its_own_updater_window_and_checks_failures() {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let path = root.join("updater.plist");
            let marker = root.join("desktop-removal.json");
            for own_worker in [true, false] {
                fs::remove_file(&path).ok();
                let mut calls = Vec::new();
                register_schedule(&path, b"registration", &marker, "gui/501", "gui/501/updater", 42, |args| {
                    calls.push(args[0].to_str().unwrap().to_owned());
                    Ok((Some(0), format!("pid = {}\n", if own_worker {42} else {43}).into_bytes()))
                }).unwrap();
                assert_eq!(fs::read(&path).unwrap(), b"registration");
                assert_eq!(calls, if own_worker {vec!["enable", "print"]} else {vec!["enable", "print", "bootout", "bootstrap"]});
            }
            for failed in ["print", "bootout", "bootstrap"] {
                fs::remove_file(&path).unwrap();
                assert!(register_schedule(&path, b"registration", &marker, "gui/501", "gui/501/updater", 42, |args| {
                    Ok((Some(if args[0] == failed {1} else {0}), b"pid = 43\n".to_vec()))
                }).is_err());
                assert_eq!(path.exists(), failed != "print");
                if !path.exists() { fs::write(&path, b"registration").unwrap(); }
            }
        }

        #[test]
        fn damaged_removal_records_always_expose_a_retryable_state() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("desktop-removal.json");
            for record in ["{", "null", "false", "[]", "{}",
                r#"{"state":"complete","errors":[],"preferences":{"hooks":[],"telemetry":"claude"}}"#,
                r#"{"state":"complete","errors":[],"preferences":{"hooks":[],"telemetry":["unknown"]}}"#,
            ] {
                fs::write(&path, record).unwrap();
                let status = read_removal_status(&path);
                assert_eq!(status["state"], "pending");
                assert!(status["errors"][0].as_str().unwrap().contains("Retry removal"));
            }
            let saved = json!({"state":"complete", "errors":[], "preferences":{"hooks":[], "telemetry":["claude"]}, "retained_data":"/retained"});
            fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
            let status = read_removal_status(&path);
            assert_eq!(status["state"], "complete");
            assert_eq!(status["retained_data"], "/retained");
            assert!(status.get("preferences").is_none());
            fs::write(&path, serde_json::to_vec(&json!({"state":"complete","errors":[],"preferences":{"hooks":[],"telemetry":[]},"data_deletion_started":true,"data_deleted":true})).unwrap()).unwrap();
            assert_eq!(read_removal_status(&path)["data_deleted"], true);
            fs::remove_file(&path).unwrap();
            assert_eq!(read_removal_status(&path)["state"], "pending");
        }

        #[test]
        fn removal_disables_the_schedule_without_killing_its_own_window() {
            for own_worker in [true, false] {
                let root = tempfile::tempdir().unwrap();
                let path = root.path().canonicalize().unwrap().join("updater.plist");
                fs::write(&path, b"registration").unwrap();
                let mut calls = Vec::new();
                remove_schedule(&path, "gui/501/updater", 42, |args| {
                    calls.push(args[0].to_owned());
                    Ok((Some(0), format!("pid = {}\n", if own_worker {42} else {43}).into_bytes()))
                }).unwrap();
                assert!(!path.exists());
                assert_eq!(calls, if own_worker {vec!["disable", "print"]} else {vec!["disable", "print", "bootout"]});
            }
        }

        #[test]
        fn removal_keeps_registration_on_failure_and_rejects_links() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().canonicalize().unwrap().join("updater.plist");
            for failed in ["disable", "print", "bootout"] {
                fs::write(&path, b"registration").unwrap();
                let result = remove_schedule(&path, "gui/501/updater", 42, |args| {
                    Ok((Some(if args[0] == failed {1} else {0}), b"pid = 43\n".to_vec()))
                });
                assert!(result.is_err());
                assert!(path.exists());
            }
            let linked = root.path().canonicalize().unwrap().join("linked.plist");
            symlink(&path, &linked).unwrap();
            assert!(remove_schedule(&linked, "gui/501/updater", 42, |_| panic!("must reject before launchctl")).is_err());
            remove_schedule(&path, "gui/501/updater", 42, |args| {
                Ok((Some(if args[0] == "print" {113} else {0}), Vec::new()))
            }).unwrap();
            assert!(!path.exists());
        }
        // Disposable test key. Its private key was discarded after signing
        // this tiny app fixture; production releases use a different key.
        const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDFEMDg1RjJDOENGNjQ5NEMKUldSTVNmYU1MRjhJSGVhS2wyWGdycnIvT0JWdSs1ZFc1V1ZMUjl4cGVhWWhLNjd2RTNnUVZZcnEK";
        const SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSTVNmYU1MRjhJSGZDOW1LaFU5djRYM20vZXBnemthRVA0T3loRTdLT0xxK2poVEZYSWpCdDhJUk1uVWxIa2FkYjhTckxRK1V0c0k2RDA0S2F4RCtLNk5TeXI0SmZWeFFRPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkxMDE1NDUxCWZpbGU6T3BlbkFJRFIuYXBwLnRhci5negpwVTdXS2lqa2pTUzRRZ3g0NWFzTk9ocndNbnNhTDJCNlE0bnJiTVl1cERZQ0kvaXVGSldJdmgwM1AwU0p4MTZkcE1ZcHlKb0pRNGpPNkQzTFRTb3VBUT09Cg==";
        const ARCHIVE: &str = "H4sIAAAAAAAC/+3VXWvbMBQGYN/Ov0LVriM5aeKM4bq0cQqGrA5NOhjsxrWVRdSRhKQsyb+fbHcr8xYY+wiDnufGIFlHsqzXzhQTV2lyR3Kl6EQKy4Q1NBUrSVTFjfX+gsAJh8Pm6nSvwXj8ra9t75+Hw4GHAu8Etsbm2k3vvUzR5X5Toc9MGy7FBe6TACMmClly8ekC3y9vem/wZexHZ0k2WX6YT1FzKtD8/nqWThDuUXqlVMUoTZYJms/SxRK5GpRObzHCa2vVW0p3u119vCpGCrmpbzR0rqVi2h5mrljPDSClLbGbpq3+3XJca8kLG/uvokd2iCc311tRVizhRlX54TbfsIjWHa7fWO2WHWdPZzqiTw2dodM9K7Y2f6h+GOkWJXJe6l7JzKOV6liFtHQx4SvOdLeCe0JSVzFuCp2TrwWJcU1SH6v3O0+xWEtt37c7tWju6FYIyIAEz8Mj2u5jRJtdjv36/Wc/zf+7vMgWtLsbf5L/8Wh0NP/BoN/Jf+g+AZD/U3h9Rh+4oGbtsz23KPA98JL8Uv7bj5f3z/I/Ou/kfxSGAeT/tPlX7i9hVwh33jpq/iIfBYYvAwAAAAAAAAAAAAAAAAAAAAAA/M++ACTdkb4AKAAA";

        fn fixture(path: &Path, version: &str) -> Bundle {
            fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
            let info = json!({
                "CFBundleIdentifier": ID,
                "CFBundleExecutable": "openaidr-desktop",
                "CFBundleShortVersionString": version,
            });
            plist::to_file_xml(path.join("Contents/Info.plist"), &info).unwrap();
            for executable in ["openaidr-desktop", "openaidr-sensor"] {
                let executable = path.join("Contents/MacOS").join(executable);
                fs::write(
                    &executable,
                    format!("#!/bin/sh\nprintf 'openaidr-sensor {version}\\n'\n"),
                )
                .unwrap();
                fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
            }
            bundle(path, ID).unwrap()
        }

        fn calendar_fixture(path: &Path, hash: char, publication: u64) -> Bundle {
            fixture(path, "0.1.0");
            let commit = hash.to_string().repeat(40);
            let version = format!("2026.10.6+{}", &commit[..7]);
            let published = if publication == 1791342000 { "2026-10-07T03:00:00+00:00" }
                else { "2026-10-07T04:00:00+00:00" };
            let build = json!({"version": version, "source_commit": commit,
                "source_timestamp": 1791334800_u64, "built_at": "2026-10-07T02:00:00+00:00",
                "published_at": published, "publication_timestamp": publication});
            let info = json!({"CFBundleIdentifier": ID, "CFBundleExecutable": "openaidr-desktop",
                "CFBundleShortVersionString": "2026.10.6", "OpenAIDRVersion": version,
                "OpenAIDRBuild": build});
            plist::to_file_xml(path.join("Contents/Info.plist"), &info).unwrap();
            fs::write(path.join("Contents/MacOS/openaidr-sensor"), format!(
                "#!/bin/sh\nif [ \"$1\" = build-info ]; then printf '%s\\n' '{}'; else printf 'openaidr-sensor {}\\n'; fi\n",
                build, version,
            )).unwrap();
            bundle(path, ID).unwrap()
        }

        #[test]
        fn updates_validate_canonical_and_legacy_executables() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let app = calendar_fixture(&root.join("OpenAIDR.app"), 'a', 1791342000);
            let version = app.version.to_string();
            let legacy = app.path.join("Contents/MacOS/openaidr-sensor");
            let canonical = app.path.join("Contents/MacOS/openaidr");
            let script = fs::read_to_string(&legacy).unwrap().replacen(
                "#!/bin/sh\n", "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$0.calls\"\n", 1,
            );
            fs::write(&legacy, &script).unwrap();
            // Existing legacy-only bundles remain valid.
            assert!(staged_version(&app.path, ID, &version).is_ok());
            assert_eq!(fs::read_to_string(legacy.with_extension("calls")).unwrap(), "build-info\n");
            fs::write(legacy.with_extension("calls"), "").unwrap();
            fs::copy(&legacy, &canonical).unwrap();
            assert!(staged_version(&app.path, ID, &version).is_ok());
            for path in [&canonical, &legacy] {
                assert_eq!(fs::read_to_string(path.with_extension("calls")).unwrap(), "build-info\n");
            }
            let original = fs::read(&legacy).unwrap();
            for path in [&canonical, &legacy] {
                fs::write(path, "#!/bin/sh\nprintf 'openaidr 0.1.0\\n'\n").unwrap();
                assert!(staged_version(&app.path, ID, &version).is_err());
                fs::write(path, &original).unwrap();
                let changed = String::from_utf8(original.clone()).unwrap().replace("1791334800", "1791334801");
                fs::write(path, changed).unwrap();
                assert!(staged_version(&app.path, ID, &version).is_err());
                fs::write(path, &original).unwrap();
                for invalid in ["{", "null", "{}"] {
                    let changed = script.replace(&app.build.to_string(), invalid);
                    assert_ne!(changed, script);
                    fs::write(path, changed).unwrap();
                    assert!(staged_version(&app.path, ID, &version).is_err());
                    fs::write(path, &original).unwrap();
                }
            }
            fs::remove_file(&canonical).unwrap();
            symlink(&legacy, &canonical).unwrap();
            assert!(staged_version(&app.path, ID, &version).is_err());
            fs::remove_file(&canonical).unwrap();
            fs::remove_file(&legacy).unwrap();
            assert!(staged_version(&app.path, ID, &version).is_err());
            let legacy_app = fixture(&root.join("OpenAIDR Sensor.app"), "0.1.0");
            assert!(staged_version(&legacy_app.path, ID, "0.1.0").is_ok());
        }

        #[test]
        fn directory_updates_validate_support_before_launch_and_resume_from_onefile() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let old = calendar_fixture(&root.join("OpenAIDR.app"), 'f', 1791342000);
            let staging = root.join(".openaidr-update-runtime");
            let next = calendar_fixture(&staging.join("OpenAIDR.app"), 'a', 1791345600);
            let contents = next.path.join("Contents");
            let canonical = contents.join("MacOS/openaidr");
            let legacy = contents.join("MacOS/openaidr-sensor");
            let runtime_name = format!("openaidr-runtime-{}", "a".repeat(64));
            let source = root.join("runtime-source");
            crate::sensor_runtime::tests::fixture(&source, 'a', 1);
            fs::create_dir(contents.join("Resources")).unwrap();
            let runtime = contents.join("Resources").join(&runtime_name);
            fs::rename(source.join(&runtime_name), &runtime).unwrap();
            symlink(Path::new("Resources").join(&runtime_name), contents.join("Frameworks")).unwrap();
            let script = format!("{}# pyi-contents-directory {runtime_name}\0\n", fs::read_to_string(&legacy).unwrap().replacen(
                "#!/bin/sh\n", "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$0.calls\"\n", 1,
            ));
            fs::write(&legacy, &script).unwrap();
            fs::copy(&legacy, &canonical).unwrap();
            assert!(staged_version(&next.path, ID, &next.version.to_string()).is_ok());
            for path in [&canonical, &legacy] {
                assert_eq!(fs::read_to_string(path.with_extension("calls")).unwrap(), "build-info\n");
                fs::remove_file(path.with_extension("calls")).unwrap();
            }

            let python = runtime.join("Python");
            let original = fs::read(&python).unwrap();
            fs::write(&python, "damaged support").unwrap();
            assert!(staged_version(&next.path, ID, &next.version.to_string()).is_err());
            fs::write(&python, original).unwrap();
            let manifest = runtime.join("runtime.json");
            let original = fs::read(&manifest).unwrap();
            fs::remove_file(&manifest).unwrap();
            assert!(staged_version(&next.path, ID, &next.version.to_string()).is_err());
            fs::write(&manifest, original).unwrap();
            fs::write(&legacy, script.replace(&runtime_name, &format!("openaidr-runtime-{}", "b".repeat(64)))).unwrap();
            assert!(staged_version(&next.path, ID, &next.version.to_string()).is_err());
            fs::write(&legacy, &script).unwrap();
            for path in [&canonical, &legacy] {
                assert!(!path.with_extension("calls").exists(), "invalid support must fail before either alias runs");
            }

            let pending = Pending { app: old.path.clone(), staging,
                version: next.version.to_string(), previous: old.version.to_string(), build: next.build.clone() };
            let installed = resume(ID, &old, &pending).unwrap();
            assert_eq!(installed.version, next.version);
            assert!(staged_version(&installed.path, ID, &installed.version.to_string()).is_ok());
            assert_eq!(resume(ID, &installed, &pending).unwrap().version, next.version);
            assert!(validate_pending(&pending, &installed).unwrap().is_dir());
        }

        #[test]
        fn same_day_updates_bind_full_identity_and_resume_in_publication_order() {
            for (first, second) in [('f', 'a'), ('a', 'f')] {
                let scratch = tempfile::tempdir().unwrap();
                let root = scratch.path().canonicalize().unwrap();
                let operation = lock(&root).unwrap();
                let identity = installation_id(&root, &operation).unwrap();
                let old = calendar_fixture(&root.join("OpenAIDR.app"), first, 1791342000);
                let staging = root.join(".openaidr-update-calendar");
                let next = calendar_fixture(&staging.join("OpenAIDR.app"), second, 1791345600);
                assert!(staged_version(&next.path, ID, &next.version.to_string()).is_ok());
                assert!(staged_version(&next.path, ID, &old.version.to_string()).is_err());
                let pending = Pending { app: old.path.clone(), staging: staging.clone(),
                    version: next.version.to_string(), previous: old.version.to_string(), build: next.build.clone() };
                let installed = resume(ID, &old, &pending).unwrap();
                assert_eq!(installed.version, next.version);
                assert_eq!(resume(ID, &installed, &pending).unwrap().version, next.version);
                let rollback = Pending { app: installed.path.clone(), staging,
                    version: old.version.to_string(), previous: installed.version.to_string(), build: old.build.clone() };
                assert_eq!(resume(ID, &installed, &rollback).unwrap().version, next.version);
                assert_eq!(installation_id(&root, &operation).unwrap(), identity);
                let mut unknown = next.build.clone();
                unknown.as_object_mut().unwrap().remove("publication_timestamp");
                assert!(!crate::newer_build(&next.version.to_string(), &old.version.to_string(), &unknown, &old.build));
                let mut unknown = next.build.clone();
                unknown.as_object_mut().unwrap().remove("published_at");
                assert!(!crate::newer_build(&next.version.to_string(), &old.version.to_string(), &unknown, &old.build));
            }
        }

        #[test]
        fn bundle_id_migration_resumes_and_retires_only_known_app_backups() {
            for (before, after) in [(ID, "com.opensecura.openaidr"), ("com.opensecura.openaidr", ID)] {
                let scratch = tempfile::tempdir().unwrap();
                let root = scratch.path().canonicalize().unwrap();
                let operation = lock(&root).unwrap();
                let identity = installation_id(&root, &operation).unwrap();
                let change_id = |path: &Path, identifier: &str| {
                    let file = path.join("Contents/Info.plist");
                    let mut info: Dictionary = plist::from_file(&file).unwrap();
                    info.insert("CFBundleIdentifier".into(), identifier.into());
                    plist::to_file_xml(file, &info).unwrap();
                };
                let old = calendar_fixture(&root.join("OpenAIDR.app"), 'a', 1791342000);
                change_id(&old.path, before);
                let staging = root.join(".openaidr-update-identity");
                let next = calendar_fixture(&staging.join("OpenAIDR.app"), 'b', 1791345600);
                let pending = Pending { app: old.path.clone(), staging: staging.clone(),
                    version: next.version.to_string(), previous: old.version.to_string(), build: next.build.clone() };
                change_id(&next.path, "com.example.unrelated");
                assert!(staged_version(&next.path, before, &pending.version).is_err());
                assert!(resume(before, &old, &pending).is_err());
                assert_eq!(bundle(&old.path, before).unwrap().version, old.version);
                change_id(&next.path, after);
                assert!(staged_version(&next.path, before, &pending.version).is_ok());
                // Both the old running process and the restarted app can recover.
                let installed = resume(before, &old, &pending).unwrap();
                assert_eq!(resume(after, &installed, &pending).unwrap().version, next.version);
                assert_eq!(bundle(&installed.path, before).unwrap().version, next.version);
                assert!(bundle(&installed.path, "com.example.unrelated").is_err());
                let mut state = State { pending: Some(pending), ..State::default() };
                change_id(&next.path, "com.example.unrelated");
                assert!(complete(after, &installed, &root, &mut state).is_err());
                assert!(staging.exists());
                change_id(&next.path, before);
                complete(after, &installed, &root, &mut state).unwrap();
                assert!(!staging.exists());
                assert!(state.pending.is_none());
                assert_eq!(state.completed_version, next.version.to_string());
                assert_eq!(installation_id(&root, &operation).unwrap(), identity);
            }
        }

        #[test]
        fn attempts_survive_restarts_and_locks_serialize_processes() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let guard = lock(&root).unwrap();
            assert!(lock(&root).is_err());
            let mut state = State::default();
            assert!(due(state.attempted_at, 100_000, INTERVAL));
            state.attempted_at = Some(100_000);
            state.fail(&root, "offline".into());
            let reloaded = load(&root);
            assert!(!due(
                reloaded.attempted_at,
                100_000 + INTERVAL - 1,
                INTERVAL
            ));
            assert!(due(reloaded.attempted_at, 100_000 + INTERVAL, INTERVAL));
            assert!(due(reloaded.attempted_at, 99_000, INTERVAL));
            assert_eq!(reloaded.public()["state"], "error");
            assert!(reloaded.public().get("attempted_at").is_none());
            drop(guard);
            fs::write(root.join(JOURNAL), "invalid JSON").unwrap();
            assert!(due(load(&root).attempted_at, 100_000, INTERVAL));
            fs::remove_file(root.join("desktop-operation.lock")).unwrap();
            symlink(root.join(JOURNAL), root.join("desktop-operation.lock")).unwrap();
            assert!(lock(&root).is_err());
            assert_eq!(
                fs::read_to_string(root.join(JOURNAL)).unwrap(),
                "invalid JSON"
            );
        }

        #[test]
        fn pending_update_retries_a_busy_window_without_reopening() {
            use std::{future::Future, task::Poll};

            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let old = fixture(&root.join("OpenAIDR.app"), "0.1.0");
            let staging = root.join(".openaidr-update-test");
            fixture(&staging.join("OpenAIDR.app"), "0.2.0");
            let pending = Pending {
                app: old.path.clone(), staging: staging.clone(),
                version: "0.2.0".into(), previous: "0.1.0".into(),
                build: Value::Null,
            };
            let mut state = State::default();
            save_pending(&root, &mut state, pending.clone()).unwrap();
            let installed = resume(ID, &old, &pending).unwrap();
            state.set(&root, "restarting").unwrap();
            let saved = fs::read(root.join(JOURNAL)).unwrap();
            let window_operation = lock(&root).unwrap();
            tauri::async_runtime::block_on(async {
                // A busy window cannot cause an unbounded wait or remove recovery data.
                assert!(update_operation_lock(&root, Duration::ZERO).await.is_err());
                assert_eq!(fs::read(root.join(JOURNAL)).unwrap(), saved);
                assert!(staging.exists());
                let mut recovery = Box::pin(async {
                    let _operation = update_operation_lock(&root, OPERATION_WAIT).await?;
                    let next = resume(ID, &installed, &pending)?;
                    complete(ID, &next, &root, &mut state)
                });
                // Poll while a real flock is held, then let the ongoing request finish.
                std::future::poll_fn(|context| {
                    assert!(recovery.as_mut().poll(context).is_pending());
                    Poll::Ready(())
                }).await;
                assert_eq!(fs::read(root.join(JOURNAL)).unwrap(), saved);
                drop(window_operation);
                recovery.await.unwrap();
            });
            let completed = load(&root);
            assert_eq!(completed.state, "updated");
            assert_eq!(completed.completed_version, "0.2.0");
            assert!(completed.pending.is_none());
            assert!(completed.error.is_none());
            assert!(!staging.exists());
            assert_eq!(bundle(&installed.path, ID).unwrap().version.to_string(), "0.2.0");
        }

        #[test]
        fn waiting_update_honors_removal_and_rejects_lock_path_errors() {
            use std::{future::Future, task::Poll};

            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let window_operation = lock(&root).unwrap();
            tauri::async_runtime::block_on(async {
                let mut waiting = Box::pin(update_operation_lock(&root, OPERATION_WAIT));
                std::future::poll_fn(|context| {
                    assert!(waiting.as_mut().poll(context).is_pending());
                    Poll::Ready(())
                }).await;
                // Direct sensor removal can create the marker outside the native gate.
                fs::write(root.join("desktop-removal.json"), r#"{"state":"pending"}"#).unwrap();
                drop(window_operation);
                assert!(waiting.await.err().unwrap().contains("Removal was requested"));
                let operation = root.join("desktop-operation.lock");
                fs::remove_file(&operation).unwrap();
                symlink(root.join("desktop-removal.json"), operation).unwrap();
                let mut invalid = Box::pin(update_operation_lock(&root, OPERATION_WAIT));
                std::future::poll_fn(|context| {
                    assert!(matches!(invalid.as_mut().poll(context), Poll::Ready(Err(_))));
                    Poll::Ready(())
                }).await;
            });
        }

        #[test]
        fn transient_and_symbolic_installations_are_rejected() {
            let scratch = tempfile::tempdir().unwrap();
            let home = scratch.path().canonicalize().unwrap();
            let app = fixture(&home.join("Applications/OpenAIDR.app"), "0.1.0");
            installed_path(&app.path, &home).unwrap();
            assert!(installed_path(&home.join("build/OpenAIDR.app"), &home).is_err());
            assert!(installed_path(Path::new("/Volumes/Installer/OpenAIDR.app"), &home).is_err());
            let linked = home.join("Applications/Linked.app");
            symlink(&app.path, &linked).unwrap();
            assert!(installed_path(&linked, &home).is_err());
            assert!(bundle(&app.path, "another.application").is_err());
            fs::set_permissions(home.join("Applications"), fs::Permissions::from_mode(0o500))
                .unwrap();
            assert!(installed_path(&app.path, &home).is_err());
            fs::set_permissions(home.join("Applications"), fs::Permissions::from_mode(0o700))
                .unwrap();
        }

        #[test]
        fn interrupted_exchange_resumes_and_failed_exchange_keeps_the_app() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let old = fixture(&root.join("OpenAIDR.app"), "0.1.0");
            let staging = root.join(".openaidr-update-test");
            let next = fixture(&staging.join("OpenAIDR.app"), "0.2.0");
            let pending = Pending {
                app: old.path.clone(),
                staging,
                version: "0.2.0".into(),
                previous: "0.1.0".into(),
                build: Value::Null,
            };
            // A crash after saving the journal but before replacement resumes.
            let installed = resume(ID, &old, &pending).unwrap();
            assert_eq!(installed.version.to_string(), "0.2.0");
            assert_eq!(bundle(&next.path, ID).unwrap().version.to_string(), "0.1.0");
            // A crash after replacement does not exchange the old app back in.
            assert_eq!(
                resume(ID, &installed, &pending)
                    .unwrap()
                    .version
                    .to_string(),
                "0.2.0"
            );
            assert!(swap(&installed.path, &root.join("missing.app")).is_err());
            assert_eq!(
                bundle(&installed.path, ID).unwrap().version.to_string(),
                "0.2.0"
            );
            let mut unrelated = pending.clone();
            unrelated.staging = root.join("unrelated");
            assert!(resume(ID, &installed, &unrelated).is_err());
            // Recovery can restore the retained complete app atomically.
            swap(&installed.path, &next.path).unwrap();
            assert_eq!(
                bundle(&installed.path, ID).unwrap().version.to_string(),
                "0.1.0"
            );
        }

        #[test]
        fn corrective_releases_and_manual_newer_apps_retire_pending_recovery_safely() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let old = fixture(&root.join("OpenAIDR.app"), "0.1.0");
            let pending = |version: &str, previous: &str| {
                let staging = root.join(format!(".openaidr-update-{version}"));
                fixture(&staging.join("OpenAIDR.app"), version);
                Pending {
                    app: old.path.clone(),
                    staging,
                    version: version.into(),
                    previous: previous.into(),
                    build: Value::Null,
                }
            };
            let first = pending("0.2.0", "0.1.0");
            let mut state = State::default();
            state.attempted_at = Some(10_000);
            save_pending(&root, &mut state, first.clone()).unwrap();
            let broken = resume(ID, &old, &first).unwrap();
            state.fail(&root, "sensor handoff failed".into());
            let mut state = load(&root);
            assert!(!due(state.attempted_at, 10_001, INTERVAL));
            assert!(due(state.attempted_at, 10_000 + INTERVAL, INTERVAL));

            // A corrective release retains both complete earlier apps while
            // its own sensor handoff is pending, including after a restart.
            let correction = pending("0.3.0", "0.2.0");
            save_pending(&root, &mut state, correction.clone()).unwrap();
            let corrected = resume(ID, &broken, &correction).unwrap();
            let mut state = load(&root);
            assert_eq!(state.retained.len(), 1);
            assert_eq!(
                bundle(&retained_path(&first, &corrected, ID).unwrap(), ID)
                    .unwrap()
                    .version
                    .to_string(),
                "0.1.0"
            );
            assert_eq!(
                bundle(&retained_path(&correction, &corrected, ID).unwrap(), ID)
                    .unwrap()
                    .version
                    .to_string(),
                "0.2.0"
            );
            let unrelated = first.staging.join("user-note.txt");
            fs::write(&unrelated, "keep this file").unwrap();
            complete(ID, &corrected, &root, &mut state).unwrap();
            assert_eq!(fs::read_to_string(&unrelated).unwrap(), "keep this file");
            assert!(!first.staging.join("OpenAIDR.app").exists());
            assert!(!correction.staging.exists());
            assert!(load(&root).pending.is_none());
            assert!(load(&root).retained.is_empty());
            assert_eq!(load(&root).completed_version, "0.3.0");

            // The installed bundle is re-read even when the caller's snapshot
            // predates a newer manual installation.
            let awaiting = pending("0.4.0", "0.3.0");
            save_pending(&root, &mut state, awaiting.clone()).unwrap();
            fixture(&corrected.path, "0.5.0");
            // A broken sensor must not stop this newer installed app from
            // checking the feed for its own repair. Finish still validates it.
            fs::write(
                corrected.path.join("Contents/MacOS/openaidr-sensor"),
                "#!/bin/sh\nexit 1\n",
            )
            .unwrap();
            let manual = resume(ID, &corrected, &awaiting).unwrap();
            assert_eq!(manual.version.to_string(), "0.5.0");
            assert!(staged_version(&manual.path, ID, "0.5.0").is_err());
            fixture(&manual.path, "0.5.0");
            assert_eq!(
                bundle(&awaiting.staging.join("OpenAIDR.app"), ID)
                    .unwrap()
                    .version
                    .to_string(),
                "0.4.0"
            );
            // Unexpected contents are not removed during recovery cleanup.
            fixture(&awaiting.staging.join("OpenAIDR.app"), "0.9.0");
            assert!(complete(ID, &manual, &root, &mut state).is_err());
            assert!(load(&root).pending.is_some());
            fixture(&awaiting.staging.join("OpenAIDR.app"), "0.4.0");
            complete(ID, &manual, &root, &mut state).unwrap();
            assert_eq!(load(&root).completed_version, "0.5.0");
            assert_eq!(
                bundle(&manual.path, ID).unwrap().version.to_string(),
                "0.5.0"
            );
        }

        #[test]
        fn sensor_handoff_verifies_health_and_preserves_unmanaged_services() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let executable = root.join("sensor");
            fs::write(&executable, "#!/bin/sh\nIFS= read -r request\nprintf '%s\\n' \"$request\" >> \"$0.calls\"\ncase \"$request\" in\n*desktop.update.setup*) /bin/cat \"$0.setup\" ;;\n*) /bin/cat \"$0.status\" ;;\nesac\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
            let healthy = json!({"enrolled":true,"running":true,"service_version":"0.2.0","telemetry":{"enabled":true}});
            let write_status = |data: &Value| {
                fs::write(
                    root.join("sensor.status"),
                    serde_json::to_vec(&json!({"ok":true,"data":data})).unwrap(),
                )
                .unwrap()
            };
            fs::write(
                root.join("sensor.setup"),
                r#"{"ok":true,"data":{"steps":[{"step":"service.restart","ok":true}]}}"#,
            )
            .unwrap();
            write_status(&healthy);
            finish_sensor(&executable, "0.2.0", Duration::ZERO).unwrap();
            let calls = fs::read_to_string(root.join("sensor.calls")).unwrap();
            assert_eq!(calls.lines().count(), 3);
            assert_eq!(calls.matches("desktop.update.setup").count(), 1);
            let mut telemetry_disabled = healthy.clone();
            telemetry_disabled["telemetry"] = json!({"enabled":false});
            write_status(&telemetry_disabled);
            fs::write(root.join("sensor.calls"), "").unwrap();
            finish_sensor(&executable, "0.2.0", Duration::ZERO).unwrap();
            let calls = fs::read_to_string(root.join("sensor.calls")).unwrap();
            assert_eq!(calls.lines().count(), 3);
            assert_eq!(calls.matches("desktop.update.setup").count(), 1);
            for (field, value) in [
                ("enrolled", json!(false)),
                ("foreground", json!(true)),
            ] {
                let mut preserved = healthy.clone();
                preserved[field] = value;
                preserved["running"] = json!(false);
                write_status(&preserved);
                fs::write(root.join("sensor.calls"), "").unwrap();
                finish_sensor(&executable, "0.2.0", Duration::ZERO).unwrap();
                let calls = fs::read_to_string(root.join("sensor.calls")).unwrap();
                assert_eq!(calls.lines().count(), 1, "{field}");
                assert!(!calls.contains("desktop.update.setup"), "{field}");
            }
            let mut unhealthy = healthy.clone();
            unhealthy["service_version"] = json!("0.1.0");
            for newer in [false, true] {
                unhealthy["service_newer"] = json!(newer);
                write_status(&unhealthy);
                assert!(finish_sensor(&executable, "0.2.0", Duration::ZERO).is_err());
            }
            write_status(&healthy);
            fs::write(
                root.join("sensor.setup"),
                r#"{"ok":false,"error":"private-token"}"#,
            )
            .unwrap();
            let error = finish_sensor(&executable, "0.2.0", Duration::ZERO).unwrap_err();
            assert!(!error.contains("private-token"));
        }

        struct ReleaseServer {
            endpoint: String,
            manifest: Arc<Mutex<Value>>,
            requests: Arc<Mutex<Vec<String>>>,
            tampered: Arc<AtomicBool>,
            announce_length: Arc<AtomicBool>,
            pause_download: Arc<AtomicBool>,
            disconnect: Arc<AtomicBool>,
            status: Arc<Mutex<u16>>,
            stop: Arc<AtomicBool>,
            worker: Option<thread::JoinHandle<()>>,
        }

        impl ReleaseServer {
            fn start() -> Self {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let origin = format!("http://{}", listener.local_addr().unwrap());
                let endpoint = format!("{origin}/rollout-v2.json");
                let manifest = Arc::new(Mutex::new(json!({
                    "version": "0.2.0",
                    "platforms": { tauri_plugin_updater::target().unwrap(): {
                        "url": format!("{origin}/OpenAIDR.app.tar.gz"),
                        "signature": SIGNATURE,
                    }},
                })));
                let requests = Arc::new(Mutex::new(Vec::new()));
                let bytes = STANDARD.decode(ARCHIVE).unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                let tampered = Arc::new(AtomicBool::new(false));
                let announce_length = Arc::new(AtomicBool::new(true));
                let pause_download = Arc::new(AtomicBool::new(false));
                let disconnect = Arc::new(AtomicBool::new(false));
                let status = Arc::new(Mutex::new(200));
                let quit = stop.clone();
                let corrupt = tampered.clone();
                let announced = announce_length.clone();
                let paused = pause_download.clone();
                let disconnected = disconnect.clone();
                let response_status = status.clone();
                let feed = manifest.clone();
                let received = requests.clone();
                let worker = thread::spawn(move || {
                    while !quit.load(Ordering::Relaxed) {
                        let (mut stream, _) = match listener.accept() {
                            Ok(connection) => connection,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(1));
                                continue;
                            }
                            Err(error) => panic!("test listener: {error}"),
                        };
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut byte = [0u8];
                        while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
                            if stream.read(&mut byte).unwrap_or(0) == 0 {
                                break;
                            }
                            request.push(byte[0]);
                        }
                        let request = String::from_utf8(request).unwrap();
                        let target = request
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .to_string();
                        received.lock().unwrap().push(request);
                        if disconnected.load(Ordering::Relaxed) { continue; }
                        let manifest_request = target == "/rollout-v2.json";
                        assert!(
                            manifest_request || target.ends_with("/OpenAIDR.app.tar.gz"),
                            "unexpected test request {target:?}"
                        );
                        let mut body = if manifest_request {
                            serde_json::to_vec(&*feed.lock().unwrap()).unwrap()
                        } else {
                            bytes.clone()
                        };
                        if !manifest_request && corrupt.load(Ordering::Relaxed) {
                            body[20] ^= 1;
                        }
                        write!(stream, "HTTP/1.1 {} Response\r\nConnection: close\r\n", response_status.lock().unwrap()).unwrap();
                        if manifest_request || announced.load(Ordering::Relaxed) {
                            write!(stream, "Content-Length: {}\r\n", body.len()).unwrap();
                        }
                        stream.write_all(b"\r\n").unwrap();
                        if !manifest_request && paused.load(Ordering::Relaxed) {
                            let half = body.len() / 2;
                            stream.write_all(&body[..half]).unwrap();
                            stream.flush().unwrap();
                            while paused.load(Ordering::Relaxed) && !quit.load(Ordering::Relaxed) {
                                thread::sleep(Duration::from_millis(1));
                            }
                            let _ = stream.write_all(&body[half..]);
                        } else {
                            stream.write_all(&body).unwrap();
                        }
                    }
                });
                Self {
                    endpoint,
                    manifest,
                    requests,
                    tampered,
                    announce_length,
                    pause_download,
                    disconnect,
                    status,
                    stop,
                    worker: Some(worker),
                }
            }
        }

        impl Drop for ReleaseServer {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                let _ = self.worker.take().unwrap().join();
            }
        }

        #[test]
        fn release_check_connection_warnings_persist_and_clear_without_hiding_invalid_metadata() {
            let server = ReleaseServer::start();
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.config_mut().plugins.0.insert("updater".into(), json!({
                "pubkey": PUBLIC_KEY, "dangerousInsecureTransportProtocol": true,
            }));
            let app = tauri::test::mock_builder().plugin(tauri_plugin_updater::Builder::new().build())
                .build(context).unwrap();
            tauri::async_runtime::block_on(async {
                let updater = app.updater_builder().no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()]).unwrap()
                    .version_comparator(|_, _| false)
                    .executable_path(root.join("OpenAIDR.app/Contents/MacOS/openaidr-desktop"))
                    .timeout(Duration::from_secs(3)).build().unwrap();
                let mut state = State::default();
                for disconnected in [true, false] {
                    server.disconnect.store(disconnected, Ordering::Relaxed);
                    *server.status.lock().unwrap() = 503;
                    state.set(&root, "checking").unwrap();
                    let error = state.check_health.check(&updater, timestamp()).await.err().unwrap();
                    state.fail(&root, error);
                    state = read_state(&root).unwrap();
                    assert_eq!(state.public()["warning_deferred"], true);
                }
                *server.status.lock().unwrap() = 200;
                server.manifest.lock().unwrap()["version"] = json!("invalid");
                let error = state.check_health.check(&updater, timestamp()).await.err().unwrap();
                state.fail(&root, error);
                assert_ne!(read_status(&root).unwrap()["warning_deferred"], true);
                *server.status.lock().unwrap() = 503;
                let error = state.check_health.check(&updater, timestamp() - 24 * 60 * 60 - 1).await.err().unwrap();
                state.fail(&root, error);
                assert_ne!(read_status(&root).unwrap()["warning_deferred"], true);
                *server.status.lock().unwrap() = 200;
                server.manifest.lock().unwrap()["version"] = json!("0.2.0");
                assert!(state.check_health.check(&updater, timestamp()).await.unwrap().is_none());
                state.set(&root, "idle").unwrap();
                assert_eq!(read_status(&root).unwrap()["state"], "idle");
                *server.status.lock().unwrap() = 503;
                let error = state.check_health.check(&updater, timestamp()).await.err().unwrap();
                state.fail(&root, error);
                assert_eq!(read_status(&root).unwrap()["warning_deferred"], true);
            });
            assert!(server.requests.lock().unwrap().iter().all(|request| request.starts_with("GET /rollout-v2.json ")));
        }

        #[test]
        fn rollout_gate_defers_without_archive_requests_and_verifies_eligible_downloads() {
            let server = ReleaseServer::start();
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let id = "0123456789abcdef0123456789abcdef";
            fs::write(root.join(INSTALLATION_ID), id).unwrap();
            fs::set_permissions(root.join(INSTALLATION_ID), fs::Permissions::from_mode(0o600)).unwrap();
            let policy = json!({"schema_version": 1, "starts_at": "2026-10-16T16:00:00Z", "paused": false,
                "steps": [{"after_hours": 0, "percent": 1}, {"after_hours": 24, "percent": 100}]});
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.config_mut().plugins.0.insert("updater".into(), json!({
                "pubkey": PUBLIC_KEY, "dangerousInsecureTransportProtocol": true,
            }));
            let app = tauri::test::mock_builder().plugin(tauri_plugin_updater::Builder::new().build())
                .build(context).unwrap();
            let archive_requests = || server.requests.lock().unwrap().iter()
                .filter(|request| request.starts_with("GET /OpenAIDR.app.tar.gz ")).count();
            tauri::async_runtime::block_on(async {
                let updater = app.updater_builder().no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()]).unwrap()
                    .version_comparator(|_, _| true)
                    .executable_path(root.join("OpenAIDR.app/Contents/MacOS/openaidr-desktop"))
                    .timeout(Duration::from_secs(3)).build().unwrap();
                let mut state = State::default();
                for case in ["excluded", "zero", "future", "paused", "missing", "unsupported", "invalid", "identity"] {
                    let mut rollout = policy.clone();
                    match case {
                        "zero" => rollout["steps"][0]["percent"] = json!(0),
                        "future" => rollout["starts_at"] = json!("2026-10-17T16:00:00Z"),
                        "paused" => { rollout["paused"] = json!(true); rollout["steps"][0]["percent"] = json!(100); }
                        "missing" => rollout = Value::Null,
                        "unsupported" => rollout["schema_version"] = json!(2),
                        "invalid" => rollout["steps"][0]["percent"] = json!(1.0),
                        "identity" => {
                            rollout["steps"][0]["percent"] = json!(100);
                            fs::write(root.join(INSTALLATION_ID), "invalid").unwrap();
                        }
                        _ => {}
                    }
                    {
                        let mut manifest = server.manifest.lock().unwrap();
                        manifest["version"] = json!("2026.10.6+8d5b065");
                        manifest["rollout"] = rollout;
                    }
                    let update = updater.check().await.unwrap().unwrap();
                    state.set(&root, "checking").unwrap();
                    let result = download_if_eligible(&update, &root, &mut state, 1792166400, PUBLIC_KEY).await;
                    if ["missing", "unsupported", "invalid", "identity"].contains(&case) {
                        assert!(result.is_err(), "{case}");
                    } else {
                        assert!(result.unwrap().is_none(), "{case}");
                        assert_eq!(read_status(&root).unwrap()["state"], "idle");
                    }
                    assert_eq!(archive_requests(), 0, "{case}");
                }
                fs::write(root.join(INSTALLATION_ID), id).unwrap();
                let mut rollout = policy;
                rollout["steps"][0]["percent"] = json!(25);
                server.manifest.lock().unwrap()["rollout"] = rollout;
                let update = updater.check().await.unwrap().unwrap();
                let bytes = download_if_eligible(&update, &root, &mut state, 1792166400, PUBLIC_KEY).await.unwrap().unwrap();
                assert_eq!(fs::read(bytes.path()).unwrap(), STANDARD.decode(ARCHIVE).unwrap());
                assert_eq!(archive_requests(), 1);
                assert_eq!(fs::read_to_string(root.join(INSTALLATION_ID)).unwrap(), id);
                assert!(lock(&root).is_ok());
                server.tampered.store(true, Ordering::Relaxed);
                assert!(download_if_eligible(&update, &root, &mut state, 1792166400, PUBLIC_KEY).await.is_err());
                assert_eq!(archive_requests(), 2);
                server.manifest.lock().unwrap()["platforms"] = json!({});
                assert!(updater.check().await.is_err());
                assert_eq!(archive_requests(), 2);
            });
            let requests = server.requests.lock().unwrap();
            assert_eq!(requests.iter().filter(|request| request.starts_with("GET /rollout-v2.json ")).count(), 10);
            assert!(requests.iter().all(|request| !request.contains(id) && !request.contains("latest.json")));
        }

        #[test]
        fn manual_checks_do_not_download_and_install_requires_the_selected_signed_release() {
            let server = ReleaseServer::start();
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.config_mut().plugins.0.insert("updater".into(), json!({
                "pubkey": PUBLIC_KEY, "dangerousInsecureTransportProtocol": true,
            }));
            let app = tauri::test::mock_builder().plugin(tauri_plugin_updater::Builder::new().build())
                .build(context).unwrap();
            server.manifest.lock().unwrap()["rollout"] = json!({
                "schema_version":1,"starts_at":"2099-01-01T00:00:00Z","paused":true,
                "steps":[{"after_hours":0,"percent":100}],
            });
            tauri::async_runtime::block_on(async {
                let updater = app.updater_builder().no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()]).unwrap()
                    .executable_path(root.join("OpenAIDR.app/Contents/MacOS/openaidr-desktop"))
                    .timeout(Duration::from_secs(3)).build().unwrap();
                let update = updater.check().await.unwrap().unwrap();
                let mut state = State::default();
                assert!(!prepare_download(&update, &root, &mut state, 0, Intent::Check).await.unwrap());
                assert_eq!(read_status(&root).unwrap()["state"], "available");
                assert_eq!(state.latest, update.version);
                assert!(prepare_download(&update, &root, &mut state, 0, Intent::Install("0.3.0")).await.is_err());
                assert_eq!(server.requests.lock().unwrap().len(), 1, "Only the manifest was requested");
                // Explicit installation has the same availability as manual downloads,
                // independently of automatic rollout eligibility, but still verifies signatures.
                assert!(prepare_download(&update, &root, &mut state, 0, Intent::Install(&update.version)).await.unwrap());
                let task = ManualTask::default();
                let bytes = task.run(download(&update, &root, &mut state, PUBLIC_KEY)).await.unwrap();
                assert_eq!(fs::read(bytes.path()).unwrap(), STANDARD.decode(ARCHIVE).unwrap());
                task.begin_install().unwrap();
                assert!(task.cancel().is_err(), "Installation cannot be cancelled after the boundary");
                server.tampered.store(true, Ordering::Relaxed);
                assert!(download(&update, &root, &mut state, PUBLIC_KEY).await.unwrap_err().contains("signature"));
                server.manifest.lock().unwrap()["rollout"] = Value::Null;
                let invalid = updater.check().await.unwrap().unwrap();
                assert!(prepare_download(&invalid, &root, &mut state, 0, Intent::Check).await.is_err());
                assert!(prepare_download(&invalid, &root, &mut state, 0, Intent::Install(&invalid.version)).await.is_err());
            });
        }

        #[test]
        fn manual_cancellation_stops_a_download_and_prevents_installation() {
            let server = ReleaseServer::start();
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.config_mut().plugins.0.insert("updater".into(), json!({
                "pubkey": PUBLIC_KEY, "dangerousInsecureTransportProtocol": true,
            }));
            let app = tauri::test::mock_builder().plugin(tauri_plugin_updater::Builder::new().build())
                .build(context).unwrap();
            tauri::async_runtime::block_on(async {
                let updater = app.updater_builder().no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()]).unwrap()
                    .executable_path(root.join("OpenAIDR.app/Contents/MacOS/openaidr-desktop"))
                    .timeout(Duration::from_secs(3)).build().unwrap();
                let update = updater.check().await.unwrap().unwrap();
                let task = ManualTask::default();
                let mut state = State::default();
                state.set(&root, "downloading").unwrap();
                server.pause_download.store(true, Ordering::Relaxed);
                let cancel = async {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        while read_status(&root).unwrap()["downloaded_bytes"].as_u64().unwrap_or(0) == 0 {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }).await.unwrap();
                    task.cancel().unwrap();
                };
                let (result, ()) = tokio::join!(task.run(download(&update, &root, &mut state, PUBLIC_KEY)), cancel);
                assert!(result.unwrap_err().contains("cancelled"));
                assert!(task.begin_install().is_err());
                assert!(task.run::<()>(async { panic!("A cancelled check must not start") }).await.is_err());
                assert!(state.pending.is_none());
                server.pause_download.store(false, Ordering::Relaxed);
            });
        }

        #[test]
        fn update_status_reads_old_journals_and_rejects_invalid_files_without_waiting() {
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let path = root.join(JOURNAL);
            assert_eq!(read_status(&root).unwrap()["state"], "idle");
            fs::write(&path, br#"{"state":"downloading","latest":"0.2.0"}"#).unwrap();
            let legacy = read_status(&root).unwrap();
            assert_eq!(legacy["state"], "downloading");
            assert!(legacy.get("downloaded_bytes").is_none());
            assert!(legacy.get("total_bytes").is_none());
            let mut state = load(&root);
            state.recover_interrupted_check(&root);
            assert_eq!(read_status(&root).unwrap()["state"], "error");
            assert!(read_status(&root).unwrap()["error"].as_str().unwrap().contains("interrupted"));
            for phase in ["checking", "installing", "restarting", "updated", "idle"] {
                state.downloaded_bytes = Some(123);
                state.total_bytes = Some(456);
                state.set(&root, phase).unwrap();
                let saved = load(&root);
                assert!(saved.downloaded_bytes.is_none());
                assert!(saved.total_bytes.is_none());
                assert!(saved.public().get("downloaded_bytes").is_none());
            }
            state.downloaded_bytes = Some(123);
            state.total_bytes = Some(456);
            state.fail(&root, "test error".into());
            assert!(load(&root).downloaded_bytes.is_none());
            assert!(load(&root).total_bytes.is_none());
            for invalid in [b"invalid JSON".to_vec(), vec![b' '; 64 * 1024 + 1]] {
                fs::write(&path, invalid).unwrap();
                assert!(read_status(&root).is_err());
                assert_eq!(load(&root).public()["state"], "idle");
            }
            fs::remove_file(&path).unwrap();
            let pipe = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
            assert!(read_status(&root).is_err());
        }

        #[test]
        fn signed_download_progress_is_visible_during_transfer_without_operation_locks() {
            let server = ReleaseServer::start();
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            let _operation = lock(&root).unwrap();
            let _updater = lock_file(&root, "desktop-updater.lock").unwrap();
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.config_mut().plugins.0.insert("updater".into(), json!({
                "pubkey": PUBLIC_KEY, "dangerousInsecureTransportProtocol": true,
            }));
            let app = tauri::test::mock_builder()
                .plugin(tauri_plugin_updater::Builder::new().build())
                .build(context).unwrap();
            tauri::async_runtime::block_on(async {
                let updater = app.updater_builder().no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()]).unwrap()
                    .executable_path(root.join("OpenAIDR.app/Contents/MacOS/openaidr-desktop"))
                    .timeout(Duration::from_secs(10)).build().unwrap();
                let update = updater.check().await.unwrap().unwrap();
                let size = STANDARD.decode(ARCHIVE).unwrap().len() as u64;
                let mut state = State::default();
                for announced in [true, false] {
                    state.set(&root, "downloading").unwrap();
                    server.announce_length.store(announced, Ordering::Relaxed);
                    server.pause_download.store(true, Ordering::Relaxed);
                    let observe = async {
                        tokio::time::timeout(Duration::from_secs(5), async {
                            loop {
                                let progress = read_status(&root).unwrap();
                                if let Some(downloaded) = progress["downloaded_bytes"].as_u64().filter(|value| *value > 0) {
                                    assert!(downloaded < size);
                                    assert_eq!(progress["state"], "downloading");
                                    assert_eq!(progress["total_bytes"].as_u64(), if announced { Some(size) } else { None });
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                        }).await.unwrap();
                        server.pause_download.store(false, Ordering::Relaxed);
                    };
                    let (bytes, ()) = tokio::join!(download(&update, &root, &mut state, PUBLIC_KEY), observe);
                    assert_eq!(bytes.unwrap().as_file().metadata().unwrap().len(), size);
                    assert_eq!(state.downloaded_bytes, Some(size));
                    state.set(&root, "installing").unwrap();
                    assert!(read_status(&root).unwrap().get("downloaded_bytes").is_none());
                }
                // Progress-only persistence failures do not reject a valid signed archive.
                let unwritable = root.join("invalid-journal");
                fs::create_dir_all(unwritable.join(JOURNAL)).unwrap();
                state.set(&root, "downloading").unwrap();
                assert_eq!(download(&update, &unwritable, &mut state, PUBLIC_KEY).await.unwrap().as_file().metadata().unwrap().len(), size);
                server.tampered.store(true, Ordering::Relaxed);
                let error = download(&update, &root, &mut state, PUBLIC_KEY).await.unwrap_err();
                state.fail(&root, error);
                let failed = read_status(&root).unwrap();
                assert_eq!(failed["state"], "error");
                assert!(failed.get("downloaded_bytes").is_none());
                assert!(failed.get("total_bytes").is_none());
            });
        }

        #[test]
        fn renamed_signed_app_updates_legacy_install_and_rejects_tampering_or_version_mismatch() {
            let server = ReleaseServer::start();
            let scratch = tempfile::tempdir().unwrap();
            let root = scratch.path().canonicalize().unwrap();
            // An update replaces contents at the legacy path without moving the app.
            let current = fixture(&root.join("OpenAIDR Sensor.app"), "0.1.0");
            let stage = root.join(".openaidr-update-test/OpenAIDR Sensor.app");
            fs::create_dir_all(&stage).unwrap();
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.config_mut().plugins.0.insert(
                "updater".into(),
                json!({
                    "pubkey": PUBLIC_KEY,
                    "dangerousInsecureTransportProtocol": true,
                }),
            );
            let app = tauri::test::mock_builder()
                .plugin(tauri_plugin_updater::Builder::new().build())
                .build(context)
                .unwrap();
            tauri::async_runtime::block_on(async {
                let updater = app
                    .updater_builder()
                    .no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()])
                    .unwrap()
                    .executable_path(stage.join("Contents/MacOS/openaidr-desktop"))
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap();
                let update = updater.check().await.unwrap().unwrap();
                let mut state = State::default();
                state.set(&root, "downloading").unwrap();
                let mut file = download(&update, &root, &mut state, PUBLIC_KEY).await.unwrap();
                unpack(file.as_file_mut(), &stage).unwrap();
                staged_version(&stage, ID, "0.2.0").unwrap();
                let info = plist::Value::from_file(stage.join("Contents/Info.plist")).unwrap();
                let info = info.as_dictionary().unwrap();
                for key in ["CFBundleName", "CFBundleDisplayName"] {
                    assert_eq!(info[key].as_string(), Some("OpenAIDR"));
                }
                assert!(staged_version(&stage, ID, "0.3.0").is_err());
                swap(&current.path, &stage).unwrap();
                assert_eq!(
                    bundle(&current.path, ID).unwrap().version.to_string(),
                    "0.2.0"
                );
                assert_eq!(bundle(&stage, ID).unwrap().version.to_string(), "0.1.0");
                server.tampered.store(true, Ordering::Relaxed);
                assert!(download(&update, &root, &mut state, PUBLIC_KEY).await.is_err());
                assert_eq!(
                    bundle(&current.path, ID).unwrap().version.to_string(),
                    "0.2.0"
                );
                // A stale running GUI compares with the installed bundle,
                // so it cannot download and reinstall the same release.
                let installed = bundle(&current.path, ID).unwrap().version;
                let updater = app
                    .updater_builder()
                    .no_proxy()
                    .endpoints(vec![server.endpoint.parse().unwrap()])
                    .unwrap()
                    .executable_path(stage.join("Contents/MacOS/openaidr-desktop"))
                    .version_comparator(move |_, remote| remote.version > installed)
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap();
                assert!(updater.check().await.unwrap().is_none());
            });
            let wrong_sensor = current.path.join("Contents/MacOS/openaidr-sensor");
            fs::write(
                wrong_sensor,
                "#!/bin/sh\nprintf 'openaidr-sensor 0.1.0\\n'\n",
            )
            .unwrap();
            assert!(staged_version(&current.path, ID, "0.2.0").is_err());
        }
    }
}
