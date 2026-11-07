//! Per-user Windows rollout checks and signed installer recovery.

use super::{Mode, manual_update::{Intent, ManualTask}};
pub use super::manual_update::ManualUpdate;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::Path, sync::{Arc, atomic::Ordering}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tauri::{AppHandle, Config, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

#[path = "../signed_release.rs"]
mod release;
#[path = "update_storage.rs"]
mod update_storage;
#[path = "update_worker.rs"]
mod update_worker;
#[path = "update_layout.rs"]
mod update_layout;
use update_storage as storage;
pub use storage::OperationLock;

const ENDPOINT: &str = crate::platform::RELEASE_FEED;
const JOURNAL: &str = "desktop-update.json";
const MAX_DOWNLOAD: u64 = 1024 * 1024 * 1024;
const INTERVAL: u64 = 3 * 60 * 60;
const WAKE: u64 = 5 * 60;
const LOCK_WAIT: Duration = Duration::from_secs(180);

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct State {
    state: String,
    latest: String,
    error: Option<String>,
    downloaded_bytes: Option<u64>,
    total_bytes: Option<u64>,
    attempted_at: Option<u64>,
    check_health: super::update_check::CheckHealth,
    pending: Option<Pending>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Pending {
    release: release::Release,
    previous: Value,
    reopen_window: bool,
    #[serde(default)]
    install_started: bool,
    #[serde(default)]
    manual: bool,
}

impl State {
    fn public(&self) -> Value {
        let mut value = json!({"state":if self.state.is_empty() { "idle" } else { &self.state },
            "latest":self.latest, "error":self.error});
        if self.state == "error" && self.check_health.warning_deferred(self.error.as_deref(), timestamp()) {
            value["warning_deferred"] = json!(true);
        }
        if self.state == "downloading" {
            value["downloaded_bytes"] = json!(self.downloaded_bytes);
            value["total_bytes"] = json!(self.total_bytes);
        }
        value
    }

    fn set(&mut self, directory: &Path, phase: &str) -> Result<(), String> {
        self.state = phase.into();
        self.error = None;
        self.downloaded_bytes = None;
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
}

fn load(directory: &Path) -> Result<State, String> {
    storage::json_file(&directory.join(JOURNAL))?.map(serde_json::from_value).transpose()
        .map(|state| state.unwrap_or_default()).map_err(|_| "Cannot read the saved update state.".into())
}

fn read_state(directory: &Path) -> Result<State, String> {
    match storage::lock(directory, "updater.lock") {
        Ok(_guard) => {
            let mut state = load(directory)?;
            if state.pending.is_none() && matches!(state.state.as_str(), "checking" | "downloading" | "installing") {
                state.fail(directory, "The previous update was interrupted. Check for updates to try again.".into());
            }
            Ok(state)
        },
        Err(error) if error == storage::BUSY => load(directory),
        Err(error) => Err(error),
    }
}

fn save(directory: &Path, state: &State) -> Result<(), String> {
    storage::write(&directory.join(JOURNAL), &serde_json::to_vec(state).map_err(|_| "Cannot prepare update state.")?)
}

fn current_build() -> Value {
    serde_json::from_str(env!("OPENAIDR_BUILD_INFO")).unwrap_or(Value::Null)
}

fn key() -> String {
    STANDARD.encode(crate::platform::UPDATER_PUBLIC_KEY)
}

fn timestamp() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

fn due(attempted: Option<u64>, now: u64) -> bool {
    attempted.map_or(true, |last| now < last || now - last >= INTERVAL)
}

pub fn enabled(config: &Config) -> bool {
    !cfg!(debug_assertions) && config.plugins.0.get("updater").and_then(|v| v["pubkey"].as_str())
        .and_then(|text| STANDARD.decode(text).ok())
        .is_some_and(|bytes| String::from_utf8_lossy(&bytes).trim() == String::from_utf8_lossy(&STANDARD.decode(key()).unwrap()).trim())
}

pub fn operation_lock(app: &AppHandle) -> Result<OperationLock, String> {
    storage::lock(&storage::directory(app)?, "operation.lock")
}

pub fn status(app: &AppHandle) -> Option<Value> {
    read_status(app).ok().flatten()
}

pub fn read_status(app: &AppHandle) -> Result<Option<Value>, String> {
    if !enabled(app.config()) { return Ok(None); }
    Ok(Some(read_state(&storage::directory(app)?)?.public()))
}

pub fn cancel(app: &AppHandle) -> Result<Value, String> {
    let manual = app.state::<ManualUpdate>();
    let active = manual.0.lock().map_err(|_| "Cannot cancel the update.")?;
    active.as_ref().ok_or("There is no cancellable update running.")?.cancel()?;
    Ok(Value::Null)
}

pub async fn manual(app: &AppHandle, version: Option<String>) -> Result<Value, String> {
    if !enabled(app.config()) {
        return Ok(json!({"state":"unavailable", "latest":"",
            "error":"This build does not support in-app updates. Install an OpenAIDR release with update support."}));
    }
    let manual = app.state::<ManualUpdate>();
    let task = Arc::new(ManualTask::default());
    {
        let mut active = manual.0.lock().map_err(|_| storage::BUSY)?;
        if active.is_some() { return Err(storage::BUSY.into()); }
        *active = Some(task.clone());
    }
    let result = async {
        let directory = storage::directory(app)?;
        let Some((_guard, operation)) = manual_locks(&directory, &task, LOCK_WAIT).await? else {
            return Ok(State { latest:app.package_info().version.to_string(), ..State::default() }.public());
        };
        if directory.join("removed").exists() {
            return Err("OpenAIDR was uninstalled. Install it again before updating.".into());
        }
        let mut state = load(&directory)?;
        if state.pending.is_some() {
            return Err("Reopen OpenAIDR to finish the pending update before checking again.".into());
        }
        if let Err(error) = update_worker::register(&directory,
            &std::env::current_exe().map_err(|_| "Cannot locate OpenAIDR.")?) {
            return Ok(json!({"state":"unavailable", "latest":"", "error":error}));
        }
        drop(operation);
        let intent = version.as_deref().map_or(Intent::Check, Intent::Install);
        let result = check(app, &directory, &mut state, Mode::Window, intent, Some(&task)).await;
        if task.phase.load(Ordering::SeqCst) == 1 {
            state.latest = app.package_info().version.to_string();
            state.set(&directory, "idle")?;
        } else {
            match result {
                Ok(true) => match update_worker::launch(&directory) {
                    Ok(()) => app.exit(0),
                    Err(error) => state.fail(&directory, error),
                },
                Ok(false) => {},
                Err(error) => state.fail(&directory, error),
            }
        }
        Ok(state.public())
    }.await;
    if let Ok(mut active) = manual.0.lock() { *active = None; }
    result
}

pub fn restart_after_update(_app: &AppHandle) -> bool { false }

// Windows removal uses the native uninstaller, which calls the retained-worker
// cleanup before removing its installation. The macOS Trash flow is unavailable.
pub fn removal_supported() -> bool { true }

pub fn launch_uninstaller(app: &AppHandle) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|_| "Cannot locate OpenAIDR.")?;
    start_uninstaller(&executable, &storage::directory(app)?).map(|_| ())
}

fn start_uninstaller(executable: &Path, directory: &Path) -> Result<std::process::Child, String> {
    use std::process::{Command, Stdio};
    let uninstaller = executable.with_file_name("uninstall.exe");
    storage::reject_links(&uninstaller)?;
    if !uninstaller.is_file() {
        return Err("The Windows uninstaller is missing. Reinstall OpenAIDR, then try again.".into());
    }
    let _updater = storage::lock(directory, "updater.lock")?;
    let _operation = storage::lock(directory, "operation.lock")?;
    update_worker::installer_idle(&directory.join("installer.exe"))?;
    // Keep the native confirmation and cleanup. Cancelling its wizard must not
    // stop services or mark this installation as removed. Exit only after launch.
    Command::new(uninstaller).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|_| "Cannot open the Windows uninstaller. Try again or use Windows Settings > Apps.".into())
}

pub fn removal_status(_app: &AppHandle) -> Option<Value> { None }
pub fn removal_lock(_app: &AppHandle) -> Result<OperationLock, String> { Err("Use the Windows uninstaller to remove OpenAIDR.".into()) }
pub fn prepare_removal(_app: &AppHandle) -> Result<(), String> { Err("Use the Windows uninstaller to remove OpenAIDR.".into()) }
pub fn resume_removal(_app: &AppHandle) -> Result<(), String> { Err("Open the Windows installer to set up OpenAIDR again.".into()) }
pub fn trash_app(_app: &AppHandle) -> Result<(), String> { Err("Use the Windows uninstaller to remove OpenAIDR.".into()) }

pub fn early_command() -> Option<i32> {
    match std::env::args().nth(1).as_deref() {
        Some("--update-build-info") => { println!("{}", current_build()); Some(0) },
        Some("--update-worker") => Some(if update_layout::pending().and_then(|pending|
            if pending { update_layout::run() } else { update_worker::run() }).is_ok() { 0 } else { 1 }),
        Some("--resume-migration") => Some(if update_layout::pending().and_then(|pending|
            if pending { update_layout::launch(false).map(|_| ()) } else { Ok(()) }).is_ok() { 0 } else { 1 }),
        Some("--remove-update-service") => Some(if update_layout::pending().and_then(|pending|
            if pending { Err("Windows folder migration is still pending.".into()) } else { update_worker::remove() }).is_ok() { 0 } else { 1 }),
        _ => match update_layout::pending() {
            Ok(true) => match update_layout::launch(Mode::from_args() == Mode::Window) {
                Ok(true) => Some(0),
                Ok(false) => None,
                Err(_) => Some(1),
            },
            Ok(false) => None,
            Err(_) => Some(1),
        },
    }
}

struct WindowLock { _guard: OperationLock }

// Plugin setup runs before Tauri creates its windows. A launch during an
// installer transaction must exit before loading the old app's resources.
pub fn window_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("openaidr-update-window").setup(|app, _| {
        if enabled(app.config()) {
            let directory = storage::directory(app).map_err(std::io::Error::other)?;
            match update_worker::installer_idle(&directory.join("installer.exe"))
                .and_then(|_| storage::lock(&directory, "window.lock")) {
                Ok(guard) => { app.manage(WindowLock { _guard:guard }); },
                Err(error) if error == storage::BUSY => std::process::exit(0),
                Err(error) => return Err(std::io::Error::other(error).into()),
            }
        }
        Ok(())
    }).build()
}

async fn manual_locks(directory: &Path, task: &ManualTask, timeout: Duration) -> Result<Option<(OperationLock, OperationLock)>, String> {
    let result = task.run(async {
        let updater = wait_lock(directory, "updater.lock", timeout).await?;
        let operation = wait_lock(directory, "operation.lock", timeout).await?;
        Ok((updater, operation))
    }).await;
    // A cancelled wait owns no journal state. Return a neutral result without
    // saving over the operation that still holds the lock.
    if task.phase.load(Ordering::SeqCst) == 1 { Ok(None) } else { result.map(Some) }
}

async fn wait_lock(directory: &Path, name: &str, timeout: Duration) -> Result<OperationLock, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match storage::lock(directory, name) {
            Ok(lock) => return Ok(lock),
            Err(error) if error == storage::BUSY && Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(error) => return Err(error),
        }
    }
}

async fn download(update: &Update, directory: &Path, state: &mut State, public_key: &str) -> Result<tempfile::NamedTempFile, String> {
    let mut saved_at = None;
    super::update_download::download(update, directory, public_key, MAX_DOWNLOAD, |total, announced| {
        state.downloaded_bytes = Some(total);
        state.total_bytes = announced.filter(|size| *size > 0);
        let now = Instant::now();
        if saved_at.map_or(true, |last| now.duration_since(last) >= Duration::from_secs(1)) {
            let _ = save(directory, state);
            saved_at = Some(now);
        }
    }).await
}

async fn check(app: &AppHandle, directory: &Path, state: &mut State, mode: Mode,
    intent: Intent<'_>, task: Option<&ManualTask>) -> Result<bool, String> {
    if matches!(intent, Intent::Automatic) && !due(state.attempted_at, timestamp()) { return Ok(false); }
    let installed = current_build();
    let current = app.package_info().version.clone();
    let publication = installed["publication_timestamp"].as_i64().unwrap_or(0);
    state.attempted_at = Some(timestamp());
    state.set(directory, "checking")?;
    // The selected proxy also carries the archive download (update.proxy).
    let proxy = super::update_download::release_proxy(crate::bundled_binary(app).ok(), ENDPOINT).await;
    let mut builder = app.updater_builder().endpoints(vec![ENDPOINT.parse().unwrap()])
        .map_err(|_| "The update endpoint is invalid.")?
        .version_comparator(move |_, remote| remote.version != current && !remote.version.build.is_empty()
            && remote.pub_date.is_some_and(|date| date.unix_timestamp() > publication))
        .timeout(Duration::from_secs(30))
        .configure_client(|client| client.https_only(true).danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false).connect_timeout(Duration::from_secs(15)));
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy);
    }
    let updater = builder.build().map_err(|_| "Cannot initialize signed updates.")?;
    let lookup = state.check_health.check(&updater, timestamp());
    let Some(mut update) = (match task { Some(task) => task.run(lookup).await, None => lookup.await })? else {
        state.latest = app.package_info().version.to_string();
        state.set(directory, "idle")?;
        return Ok(false);
    };
    let release = selected_release(&update, &installed, &key())?;
    update.timeout = Some(Duration::from_secs(15 * 60));
    if !prepare_download(&update, &release, directory, state, timestamp() as i64, intent).await? {
        return Ok(false);
    }
    let public_key = key();
    let transfer = download(&update, directory, state, &public_key);
    let mut file = match task { Some(task) => task.run(transfer).await, None => transfer.await }?;
    release.verify_file(file.as_file_mut(), &public_key)?;
    if let Some(task) = task { task.begin_install()?; }
    state.set(directory, "installing")?;
    let installer = directory.join("installer.exe");
    storage::write_from(&installer, file.as_file_mut(), MAX_DOWNLOAD)?;
    storage::support("signature", &installer)?;
    state.pending = Some(Pending { release, previous:installed, reopen_window:mode == Mode::Window, install_started:false, manual:matches!(intent, Intent::Install(_)) });
    state.set(directory, "installing")?;
    Ok(true)
}

fn selected_release(update: &Update, installed: &Value, key: &str) -> Result<release::Release, String> {
    let release = release::from_manifest(&update.raw_json, key).map_err(str::to_owned)?;
    if update.raw_json["platforms"][release::TARGET]["url"].as_str() != Some(update.download_url.as_str())
        || update.signature != release.signature {
        return Err("The selected installer differs from its signed release record. The current app was kept.".into());
    }
    if release.version != update.version || !crate::newer_build(&release.version,
        installed["version"].as_str().unwrap_or(""), &release.build, installed) {
        return Err("The signed update has no later publication order. The current app was kept.".into());
    }
    Ok(release)
}

async fn prepare_download(update: &Update, release: &release::Release, directory: &Path,
    state: &mut State, now: i64, intent: Intent<'_>) -> Result<bool, String> {
    let policy = super::rollout::Policy::from_manifest(&update.raw_json).map_err(str::to_owned)?;
    match intent {
        Intent::Automatic => {
            let id = {
                let operation = wait_lock(directory, "operation.lock", LOCK_WAIT).await?;
                storage::installation_id(directory, &operation)?
            };
            if !policy.eligible(&release.version, &id, now) {
                state.set(directory, "idle")?;
                return Ok(false);
            }
        },
        Intent::Check => {
            state.latest = release.version.clone();
            state.set(directory, "available")?;
            return Ok(false);
        },
        Intent::Install(version) if version != release.version => {
            return Err("The available release changed. Check for updates again before installing.".into());
        },
        Intent::Install(_) => {},
    }
    state.latest = release.version.clone();
    state.set(directory, "downloading")?;
    Ok(true)
}

fn finish_sensor(executable: &Path, expected: &str) -> Result<(), String> {
    super::sensor_handoff::finish(expected, Duration::from_secs(120), |payload| crate::bridge(executable, payload))
}


fn finish(app: &AppHandle, directory: &Path, state: &mut State) -> Result<bool, String> {
    let pending = state.pending.as_ref().ok_or("There is no pending update.")?;
    let release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
    let build = current_build();
    let version = app.package_info().version.to_string();
    if (version == release.version && build != release.build)
        || (version != release.version && !crate::newer_build(&version, &release.version, &build, &release.build)) {
        return Err("Reopen the installed app to finish its update.".into());
    }
    let executable = crate::stable_binary(app)?;
    if crate::sensor_build(&executable) != build { return Err("The installed app and sensor have different build metadata.".into()); }
    let disabled = update_layout::preserve_disabled(&version)?;
    if !disabled {
        finish_sensor(&executable, &version)?;
    }
    let reopen = pending.reopen_window && !disabled;
    let phase = if pending.manual { "updated" } else { "idle" };
    state.latest = version;
    state.pending = None;
    state.set(directory, phase)?;
    let _ = fs::remove_file(directory.join("installer.exe"));
    Ok(reopen)
}

async fn attempt(app: &AppHandle, mode: Mode) -> Result<bool, String> {
    let directory = storage::directory(app)?;
    let _guard = wait_lock(&directory, "updater.lock", LOCK_WAIT).await?;
    if directory.join("removed").exists() { return Ok(false); }
    let mut state = load(&directory)?;
    let result: Result<bool, String> = async {
        if let Some(pending) = state.pending.as_ref() {
            update_worker::installer_idle(&directory.join("installer.exe"))?;
            let release = pending.release.revalidate(&key()).map_err(str::to_owned)?;
            let current = current_build();
            let version = app.package_info().version.to_string();
            let installed = version == release.version
                || crate::newer_build(&version, &release.version, &current, &release.build);
            // A failed sensor handoff must not prevent a later signed release
            // from repairing the installation. Keep the pending record until
            // its replacement is verified or the sensor becomes healthy.
            if installed && mode != Mode::Finish && check(app, &directory, &mut state, mode, Intent::Automatic, None).await? {
                update_worker::launch(&directory)?;
                return Ok(mode == Mode::Window);
            }
            if installed || mode == Mode::Finish {
                let _operation = wait_lock(&directory, "operation.lock", LOCK_WAIT).await?;
                let reopen = finish(app, &directory, &mut state)?;
                update_worker::register(&directory, &std::env::current_exe().map_err(|_| "Cannot locate the updated app.")?)?;
                if reopen && mode.headless() {
                    let mut command = std::process::Command::new(std::env::current_exe().map_err(|_| "Cannot locate the updated app.")?);
                    command.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
                    crate::hide_console(&mut command);
                    command.spawn().map_err(|_| "Cannot reopen the updated app.")?;
                }
                return Ok(false);
            }
            if mode == Mode::Window {
                state.pending.as_mut().unwrap().reopen_window = true;
                save(&directory, &state)?;
            }
            update_worker::launch(&directory)?;
            return Ok(mode == Mode::Window);
        }
        if mode != Mode::Finish && check(app, &directory, &mut state, mode, Intent::Automatic, None).await? {
            update_worker::launch(&directory)?;
            return Ok(mode == Mode::Window);
        }
        Ok(false)
    }.await;
    if let Err(error) = &result { state.fail(&directory, error.clone()); }
    result
}

pub fn initialize(app: &AppHandle, mode: Mode) {
    if !enabled(app.config()) { if mode.headless() { app.exit(0); } return; }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if mode == Mode::Window {
            let result = async {
                let directory = storage::directory(&app)?;
                let _guard = wait_lock(&directory, "updater.lock", LOCK_WAIT).await?;
                let _operation = wait_lock(&directory, "operation.lock", LOCK_WAIT).await?;
                update_worker::register(&directory, &std::env::current_exe().map_err(|_| "Cannot locate OpenAIDR.")?)
            }.await;
            if let Err(error) = result {
                if let Ok(directory) = storage::directory(&app) {
                    if let Ok(_guard) = storage::lock(&directory, "updater.lock") {
                        if let Ok(mut state) = load(&directory) { state.fail(&directory, error); }
                    }
                }
                return;
            }
        }
        loop {
            let exit_window = attempt(&app, mode).await.unwrap_or(false);
            if exit_window || mode.headless() { app.exit(0); return; }
            tokio::time::sleep(Duration::from_secs(WAKE)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::{Read, Write}, net::TcpListener, sync::{Mutex, atomic::{AtomicBool, Ordering}}, thread};

    #[test]
    fn manual_update_waits_for_busy_locks_and_keeps_them_exclusive() {
        use std::{future::Future, task::{Context, Waker}};
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for name in ["updater.lock", "operation.lock"] {
                let scratch = tempfile::tempdir().unwrap();
                let directory = scratch.path();
                let busy = storage::lock(directory, name).unwrap();
                let task = ManualTask::default();
                let mut waiting = Box::pin(manual_locks(directory, &task, LOCK_WAIT));
                assert!(waiting.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                drop(busy);
                let guards = waiting.await.unwrap().unwrap();
                for lock in ["updater.lock", "operation.lock"] {
                    assert_eq!(storage::lock(directory, lock).err().unwrap(), storage::BUSY);
                }
                drop(guards);
                assert!(manual_locks(directory, &task, Duration::ZERO).await.unwrap().is_some());
            }
        });
    }

    #[test]
    fn cancelling_a_manual_lock_wait_releases_only_its_own_locks() {
        use std::{future::Future, task::{Context, Waker}};
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for name in ["updater.lock", "operation.lock"] {
                let scratch = tempfile::tempdir().unwrap();
                let directory = scratch.path();
                let journal = directory.join(JOURNAL);
                fs::write(&journal, b"another operation's state").unwrap();
                let busy = storage::lock(directory, name).unwrap();
                let task = ManualTask::default();
                let mut waiting = Box::pin(manual_locks(directory, &task, LOCK_WAIT));
                assert!(waiting.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                task.cancel().unwrap();
                assert!(waiting.await.unwrap().is_none());
                assert_eq!(storage::lock(directory, name).err().unwrap(), storage::BUSY);
                assert_eq!(fs::read(&journal).unwrap(), b"another operation's state");
                drop(busy);
                assert!(manual_locks(directory, &ManualTask::default(), Duration::ZERO).await.unwrap().is_some());
            }
        });
    }

    #[test]
    fn manual_lock_waits_are_bounded_and_reject_unsafe_locks() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for name in ["updater.lock", "operation.lock"] {
                let scratch = tempfile::tempdir().unwrap();
                let directory = scratch.path();
                let task = ManualTask::default();
                let busy = storage::lock(directory, name).unwrap();
                assert_eq!(manual_locks(directory, &task, Duration::ZERO).await.err().unwrap(), storage::BUSY);
                drop(busy);
                fs::write(directory.join(name), b"unsafe").unwrap();
                assert_eq!(manual_locks(directory, &task, LOCK_WAIT).await.err().unwrap(), "The desktop operation lock is unsafe.");
                fs::remove_file(directory.join(name)).unwrap();
                assert!(manual_locks(directory, &task, Duration::ZERO).await.unwrap().is_some());
            }
        });
    }

    #[test]
    fn native_uninstall_launch_preserves_state_and_respects_active_operations() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("OpenAIDR's installation 日本語");
        let directory = scratch.path().join("updates");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&directory).unwrap();
        let executable = root.join("openaidr-desktop.exe");
        let uninstaller = root.join("uninstall.exe");
        let launched = root.join("launched.txt");
        fs::write(directory.join(JOURNAL), b"retained update state").unwrap();
        assert!(start_uninstaller(&executable, &directory).unwrap_err().contains("uninstaller is missing"));
        fs::write(&uninstaller, b"damaged executable").unwrap();
        assert!(start_uninstaller(&executable, &directory).unwrap_err().contains("Cannot open"));
        // A real, harmless executable records its arguments without touching
        // this account's installed app, services, or enrollment.
        let source = scratch.path().join("uninstall_fixture.rs");
        fs::write(&source, r#"fn main() {
            let path = std::env::current_exe().unwrap().with_file_name("launched.txt");
            std::fs::write(path, format!("{:?}", std::env::args_os().skip(1).collect::<Vec<_>>())).unwrap();
        }"#).unwrap();
        let output = std::process::Command::new("rustc").arg(&source).arg("-o").arg(&uninstaller).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        for name in ["updater.lock", "operation.lock"] {
            let _busy = storage::lock(&directory, name).unwrap();
            assert_eq!(start_uninstaller(&executable, &directory).unwrap_err(), storage::BUSY);
            assert!(!launched.exists());
        }
        let mut child = start_uninstaller(&executable, &directory).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(fs::read_to_string(launched).unwrap(), "[]", "Keep the wizard interactive; never pass /S or /UPDATE");
        assert_eq!(fs::read(directory.join(JOURNAL)).unwrap(), b"retained update state");
        assert!(!directory.join("removed").exists(), "The user can still cancel the native wizard");
    }

    #[test]
    fn rollout_checks_only_download_eligible_verified_releases() {
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let public_key = fixture["key"].as_str().unwrap();
        let payload = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        let manifest = Arc::new(Mutex::new(fixture["manifest"].clone()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let tampered = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = std::sync::mpsc::channel();
        let worker = {
            let (manifest, requests, tampered, payload) = (manifest.clone(), requests.clone(), tampered.clone(), payload.clone());
            thread::spawn(move || {
                while matches!(stopped.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        },
                        Err(error) => panic!("test server: {error}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0];
                    while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).unwrap_or(0) == 0 { break; }
                        request.push(byte[0]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    let target = request.split_whitespace().nth(1).unwrap_or("");
                    let mut body = match target {
                        "/rollout-v2.json" => serde_json::to_vec(&*manifest.lock().unwrap()).unwrap(),
                        "/installer.exe" => payload.clone(),
                        _ => panic!("unexpected test request: {target}"),
                    };
                    if target == "/installer.exe" && tampered.load(Ordering::Relaxed) { body[0] ^= 1; }
                    requests.lock().unwrap().push(request);
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                }
            })
        };
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop-update");
        storage::support("directory", &directory).unwrap();
        let id = {
            let guard = storage::lock(&directory, "operation.lock").unwrap();
            storage::installation_id(&directory, &guard).unwrap()
        };
        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        context.config_mut().plugins.0.insert("updater".into(), json!({
            "pubkey":public_key, "dangerousInsecureTransportProtocol":true,
        }));
        let app = tauri::test::mock_builder().plugin(tauri_plugin_updater::Builder::new().build()).build(context).unwrap();
        let payload_requests = || requests.lock().unwrap().iter().filter(|request| request.starts_with("GET /installer.exe ")).count();
        let release = release::from_manifest(&fixture["manifest"], public_key).unwrap();
        let mut previous = release.build.clone();
        previous["version"] = json!("2026.10.6+0000000");
        previous["source_commit"] = json!("0".repeat(40));
        previous["publication_timestamp"] = json!(1791338400);
        previous["published_at"] = json!("2026-10-07T02:00:00+00:00");
        tauri::async_runtime::block_on(async {
            let updater = app.updater_builder().no_proxy()
                .endpoints(vec![format!("{origin}/rollout-v2.json").parse().unwrap()]).unwrap()
                .version_comparator(|_, _| true).timeout(Duration::from_secs(3)).build().unwrap();
            let mut state = State::default();
            let policy = json!({"schema_version":1, "starts_at":"2026-10-07T03:00:00Z", "paused":false,
                "steps":[{"after_hours":0,"percent":100},{"after_hours":24,"percent":100}]});
            for case in ["zero", "paused", "future", "missing", "invalid", "identity", "eligible", "tampered"] {
                let mut rollout = policy.clone();
                match case {
                    "zero" => rollout["steps"][0]["percent"] = json!(0),
                    "paused" => rollout["paused"] = json!(true),
                    "future" => rollout["starts_at"] = json!("2026-10-08T03:00:00Z"),
                    "missing" => rollout = Value::Null,
                    "invalid" => rollout["schema_version"] = json!(2),
                    "identity" => fs::write(directory.join("desktop-installation-id"), "invalid").unwrap(),
                    "tampered" => tampered.store(true, Ordering::Relaxed),
                    _ => {},
                }
                manifest.lock().unwrap()["rollout"] = rollout;
                let mut update = updater.check().await.unwrap().unwrap();
                let release = selected_release(&update, &previous, public_key).unwrap();
                assert!(selected_release(&update, &release.build, public_key).is_err());
                // Only the test transport changes. The selected target, signed
                // metadata and canonical production URL were checked above.
                update.download_url = format!("{origin}/installer.exe").parse().unwrap();
                assert!(selected_release(&update, &previous, public_key).is_err());
                let result = async {
                    if !prepare_download(&update, &release, &directory, &mut state, 1791342000, Intent::Automatic).await? {
                        return Ok::<_, String>(None);
                    }
                    let mut file = download(&update, &directory, &mut state, public_key).await?;
                    release.verify_file(file.as_file_mut(), public_key)?;
                    Ok(Some(file))
                }.await;
                match case {
                    "eligible" => { assert_eq!(fs::read(result.unwrap().unwrap().path()).unwrap(), payload); assert_eq!(payload_requests(), 1); },
                    "tampered" => { assert!(result.is_err()); assert_eq!(payload_requests(), 2); },
                    "missing" | "invalid" | "identity" => { assert!(result.is_err(), "{case}"); assert_eq!(payload_requests(), 0); },
                    _ => { assert!(result.unwrap().is_none(), "{case}"); assert_eq!(payload_requests(), 0); },
                }
                if case == "identity" { fs::write(directory.join("desktop-installation-id"), &id).unwrap(); }
            }
            tampered.store(false, Ordering::Relaxed);
            manifest.lock().unwrap()["rollout"] = policy.clone();
            manifest.lock().unwrap()["rollout"]["paused"] = json!(true);
            let mut update = updater.check().await.unwrap().unwrap();
            let release = selected_release(&update, &previous, public_key).unwrap();
            update.download_url = format!("{origin}/installer.exe").parse().unwrap();
            assert!(!prepare_download(&update, &release, &directory, &mut state, 0, Intent::Check).await.unwrap());
            assert_eq!(state.public()["state"], "available");
            assert_eq!(payload_requests(), 2, "Checking must not download even outside the rollout");
            assert!(prepare_download(&update, &release, &directory, &mut state, 0, Intent::Install("2026.10.6+0000000")).await.is_err());
            assert_eq!(payload_requests(), 2);
            let task = ManualTask::default();
            task.cancel().unwrap();
            assert!(task.run(download(&update, &directory, &mut state, public_key)).await.is_err());
            assert!(task.begin_install().is_err());
            assert_eq!(payload_requests(), 2, "Cancellation must prevent downloading and installation");
            assert!(prepare_download(&update, &release, &directory, &mut state, 0, Intent::Install(&release.version)).await.unwrap());
            let task = ManualTask::default();
            let mut file = task.run(download(&update, &directory, &mut state, public_key)).await.unwrap();
            release.verify_file(file.as_file_mut(), public_key).unwrap();
            task.begin_install().unwrap();
            assert!(task.cancel().is_err());
            assert_eq!(payload_requests(), 3);
            update.raw_json["rollout"]["schema_version"] = json!(2);
            for intent in [Intent::Check, Intent::Install(&release.version)] {
                assert!(prepare_download(&update, &release, &directory, &mut state, 0, intent).await.is_err());
            }
            assert_eq!(payload_requests(), 3);
        });
        assert_eq!(fs::read_to_string(directory.join("desktop-installation-id")).unwrap(), id);
        assert!(!directory.join("installer.exe").exists());
        assert!(requests.lock().unwrap().iter().all(|request| !request.contains(&id) && !request.contains("latest.json")));
        assert_eq!(requests.lock().unwrap().iter().filter(|request| request.starts_with("GET /rollout-v2.json ")).count(), 9);
        stop.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn scheduled_wakes_do_not_each_fetch_a_release() {
        assert!(due(None, 1000));
        assert!(!due(Some(1000), 1000 + WAKE));
        assert!(!due(Some(1000), 1000 + INTERVAL - 1));
        assert!(due(Some(1000), 1000 + INTERVAL));
        assert!(due(Some(1000), 999));
    }

    #[test]
    fn failed_handoff_retains_verified_publication_for_recovery() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop-update");
        storage::support("directory", &directory).unwrap();
        let fixture: Value = serde_json::from_str(include_str!("release-fixture.json")).unwrap();
        let release = release::from_manifest(&fixture["manifest"], fixture["key"].as_str().unwrap()).unwrap();
        let mut state = State { pending:Some(Pending { release, previous:json!({}), reopen_window:true, install_started:true, manual:false }), ..State::default() };
        state.set(&directory, "restarting").unwrap();
        state.fail(&directory, "Sensor setup failed".into());
        let recovered = load(&directory).unwrap();
        assert_eq!(recovered.public()["state"], "error");
        let pending = recovered.pending.unwrap();
        assert!(pending.reopen_window && pending.install_started);
        pending.release.revalidate(fixture["key"].as_str().unwrap()).unwrap();
        state.set(&directory, "installing").unwrap();
        assert_eq!(read_state(&directory).unwrap().state, "installing");
        state.pending = None;
        let active = storage::lock(&directory, "updater.lock").unwrap();
        state.set(&directory, "downloading").unwrap();
        assert_eq!(read_state(&directory).unwrap().state, "downloading");
        drop(active);
        let recovered = read_state(&directory).unwrap();
        assert_eq!(recovered.state, "error");
        assert!(recovered.error.unwrap().contains("interrupted"));
    }
}
