//! Signed AppImage updates, including workers that do not need a display server.

use super::{Mode, manual_update::{Intent, ManualTask}};
pub use super::manual_update::ManualUpdate;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::{Path, PathBuf}, process::{Command, Stdio},
    sync::{Arc, atomic::Ordering}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tauri::{AppHandle, Config, Manager};

#[path = "../signed_release.rs"]
mod release;
#[path = "update_storage.rs"]
mod storage;
#[path = "update_installation.rs"]
mod installation;
pub use storage::OperationLock;

const ENDPOINT: &str = crate::platform::RELEASE_FEED;
const IMAGE: &str = "OpenAIDR.AppImage";
const JOURNAL: &str = "desktop-update.json";
const RECORD: &str = "installation.json";
const MAX_DOWNLOAD: u64 = 1024 * 1024 * 1024;
const INTERVAL: u64 = 3 * 60 * 60;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct State {
    state: String,
    latest: String,
    error: Option<String>,
    attempted_at: Option<u64>,
    check_health: super::update_check::CheckHealth,
    downloaded_bytes: Option<u64>,
    total_bytes: Option<u64>,
    pending: Option<Pending>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Pending {
    release: release::Release,
    previous: release::Release,
    reopen_window: bool,
    #[serde(default)]
    manual: bool,
}

impl State {
    fn public(&self) -> Value {
        let mut value = json!({"state":if self.state.is_empty() { "idle" } else { &self.state },
            "latest":self.latest,"error":self.error});
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
}

fn current_build() -> Value { serde_json::from_str(env!("OPENAIDR_BUILD_INFO")).unwrap_or(Value::Null) }
fn key() -> String { STANDARD.encode(crate::platform::UPDATER_PUBLIC_KEY) }
fn timestamp() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
fn due(last: Option<u64>, now: u64) -> bool { last.map_or(true, |last| now < last || now - last >= INTERVAL) }

fn load(directory: &Path) -> Result<State, String> {
    storage::json_file(&directory.join(JOURNAL))?.map(serde_json::from_value).transpose()
        .map(|state| state.unwrap_or_default()).map_err(|_| "Cannot read saved update state.".into())
}

fn read_state(directory: &Path) -> Result<State, String> {
    match storage::lock(directory, "updater.lock") {
        Ok(_guard) => {
            let mut state = load(directory)?;
            if state.pending.is_none() && matches!(state.state.as_str(), "checking" | "downloading" | "installing") {
                state.set(directory, "error")?;
                state.error = Some("The previous update was interrupted. Check for updates to try again.".into());
                save(directory, &state)?;
            }
            Ok(state)
        },
        Err(error) if error == storage::BUSY => load(directory),
        Err(error) => Err(error),
    }
}

fn save(directory: &Path, state: &State) -> Result<(), String> {
    storage::write(&directory.join(JOURNAL), &serde_json::to_vec(state).map_err(|_| "Cannot encode update state.")?, false)
}

fn record(directory: &Path) -> Result<release::Release, String> {
    record_with_key(directory, &key())
}

fn record_with_key(directory: &Path, public_key: &str) -> Result<release::Release, String> {
    let value = storage::json_file(&directory.join(RECORD))?.ok_or("Install this AppImage for automatic updates first.")?;
    let release: release::Release = serde_json::from_value(value).map_err(|_| "The AppImage installation record is invalid.")?;
    release.revalidate(public_key).map_err(str::to_owned)
}

fn save_record(directory: &Path, release: &release::Release) -> Result<(), String> {
    storage::write(&directory.join(RECORD), &serde_json::to_vec(release).map_err(|_| "Cannot retain the signed release.")?, false)
}

fn candidate_path(directory: &Path, release: &release::Release) -> PathBuf {
    directory.join(format!("candidate-{}.AppImage", release.build["source_commit"].as_str().unwrap()))
}

fn verified_image(path: &Path, release: &release::Release, public_key: &str) -> Result<fs::File, String> {
    storage::reject_links(path)?;
    let mut file = storage::open(path, MAX_DOWNLOAD).map_err(|_| "Cannot read the signed AppImage. The current app was kept.")?;
    release.verify_file(&mut file, public_key)?;
    Ok(file)
}

fn image_command(path: &Path, argument: &str) -> Command {
    let mut command = Command::new(path);
    command.arg(argument).env("APPIMAGE_EXTRACT_AND_RUN", "1")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    command
}

fn run_image(path: &Path, argument: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = image_command(path, argument).spawn().map_err(|_| "Cannot start the verified AppImage.")?;
    let (status, bytes) = crate::child_output(&mut child, timeout, 64 * 1024)?;
    if !status.success() { return Err("The verified AppImage did not complete its update operation.".into()); }
    Ok(bytes)
}

fn verify_runtime(path: &Path, release: &release::Release) -> Result<(), String> {
    let bytes = run_image(path, "--update-build-info", Duration::from_secs(60))?;
    let build: Value = serde_json::from_slice(&bytes).map_err(|_| "The AppImage returned invalid build metadata.")?;
    if build != release.build { return Err("The AppImage differs from its signed publication.".into()); }
    Ok(())
}

async fn download(url: &str, directory: &Path, progress: impl FnMut(u64, Option<u64>)) -> Result<tempfile::NamedTempFile, String> {
    let response = super::update_download::client(Duration::from_secs(15 * 60))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "Cannot initialize signed updates.")?
        .get(url).send().await.map_err(|_| super::update_check::UNREACHABLE)?;
    super::update_download::receive(response, directory, MAX_DOWNLOAD, progress).await
}

async fn fetch(url: &str, limit: u64, timeout: Duration, progress: impl FnMut(u64, Option<u64>)) -> Result<Vec<u8>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder().https_only(true)
        .redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(15)).timeout(timeout)
        .build().map_err(|_| "Cannot initialize signed updates.")?;
    let response = client.get(url).send().await.and_then(|response| response.error_for_status())
        .map_err(|_| super::update_check::UNREACHABLE)?;
    read_response(response, limit, progress).await
}

async fn read_response(mut response: reqwest::Response, limit: u64, mut progress: impl FnMut(u64, Option<u64>)) -> Result<Vec<u8>, String> {
    if !response.status().is_success() { return Err("The release server returned an invalid response.".into()); }
    let total = response.content_length();
    if total.is_some_and(|size| size > limit) { return Err("The release download is too large.".into()); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| super::update_check::UNREACHABLE)? {
        if bytes.len() as u64 + chunk.len() as u64 > limit { return Err("The release download is too large.".into()); }
        bytes.extend_from_slice(&chunk);
        progress(bytes.len() as u64, total);
    }
    Ok(bytes)
}

fn selected_release(manifest: &Value, installed: &release::Release, id: &str, now: i64,
    public_key: &str, intent: Intent<'_>) -> Result<Option<release::Release>, String> {
    let policy = super::rollout::Policy::from_manifest(manifest).map_err(str::to_owned)?;
    if manifest["platforms"].get(release::TARGET).is_none() { return Ok(None); }
    let release = release::from_manifest(manifest, public_key).map_err(str::to_owned)?;
    if !crate::newer_build(&release.version, &installed.version, &release.build, &installed.build) { return Ok(None); }
    match intent {
        Intent::Automatic if !policy.eligible(&release.version, id, now) => return Ok(None),
        Intent::Install(version) if version != release.version => {
            return Err("The available release changed. Check for updates again before installing.".into());
        },
        _ => {},
    }
    Ok(Some(release))
}

async fn check(directory: &Path, state: &mut State, installed: &release::Release,
    intent: Intent<'_>, task: Option<&ManualTask>) -> Result<(), String> {
    if matches!(intent, Intent::Automatic) && !due(state.attempted_at, timestamp()) { return Ok(()); }
    state.attempted_at = Some(timestamp());
    state.set(directory, "checking")?;
    let lookup = async {
        let result = fetch(ENDPOINT, 1024 * 1024, Duration::from_secs(30), |_, _| {}).await;
        state.check_health.record(&result, timestamp());
        result
    };
    let bytes = match task { Some(task) => task.run(lookup).await, None => lookup.await }?;
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|_| "The release manifest is invalid.")?;
    let id = if matches!(intent, Intent::Automatic) {
        let operation = wait_lock(directory, "operation.lock", Duration::from_secs(180))?;
        storage::installation_id(directory, &operation)?
    } else { String::new() };
    let Some(release) = selected_release(&manifest, installed, &id, timestamp() as i64, &key(), intent)? else {
        state.latest = installed.version.clone();
        return state.set(directory, "idle");
    };
    state.latest = release.version.clone();
    if matches!(intent, Intent::Check) { return state.set(directory, "available"); }
    state.set(directory, "downloading")?;
    let mut saved = None;
    let url = release.url();
    let transfer = download(&url, directory, |downloaded, total| {
        let now = Instant::now();
        if saved.map_or(true, |last| now.duration_since(last) >= Duration::from_secs(1)) {
            state.downloaded_bytes = Some(downloaded);
            state.total_bytes = total;
            let _ = save(directory, state);
            saved = Some(now);
        }
    });
    let mut file = match task { Some(task) => task.run(transfer).await, None => transfer.await }
        .map_err(|error| if error == super::update_check::UNREACHABLE {
            "The update download did not finish.".to_string()
        } else { error })?;
    release.verify_file(file.as_file_mut(), &key())?;
    if let Some(task) = task { task.begin_install()?; }
    state.set(directory, "installing")?;
    let candidate = candidate_path(directory, &release);
    storage::write_from(&candidate, file.as_file_mut(), MAX_DOWNLOAD, true)?;
    verify_runtime(&candidate, &release)?;
    let reopen_window = match storage::lock(directory, "window.lock") {
        Ok(_) => state.pending.as_ref().is_some_and(|pending| pending.reopen_window),
        Err(error) if error == storage::BUSY => true,
        Err(error) => return Err(error),
    };
    state.pending = Some(Pending { release, previous:installed.clone(), reopen_window, manual:matches!(intent, Intent::Install(_)) });
    state.set(directory, "installing")
}

fn wait_lock(directory: &Path, name: &str, timeout: Duration) -> Result<OperationLock, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match storage::lock(directory, name) {
            Ok(guard) => return Ok(guard),
            Err(error) if error == storage::BUSY && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(error),
        }
    }
}

fn verify_replacement(directory: &Path, pending: &Pending, public_key: &str)
    -> Result<(release::Release, Option<fs::File>), String> {
    let next = pending.release.revalidate(public_key).map_err(str::to_owned)?;
    let previous = pending.previous.revalidate(public_key).map_err(str::to_owned)?;
    if !crate::newer_build(&next.version, &previous.version, &next.build, &previous.build) {
        return Err("The pending AppImage has no later signed publication order.".into());
    }
    let image = directory.join(IMAGE);
    // After an interrupted rename, the complete new image may already be in
    // place. Never overwrite an unknown, manually replaced, or removed image.
    if verified_image(&image, &next, public_key).is_ok() { return Ok((next, None)); }
    let prior_bytes = verified_image(&image, &previous, public_key)?;
    verified_image(&candidate_path(directory, &next), &next, public_key)?;
    Ok((next, Some(prior_bytes)))
}

fn replace_image(directory: &Path, pending: &Pending, public_key: &str) -> Result<(), String> {
    let (next, prior_bytes) = verify_replacement(directory, pending, public_key)?;
    if let Some(mut prior_bytes) = prior_bytes {
        retain_previous(directory, &mut prior_bytes)?;
        fs::rename(candidate_path(directory, &next), directory.join(IMAGE))
            .map_err(|_| "Cannot replace the AppImage. The current app was kept.")?;
        storage::sync(directory)?;
    }
    save_record(directory, &next)
}

fn retain_previous(directory: &Path, file: &mut fs::File) -> Result<(), String> {
    storage::write_from(&directory.join("previous.AppImage"), file, MAX_DOWNLOAD, true)
}

fn recover(directory: &Path, state: &mut State) -> Result<(), String> {
    let Some(pending) = state.pending.clone() else { return Ok(()); };
    let window;
    {
        let _operation = wait_lock(directory, "operation.lock", Duration::from_secs(180))?;
        // Prepare the replacement and backup before asking the window to exit.
        // A live lock distinguishes this request from a crashed worker's journal.
        let _handoff = if let Some(mut file) = verify_replacement(directory, &pending, &key())?.1 {
            retain_previous(directory, &mut file)?;
            state.set(directory, "installing")?;
            Some(wait_lock(directory, "handoff.lock", Duration::from_secs(5))?)
        } else { None };
        window = if _handoff.is_some() {
            Some(wait_lock(directory, "window.lock", Duration::from_secs(120))?)
        } else { None };
        replace_image(directory, &pending, &key())?;
    }
    state.set(directory, "restarting")?;
    run_image(&directory.join(IMAGE), "--update-sensor", Duration::from_secs(300))?;
    drop(window);
    if pending.reopen_window { installation::reopen(directory)?; }
    state.latest = pending.release.version;
    state.pending = None;
    state.set(directory, if pending.manual { "updated" } else { "idle" })?;
    cleanup(directory);
    Ok(())
}

fn cleanup(directory: &Path) {
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            let owned = path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
                name == "previous.AppImage" || name.strip_prefix("candidate-")
                    .and_then(|name| name.strip_suffix(".AppImage"))
                    .is_some_and(|commit| commit.len() == 40 && commit.bytes().all(|c| c.is_ascii_hexdigit()))
            });
            if owned && storage::reject_links(&path).is_ok() { let _ = fs::remove_file(path); }
        }
    }
}

fn worker() -> Result<(), String> {
    let directory = storage::directory()?;
    let _guard = storage::lock(&directory, "updater.lock")?;
    let mut state = load(&directory)?;
    let manual = state.pending.as_ref().is_some_and(|pending| pending.manual);
    if directory.join("disabled").exists() && !manual { return Ok(()); }
    let result = (|| {
        let installed = record(&directory)?;
        // A rename can precede its installation-record write. Recover that
        // journal first; otherwise allow a later release to repair a handoff.
        if verified_image(&directory.join(IMAGE), &installed, &key()).is_ok() {
            if !manual {
                if let Err(error) = tauri::async_runtime::block_on(check(&directory, &mut state, &installed, Intent::Automatic, None)) {
                    if state.pending.is_none() { return Err(error); }
                    // Network availability cannot prevent recovery of a payload
                    // that was already verified and retained on this device.
                }
            }
        } else if state.pending.is_none() {
            return Err("The installed AppImage changed. Reinstall a verified release to repair it.".into());
        }
        recover(&directory, &mut state)
    })();
    if let Err(error) = &result {
        state.state = "error".into();
        state.error = Some(error.clone());
        let _ = save(&directory, &state);
    }
    result
}

fn finish_sensor() -> Result<(), String> {
    let directory = storage::directory()?;
    let _operation = wait_lock(&directory, "operation.lock", Duration::from_secs(180))?;
    let release = record(&directory)?;
    verified_image(&directory.join(IMAGE), &release, &key())?;
    if release.build != current_build() { return Err("Open the installed AppImage to finish its update.".into()); }
    let executable = std::env::current_exe().map_err(|_| "Cannot locate the bundled sensor.")?;
    let source = executable.parent().ok_or("Cannot locate the bundled sensor.")?.join("openaidr");
    if crate::sensor_build(&source) != current_build() { return Err("The bundled sensor differs from this app.".into()); }
    let target = storage::data_home()?.join("openaidr/bin");
    storage::reject_links(&target)?;
    fs::create_dir_all(&target).map_err(|_| "Cannot stage the updated sensor.")?;
    stage_and_finish_sensor(&source, &target, Duration::from_secs(120))
}

fn stage_and_finish_sensor(source: &Path, target: &Path, timeout: Duration) -> Result<(), String> {
    let sensor = crate::stage_binary(&source, &target)?;
    let expected = crate::sensor_version(source).ok_or("The bundled sensor cannot report its version.")?;
    crate::require_sensor_version(&sensor, &expected)?;
    super::sensor_handoff::finish(&expected, timeout, |payload| crate::bridge(&sensor, payload))
}

fn managed_location() -> bool {
    std::env::var_os("APPIMAGE").map(PathBuf::from).zip(storage::data_home().ok())
        .is_some_and(|(image, home)| image == home.join("openaidr/desktop").join(IMAGE))
}

pub fn enabled(_config: &Config) -> bool {
    cfg!(target_arch = "x86_64") && !cfg!(debug_assertions) && current_build()["published_at"].is_string() && managed_location()
}

pub fn cancel(app: &AppHandle) -> Result<Value, String> {
    let manual = app.state::<ManualUpdate>();
    let active = manual.0.lock().map_err(|_| "Cannot cancel the update.")?;
    active.as_ref().ok_or("There is no cancellable update running.")?.cancel()?;
    Ok(Value::Null)
}

pub async fn manual(app: &AppHandle, version: Option<String>) -> Result<Value, String> {
    if installation::needed() { return installation::start_setup(app); }
    if !enabled(app.config()) {
        return Ok(json!({"state":"unavailable", "latest":"",
            "error":"In-app updates require a signed, managed AppImage. Update DEB installations with your package manager."}));
    }
    let manual = app.state::<ManualUpdate>();
    let task = Arc::new(ManualTask::default());
    {
        let mut active = manual.0.lock().map_err(|_| storage::BUSY)?;
        if active.is_some() { return Err(storage::BUSY.into()); }
        *active = Some(task.clone());
    }
    let result = async {
        let directory = storage::directory()?;
        let guard = storage::lock(&directory, "updater.lock")?;
        let mut state = load(&directory)?;
        if state.pending.is_some() {
            return Err("Reopen OpenAIDR to finish the pending update before checking again.".into());
        }
        let installed = record(&directory)?;
        if installed.build != current_build() {
            return Err("Reopen the installed AppImage before checking for updates.".into());
        }
        verified_image(&directory.join(IMAGE), &installed, &key())?;
        installation::remember_session(&directory)?;
        let intent = version.as_deref().map_or(Intent::Check, Intent::Install);
        let result = check(&directory, &mut state, &installed, intent, Some(&task)).await;
        if task.phase.load(Ordering::SeqCst) == 1 {
            state.latest = installed.version;
            state.set(&directory, "idle")?;
        } else if let Err(error) = result {
            state.state = "error".into();
            state.error = Some(error);
            save(&directory, &state)?;
        } else if state.pending.is_some() {
            // The user service owns installation and survives the window exit.
            drop(guard);
            if let Err(error) = installation::start() {
                let _guard = storage::lock(&directory, "updater.lock")?;
                state = load(&directory)?;
                if state.pending.is_some() {
                    state.set(&directory, "error")?;
                    state.error = Some(error);
                    save(&directory, &state)?;
                }
            }
        }
        Ok(state.public())
    }.await;
    if let Ok(mut active) = manual.0.lock() { *active = None; }
    result
}

pub fn early_command() -> Option<i32> {
    let action = std::env::args().nth(1)?;
    if action == "--update-build-info" { println!("{}", current_build()); return Some(0); }
    if action == "--update-protocol" { println!("1"); return Some(0); }
    let result = match action.as_str() {
        "--install-updates" => installation::bootstrap(),
        "--background-update" => worker(),
        "--update-sensor" => finish_sensor(),
        "--disable-updates" => installation::disable(),
        _ => return None,
    };
    Some(match result { Ok(()) => 0, Err(error) => { eprintln!("{error}"); 1 } })
}

pub fn operation_lock(_app: &AppHandle) -> Result<OperationLock, String> { storage::lock(&storage::directory()?, "operation.lock") }
pub fn status(app: &AppHandle) -> Option<Value> { read_status(app).ok().flatten() }
pub fn read_status(app: &AppHandle) -> Result<Option<Value>, String> {
    if installation::needed() { return installation::status(app); }
    if !enabled(app.config()) { return Ok(None); }
    Ok(Some(read_state(&storage::directory()?)?.public()))
}
pub fn restart_after_update(_app: &AppHandle) -> bool { false }
pub fn removal_supported() -> bool { false }
pub fn removal_status(_app: &AppHandle) -> Option<Value> { None }
pub fn removal_lock(_app: &AppHandle) -> Result<OperationLock, String> { Err("Use the Linux installation procedure to remove OpenAIDR.".into()) }
pub fn prepare_removal(_app: &AppHandle) -> Result<(), String> { Err("Use the Linux installation procedure to remove OpenAIDR.".into()) }
pub fn resume_removal(_app: &AppHandle) -> Result<(), String> { Err("Install a verified AppImage to enable updates.".into()) }
pub fn trash_app(_app: &AppHandle) -> Result<(), String> { Err("Use the Linux installation procedure to remove OpenAIDR.".into()) }

struct WindowLock { _guard: OperationLock }

pub fn window_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("openaidr-update-window").setup(|app, _| {
        app.manage(installation::SetupStatus::default());
        if enabled(app.config()) {
            let directory = storage::directory().map_err(std::io::Error::other)?;
            // Reopen briefly probes this lock to observe startup. Retry that
            // transient contention before treating another window as active.
            match wait_lock(&directory, "window.lock", Duration::from_secs(1)) {
                Ok(guard) => { app.manage(WindowLock { _guard:guard }); },
                Err(error) if error == storage::BUSY => std::process::exit(0),
                Err(error) => return Err(std::io::Error::other(error).into()),
            }
        }
        Ok(())
    }).build()
}

fn handoff_requested(directory: &Path, state: &State, version: &str) -> bool {
    if (directory.join("disabled").exists() && !state.pending.as_ref().is_some_and(|pending| pending.manual))
        || state.state != "installing"
        || !state.pending.as_ref().is_some_and(|pending| pending.release.version != version) {
        return false;
    }
    matches!(storage::lock(directory, "handoff.lock"), Err(error) if error == storage::BUSY)
}

pub fn initialize(app: &AppHandle, mode: Mode) {
    if !mode.headless() && installation::needed() {
        let _ = installation::start_setup(app);
        return;
    }
    if !enabled(app.config()) { if mode.headless() { app.exit(0); } return; }
    let app = app.clone();
    std::thread::spawn(move || {
        let Ok(directory) = storage::directory() else { return; };
        if installation::remember_session(&directory).is_err() { return; }
        let state = load(&directory);
        if state.as_ref().is_ok_and(|state| state.pending.as_ref().is_some_and(|pending| pending.manual))
            || (!directory.join("disabled").exists()
                && state.map_or(true, |state| state.pending.is_some() || due(state.attempted_at, timestamp()))) {
            let _ = installation::start();
        }
        loop {
            // The worker waits for this window's lock before replacing files.
            if load(&directory).ok().is_some_and(|state|
                handoff_requested(&directory, &state, current_build()["version"].as_str().unwrap_or(""))) {
                app.exit(0);
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value { serde_json::from_str(include_str!("release-fixture.json")).unwrap() }

    #[test]
    fn pending_updates_close_windows_only_for_a_live_enabled_handoff() {
        let fixture = fixture();
        let key = fixture["key"].as_str().unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("desktop");
        storage::private_directory(&directory).unwrap();
        let mut state = State { state:"installing".into(), pending:Some(Pending {
            release:next.clone(), previous:previous.clone(), reopen_window:true, manual:false,
        }), ..State::default() };
        assert!(!handoff_requested(&directory, &state, &previous.version));
        let worker = storage::lock(&directory, "handoff.lock").unwrap();
        assert!(handoff_requested(&directory, &state, &previous.version));
        assert!(!handoff_requested(&directory, &state, &next.version));
        for phase in ["error", "checking", "downloading"] {
            state.state = phase.into();
            assert!(!handoff_requested(&directory, &state, &previous.version), "{phase}");
        }
        state.state = "installing".into();
        storage::write(&directory.join("disabled"), b"disabled\n", false).unwrap();
        assert!(!handoff_requested(&directory, &state, &previous.version));
        state.pending.as_mut().unwrap().manual = true;
        assert!(handoff_requested(&directory, &state, &previous.version), "Explicit installation works with automatic updates disabled");
        assert!(directory.join("disabled").exists());
        fs::remove_file(directory.join("disabled")).unwrap();
        drop(worker);
        assert!(!handoff_requested(&directory, &state, &previous.version));
        save(&directory, &state).unwrap();
        assert_eq!(read_state(&directory).unwrap().state, "installing", "Retained installation must remain recoverable");
        state.pending = None;
        let active = storage::lock(&directory, "updater.lock").unwrap();
        state.set(&directory, "downloading").unwrap();
        assert_eq!(read_state(&directory).unwrap().state, "downloading");
        drop(active);
        let recovered = read_state(&directory).unwrap();
        assert_eq!(recovered.state, "error");
        assert!(recovered.error.unwrap().contains("interrupted"));
    }

    #[test]
    fn handoff_replaces_a_newer_sensor_with_the_opened_app_version() {
        let fixture = fixture();
        let key = fixture["key"].as_str().unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let source = scratch.path().join("bundled");
        let target = scratch.path().join("bin");
        fs::create_dir(&target).unwrap();
        for (path, build) in [(&source, &previous.build), (&target.join("openaidr"), &next.build)] {
            let script = format!(r#"#!/usr/bin/env python3
import json, sys
build = json.loads({:?})
if sys.argv[1] == 'version': print(build['version'])
elif sys.argv[1] == 'build-info': print(json.dumps(build))
elif sys.argv[1] == 'desktop-bridge':
    action = json.load(sys.stdin)['action']
    data = {{'enrolled': True, 'running': True, 'service_version': build['version']}} if action == 'status' else {{'steps': [{{'ok': True}}]}}
    print(json.dumps({{'ok': True, 'data': data}}))
"#, build.to_string());
            storage::write(path, script.as_bytes(), true).unwrap();
        }
        stage_and_finish_sensor(&source, &target, Duration::ZERO).unwrap();
        for name in ["openaidr", "openaidr-sensor"] {
            assert_eq!(crate::sensor_build(&target.join(name)), previous.build);
        }
    }

    #[test]
    fn rollout_and_publication_order_gate_appimage_downloads() {
        let fixture = fixture();
        let key = fixture["key"].as_str().unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let policy = json!({"schema_version":1,"starts_at":"2026-10-07T03:00:00Z","paused":false,
            "steps":[{"after_hours":0,"percent":100},{"after_hours":24,"percent":100}]});
        for case in ["eligible", "paused", "excluded", "future", "missing", "invalid", "tampered"] {
            let mut manifest = fixture["manifest"].clone();
            manifest["rollout"] = policy.clone();
            match case {
                "paused" => manifest["rollout"]["paused"] = json!(true),
                "excluded" => manifest["rollout"]["steps"][0]["percent"] = json!(0),
                "future" => manifest["rollout"]["starts_at"] = json!("2026-10-08T03:00:00Z"),
                "missing" => manifest.as_object_mut().unwrap().remove("rollout").map(|_| ()).unwrap(),
                "invalid" => manifest["rollout"]["schema_version"] = json!(2),
                "tampered" => manifest["platforms"][release::TARGET]["metadata_signature"] = json!("changed"),
                _ => {},
            }
            let result = selected_release(&manifest, &previous, id, 1791342000, key, Intent::Automatic);
            for intent in [Intent::Check, Intent::Install(&next.version)] {
                let manual = selected_release(&manifest, &previous, "", 0, key, intent);
                if matches!(case, "missing" | "invalid" | "tampered") {
                    assert!(manual.is_err(), "{case}");
                } else {
                    assert_eq!(manual.unwrap().unwrap().version, next.version, "{case}");
                    assert!(selected_release(&manifest, &previous, "", 0, key, Intent::Install(&previous.version)).is_err());
                    assert!(selected_release(&manifest, &next, "", 0, key, intent).unwrap().is_none());
                }
            }
            match case {
                "eligible" => {
                    assert_eq!(result.unwrap().unwrap().version, next.version);
                    assert!(selected_release(&manifest, &next, id, 1791342000, key, Intent::Automatic).unwrap().is_none());
                },
                "missing" | "invalid" | "tampered" => assert!(result.is_err(), "{case}"),
                _ => assert!(result.unwrap().is_none(), "{case}"),
            }
        }
        assert!(!due(Some(1000), 1000 + 5 * 60));
        assert!(due(Some(1000), 1000 + INTERVAL));
        assert!(due(Some(1000), 999));
    }

    #[test]
    fn manual_downloads_report_progress_cancel_and_enforce_size_and_signatures() {
        use std::{io::{Read, Write}, net::TcpListener};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fixture = fixture();
        let public_key = fixture["key"].as_str().unwrap();
        let release = release::from_manifest(&fixture["manifest"], public_key).unwrap();
        let payload = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        for case in ["complete", "cancel", "oversized", "unannounced", "tampered"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let mut body = payload.clone();
            if case == "tampered" { body[0] ^= 1; }
            let (release_body, resume) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                    let mut byte = [0];
                    if stream.read(&mut byte).unwrap_or(0) == 0 { return; }
                    request.push(byte[0]);
                }
                let header = if case == "unannounced" { String::new() }
                    else { format!("Content-Length: {}\r\n", body.len()) };
                write!(stream, "HTTP/1.1 200 OK\r\n{header}Connection: close\r\n\r\n").unwrap();
                if case == "cancel" {
                    stream.write_all(&body[..1]).unwrap();
                    // The peer holds the body open until cancellation is observed.
                    let _ = resume.recv_timeout(Duration::from_secs(5));
                } else { let _ = stream.write_all(&body); }
            });
            tauri::async_runtime::block_on(async {
                let task = ManualTask::default();
                let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
                let response = client.get(url).send().await.unwrap();
                let mut progress = Vec::new();
                let progressed = tokio::sync::Notify::new();
                let limit = if matches!(case, "oversized" | "unannounced") { 1 } else { MAX_DOWNLOAD };
                let scratch = tempfile::tempdir().unwrap();
                let download = task.run(super::super::update_download::receive(response, scratch.path(), limit, |bytes, total| {
                    progress.push((bytes, total));
                    progressed.notify_one();
                }));
                let result = if case == "cancel" {
                    let cancel = async {
                        progressed.notified().await;
                        task.cancel().unwrap();
                    };
                    let (result, ()) = tokio::join!(download, cancel);
                    release_body.send(()).unwrap();
                    assert!(task.begin_install().is_err());
                    result
                } else { download.await };
                match case {
                    "complete" => {
                        let mut file = result.unwrap();
                        assert_eq!(fs::read(file.path()).unwrap(), payload);
                        release.verify_file(file.as_file_mut(), public_key).unwrap();
                        assert_eq!(progress.last(), Some(&(payload.len() as u64, Some(payload.len() as u64))));
                        task.begin_install().unwrap();
                        assert!(task.cancel().is_err());
                    },
                    "tampered" => assert!(release.verify_file(result.unwrap().as_file_mut(), public_key).is_err()),
                    "cancel" => assert!(result.unwrap_err().contains("cancelled")),
                    _ => assert!(result.unwrap_err().contains("size limit")),
                }
            });
            server.join().unwrap();
        }
    }

    #[test]
    fn atomic_replacement_recovers_and_preserves_unknown_installations() {
        let fixture = fixture();
        let key = fixture["key"].as_str().unwrap();
        let next = release::from_manifest(&fixture["manifest"], key).unwrap();
        let previous = release::from_manifest(&fixture["previous"]["manifest"], key).unwrap();
        let old_bytes = STANDARD.decode(fixture["previous"]["installer"].as_str().unwrap()).unwrap();
        let new_bytes = STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap();
        for case in ["normal", "after_rename", "tampered", "candidate_missing", "backup_conflict", "unknown", "removed"] {
            let scratch = tempfile::tempdir().unwrap();
            let private = scratch.path().join("desktop");
            storage::private_directory(&private).unwrap();
            let directory = private.as_path();
            let guard = storage::lock(directory, "operation.lock").unwrap();
            let id = storage::installation_id(directory, &guard).unwrap();
            let image = directory.join(IMAGE);
            storage::write(&image, &old_bytes, true).unwrap();
            storage::write(&candidate_path(directory, &next), &new_bytes, true).unwrap();
            let pending = Pending { release:next.clone(), previous:previous.clone(), reopen_window:true, manual:false };
            let state = State { pending:Some(pending.clone()), ..State::default() };
            save(directory, &state).unwrap();
            let enrollment = directory.join("sensor.yaml");
            fs::write(&enrollment, b"retained enrollment").unwrap();
            match case {
                "after_rename" => fs::rename(candidate_path(directory, &next), &image).unwrap(),
                "tampered" => fs::write(candidate_path(directory, &next), b"tampered").unwrap(),
                "candidate_missing" => fs::remove_file(candidate_path(directory, &next)).unwrap(),
                "backup_conflict" => fs::create_dir(directory.join("previous.AppImage")).unwrap(),
                "unknown" => fs::write(&image, b"unrecognized app").unwrap(),
                "removed" => fs::remove_file(&image).unwrap(),
                _ => {},
            }
            let before = fs::read(&image).ok();
            let result = replace_image(directory, &pending, key);
            if matches!(case, "normal" | "after_rename") {
                result.unwrap();
                replace_image(directory, &pending, key).unwrap();
                assert_eq!(fs::read(&image).unwrap(), new_bytes);
                let saved: release::Release = serde_json::from_value(storage::json_file(&directory.join(RECORD)).unwrap().unwrap()).unwrap();
                assert_eq!(saved.revalidate(key).unwrap().build, next.build);
                if case == "normal" { assert_eq!(fs::read(directory.join("previous.AppImage")).unwrap(), old_bytes); }
            } else {
                assert!(result.is_err(), "{case}");
                assert_eq!(fs::read(&image).ok(), before);
            }
            assert!(load(directory).unwrap().pending.is_some());
            assert_eq!(storage::installation_id(directory, &guard).unwrap(), id);
            assert_eq!(fs::read(&enrollment).unwrap(), b"retained enrollment");
        }
    }
}
