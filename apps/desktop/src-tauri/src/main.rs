#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Deserialize;
use serde_json::{json, Value};
#[cfg(not(windows))]
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{atomic::{AtomicU64, Ordering}, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};
use tauri::Manager;

#[cfg(target_os = "macos")]
use platform::macos::menu_bar;
#[cfg(any(windows, target_os = "linux"))]
use platform::menu_bar;

mod platform;
mod removal_progress;
mod about;
mod links;
mod local_dashboard;
#[cfg(target_os = "macos")]
mod sensor_runtime;
mod simulation;
mod usage;
mod window_fit;

use platform::updater;
#[cfg(target_os = "macos")]
use platform::macos::{
    single_instance,
    window::{listen_for_activation, reopen_single_window},
};

/// The bundled sensor is a console program. Without this flag Windows opens a
/// console window for every status read and setup step.
#[cfg(windows)]
fn hide_console(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console(_command: &mut Command) {}

#[derive(Default)]
struct SensorSnapshot(Mutex<Option<Value>>);

#[derive(Default)]
struct EnrollmentPreviews(AtomicU64);

impl EnrollmentPreviews {
    fn invalidate(&self) -> Result<u64, String> {
        self.0.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation| generation.checked_add(1))
            .map(|previous| previous + 1)
            .map_err(|_| "Restart the app to preview another enrollment link.".into())
    }
}

#[derive(Clone, Copy)]
struct PreviewCancellation<'a> {
    previews: &'a EnrollmentPreviews,
    generation: u64,
}

fn check_preview(preview: Option<PreviewCancellation<'_>>) -> Result<(), String> {
    if preview.is_some_and(|preview| preview.previews.0.load(Ordering::SeqCst) != preview.generation) {
        return Err("The enrollment preview was cancelled.".into());
    }
    Ok(())
}

fn lock_sensor<'a>(gate: &'a Mutex<()>, preview: Option<PreviewCancellation<'_>>) -> Result<MutexGuard<'a, ()>, String> {
    let guard = gate.lock().map_err(|_| "Sensor request lock unavailable.")?;
    check_preview(preview)?;
    Ok(guard)
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum GuardrailAgent { Codex, Claude, Copilot, Cursor, Antigravity, Opencode, Hermes, Workbuddy }

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum GuardrailDecision { Ask, Deny }

// The window exposes fixed setup operations, never commands or user-supplied file paths.
#[derive(Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
enum Request {
    #[serde(rename = "status")]
    Status {},
    #[serde(rename = "credits.summary")]
    CreditsSummary {},
    #[serde(rename = "free.usage")]
    FreeUsage {},
    #[serde(rename = "usage.summary")]
    UsageSummary { days: u8 },
    #[serde(rename = "posture.summary")]
    PostureSummary {},
    #[serde(rename = "posture.configure")]
    PostureConfigure { automatic: bool, scope: String },
    #[serde(rename = "guardrails.summary")]
    GuardrailsSummary { days: u8 },
    #[serde(rename = "guardrails.denials")]
    GuardrailsDenials { days: u8, until: String, cursor: String, review_version: Option<u8>, decision: Option<GuardrailDecision> },
    #[serde(rename = "guardrails.check")]
    GuardrailsCheck { id: String, scope: String, review_version: Option<u8>, decision: Option<GuardrailDecision> },
    #[serde(rename = "guardrails.review")]
    GuardrailsReview { id: String, scope: String, label: String, note: String, review_version: Option<u8>,
        evidence_sha256: Option<String>, expected_revision: Option<u64>, request_id: Option<String> },
    #[serde(rename = "guardrails.configure")]
    GuardrailsConfigure { agent: GuardrailAgent, enabled: bool, profile: Option<String> },
    #[serde(rename = "guardrails.configuration")]
    GuardrailsConfiguration { agent: GuardrailAgent, profile: Option<String> },
    #[serde(rename = "alerts.list")]
    AlertsList {},
    #[serde(rename = "alerts.received")]
    AlertsReceived { ids: Vec<String>, scope: String },
    #[serde(rename = "alerts.acknowledge")]
    AlertsAcknowledge { id: String, scope: String },
    #[serde(rename = "alerts.focus")]
    AlertsFocus {},
    #[serde(rename = "enrollment.preview")]
    EnrollmentPreview { link: String, ca_certificate: Option<String>, generation: u64 },
    #[serde(rename = "enrollment.preview.invalidate")]
    EnrollmentPreviewInvalidate {},
    #[serde(rename = "enrollment.connect")]
    EnrollmentConnect { link: String, tenant_id: String, ca_certificate: Option<String> },
    #[serde(rename = "free.connect")]
    FreeConnect {},
    #[serde(rename = "local-runtime.check")]
    LocalRuntimeCheck {},
    #[serde(rename = "local-runtime.docker-setup")]
    LocalRuntimeDockerSetup {},
    #[serde(rename = "local-runtime.prepare")]
    LocalRuntimePrepare {},
    #[serde(rename = "local-runtime.start")]
    LocalRuntimeStart {},
    #[serde(rename = "local-runtime.connect")]
    LocalRuntimeConnect { password: String },
    #[serde(rename = "local-runtime.credentials")]
    LocalRuntimeCredentials {},
    #[serde(rename = "api-key.connect")]
    ApiKeyConnect { api_key: String },
    #[serde(rename = "proxy.status")]
    ProxyStatus {},
    #[serde(rename = "proxy.test")]
    ProxyTest { mode: String, #[serde(default)] url: String, #[serde(default)] bypass: Vec<String>,
        #[serde(default)] username: String, #[serde(default)] password: Option<String> },
    #[serde(rename = "proxy.save")]
    ProxySave { mode: String, #[serde(default)] url: String, #[serde(default)] bypass: Vec<String>,
        #[serde(default)] username: String, #[serde(default)] password: Option<String> },
    #[serde(rename = "setup")]
    Setup {},
    #[serde(rename = "desktop.capabilities")]
    Capabilities {},
    #[serde(rename = "desktop.support")]
    Support {},
    #[serde(rename = "desktop.dashboard")]
    Dashboard { server_url: String },
    #[serde(rename = "desktop.update.status")]
    UpdateStatus {},
    #[serde(rename = "desktop.update.check")]
    UpdateCheck {},
    #[serde(rename = "desktop.update.install")]
    UpdateInstall { version: String },
    #[serde(rename = "desktop.update.cancel")]
    UpdateCancel {},
    #[serde(rename = "desktop.remove")]
    Remove {},
    #[serde(rename = "desktop.resume")]
    Resume {},
    #[serde(rename = "desktop.trash")]
    Trash { #[serde(default)] delete_data: bool },
    #[serde(rename = "simulation.status")]
    SimulationStatus {},
    #[serde(rename = "simulation.start")]
    SimulationStart {},
    #[serde(rename = "simulation.stop")]
    SimulationStop {},
}

impl Request {
    fn payload(self) -> Result<Value, String> {
        Ok(match self {
            Self::Status {} => json!({"action":"status"}),
            Self::CreditsSummary {} => json!({"action":"credits.summary"}),
            Self::FreeUsage {} => json!({"action":"free.usage"}),
            Self::PostureSummary {} => json!({"action":"posture.summary"}),
            Self::PostureConfigure { automatic, scope } => {
                if !valid_alert_scope(&scope) { return Err("Invalid Posture connection scope.".into()); }
                json!({"action":"posture.configure","params":{"automatic":automatic,"scope":scope}})
            }
            Self::GuardrailsSummary { days } => {
                if !matches!(days, 1 | 30) { return Err("Choose 1 or 30 days.".into()); }
                json!({"action":"guardrails.summary","params":{"days":days}})
            }
            Self::GuardrailsDenials { days, until, cursor, review_version, decision } => {
                if !matches!(days, 1 | 30) || until.len() > 64 || cursor.len() > 256 {
                    return Err("Invalid denial window.".into());
                }
                let mut params = json!({"days":days,"until":until,"cursor":cursor});
                if let Some(version) = review_version {
                    if version != 1 { return Err("Unsupported review version.".into()); }
                    params["review_version"] = json!(version);
                }
                if let Some(value) = decision { params["decision"] = json!(value); }
                json!({"action":"guardrails.denials","params":params})
            }
            Self::GuardrailsCheck { id, scope, review_version, decision } => {
                if !valid_alert_id(&id) || !valid_alert_scope(&scope) { return Err("Invalid check identity.".into()); }
                let mut params = json!({"id":id,"scope":scope});
                if let Some(version) = review_version {
                    if version != 1 { return Err("Unsupported review version.".into()); }
                    params["review_version"] = json!(version);
                }
                if let Some(value) = decision { params["decision"] = json!(value); }
                json!({"action":"guardrails.check","params":params})
            }
            Self::GuardrailsReview { id, scope, label, note, review_version, evidence_sha256, expected_revision, request_id } => {
                if !valid_alert_id(&id) || !valid_alert_scope(&scope)
                    || !(matches!(label.as_str(), "correct_denial" | "false_positive")
                        || review_version == Some(1) && label == "insufficient_context")
                    || note.chars().count() > 2000 || note.contains('\0') {
                    return Err("Invalid check review.".into());
                }
                let mut params = json!({"id":id,"scope":scope,"label":label,"note":note});
                if review_version == Some(1) {
                    if !evidence_sha256.as_deref().is_some_and(valid_alert_scope) || expected_revision.is_none()
                        || !request_id.as_deref().is_some_and(valid_alert_id) { return Err("Invalid review evidence.".into()); }
                    params["review_version"] = json!(1);
                    params["evidence_sha256"] = json!(evidence_sha256);
                    params["expected_revision"] = json!(expected_revision);
                    params["request_id"] = json!(request_id);
                } else if review_version.is_some() || evidence_sha256.is_some() || expected_revision.is_some() || request_id.is_some() {
                    return Err("Unsupported review version.".into());
                }
                json!({"action":"guardrails.review","params":params})
            }
            Self::GuardrailsConfigure { agent, enabled, profile } => {
                let mut params = json!({"agent":agent,"enabled":enabled});
                if let Some(profile) = profile { params["profile"] = json!(profile); }
                json!({"action":"guardrails.configure","params":params})
            }
            Self::GuardrailsConfiguration { agent, profile } => {
                let mut params = json!({"agent":agent});
                if let Some(profile) = profile { params["profile"] = json!(profile); }
                json!({"action":"guardrails.configuration","params":params})
            }
            Self::AlertsList {} => json!({"action":"alerts.list"}),
            Self::AlertsReceived { ids, scope } => {
                if ids.is_empty() || ids.len() > 100 || ids.iter().any(|id| !valid_alert_id(id)) || !valid_alert_scope(&scope) {
                    return Err("Invalid alert receipt.".into());
                }
                json!({"action":"alerts.received","params":{"ids":ids,"scope":scope}})
            }
            Self::AlertsAcknowledge { id, scope } => {
                if !valid_alert_id(&id) || !valid_alert_scope(&scope) { return Err("Invalid alert receipt.".into()); }
                json!({"action":"alerts.acknowledge","params":{"id":id,"scope":scope}})
            }
            Self::AlertsFocus {} => return Err("Alert focus must be handled by the desktop app.".into()),
            Self::UsageSummary { days } => {
                if !matches!(days, 1 | 7 | 14 | 30) {
                    return Err("Choose 1, 7, 14, or 30 days.".into());
                }
                json!({"action":"usage.summary","params":{"days":days}})
            }
            Self::EnrollmentPreview { link, ca_certificate, .. } => {
                json!({"action":"enrollment.preview","params":enrollment_params(link, ca_certificate)?})
            }
            Self::EnrollmentPreviewInvalidate {} => {
                return Err("Preview cancellation must be handled by the desktop app.".into());
            }
            Self::EnrollmentConnect { link, tenant_id, ca_certificate } => {
                let mut params = enrollment_params(link, ca_certificate)?;
                if tenant_id.len() != 36 {
                    return Err("Preview the organization before connecting.".into());
                }
                params["tenant_id"] = json!(tenant_id);
                json!({"action":"enrollment.connect","params":params})
            }
            Self::Setup {} => json!({"action":"desktop.update.setup"}),
            Self::FreeConnect {} => json!({"action":"free.connect"}),
            Self::LocalRuntimeCheck {} => json!({"action":"local-runtime.check"}),
            Self::LocalRuntimeDockerSetup {} => json!({"action":"local-runtime.docker-setup"}),
            Self::LocalRuntimePrepare {} => json!({"action":"local-runtime.prepare"}),
            Self::LocalRuntimeStart {} => json!({"action":"local-runtime.start"}),
            Self::LocalRuntimeCredentials {} => json!({"action":"local-runtime.credentials"}),
            Self::LocalRuntimeConnect { password } => {
                if password.len() > 1024 { return Err("Enter a valid local administrator password.".into()); }
                json!({"action":"local-runtime.connect","params":{"password":password}})
            }
            Self::ApiKeyConnect { api_key } => {
                let key = api_key.trim();
                if key.is_empty() || key.len() > 256 {
                    return Err("Enter a valid OpenSecura API key.".into());
                }
                json!({"action":"api-key.connect","params":{"api_key":key}})
            }
            Self::ProxyStatus {} => json!({"action":"proxy.status"}),
            Self::ProxyTest { mode, url, bypass, username, password } =>
                proxy_payload("proxy.test", mode, url, bypass, username, password)?,
            Self::ProxySave { mode, url, bypass, username, password } =>
                proxy_payload("proxy.save", mode, url, bypass, username, password)?,
            Self::Capabilities {} => json!({"action":"desktop.capabilities"}),
            Self::Support {} => return Err("Support must be handled by the desktop app.".into()),
            Self::Dashboard { .. } => return Err("Dashboard links must be handled by the desktop app.".into()),
            Self::UpdateStatus {} => {
                return Err("Update status must be handled by the desktop app.".into());
            }
            Self::UpdateCheck {} | Self::UpdateInstall { .. } | Self::UpdateCancel {} => {
                return Err("Updates must be handled by the desktop app.".into());
            }
            Self::Remove {} => json!({"action":"desktop.remove"}),
            Self::Resume {} => json!({"action":"desktop.resume"}),
            Self::Trash { delete_data } => json!({"action":"desktop.trash","delete_data":delete_data}),
            Self::SimulationStatus {} => json!({"action":"simulation.status"}),
            Self::SimulationStart {} | Self::SimulationStop {} if !cfg!(all(feature = "simulation", unix)) => {
                return Err("Device simulation is unavailable in this build.".into());
            }
            Self::SimulationStart {} => json!({"action":"simulation.start"}),
            Self::SimulationStop {} => json!({"action":"simulation.stop"}),
        })
    }
}

fn valid_alert_id(id: &str) -> bool {
    id.len() == 36 && id.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' } else { byte.is_ascii_hexdigit() }
    })
}

fn valid_alert_scope(scope: &str) -> bool {
    scope.len() == 64 && scope.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn enrollment_params(link: String, ca_certificate: Option<String>) -> Result<Value, String> {
    if link.trim().is_empty() || link.len() > 8192 {
        return Err("Paste an enrollment link of at most 8192 bytes.".into());
    }
    let mut params = json!({"link":link});
    if let Some(pem) = ca_certificate {
        // The sensor validates certificate contents before any network request.
        if pem.is_empty() || !pem.is_ascii() || pem.len() > 32 * 1024 {
            return Err("Choose an ASCII PEM certificate file of at most 32 KiB.".into());
        }
        params["ca_certificate"] = json!(pem);
    }
    Ok(params)
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    if fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err("The sensor installation path must not be a symbolic link.".into());
    }
    Ok(())
}

#[cfg(windows)]
fn bundled_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    platform::bundled_sensor(app)
}

#[cfg(not(windows))]
fn bundled_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    let executable = {
        let _ = app;
        // Tauri's current_binary points to the outer AppImage. Sidecars are
        // beside the executable inside its mounted or extracted filesystem.
        std::env::current_exe().map_err(|e| e.to_string())?
    };
    #[cfg(not(target_os = "linux"))]
    let executable = tauri::process::current_binary(&app.env()).map_err(|e| e.to_string())?;
    let directory = executable.parent().ok_or("Cannot locate the application directory.")?;
    let canonical = directory.join(platform::SENSOR_BINARY);
    Ok(if canonical.symlink_metadata().is_ok() { canonical }
        else { directory.join("openaidr-sensor") })
}

/// Windows runs the sensor from the installation: it starts without
/// extraction, and installing the background service stages a versioned
/// per-user copy itself (src/openaidr/sensor/windows_runtime.py).
#[cfg(windows)]
fn stable_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let binary = bundled_binary(app)?;
    reject_symlink(&binary)?;
    require_sensor_version(&binary, &app.package_info().version.to_string())?;
    Ok(binary)
}

#[cfg(not(windows))]
fn stable_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let source = bundled_binary(app)?;
    require_sensor_version(&source, &app.package_info().version.to_string())?;
    let home = app.path().home_dir().map_err(|e| e.to_string())?;
    let base = platform::sensor_directory(app, &home)?;
    reject_symlink(&base)?;
    let directory = base.join("bin");
    reject_symlink(&directory)?;
    fs::create_dir_all(&directory)
        .map_err(|e| format!("Cannot create the sensor installation directory: {e}"))?;
    stage_binary(&source, &directory)
}

#[cfg(not(windows))]
fn stage_binary(source: &Path, directory: &Path) -> Result<PathBuf, String> {
    let destinations = [directory.join(platform::SENSOR_BINARY), directory.join("openaidr-sensor")];
    reject_symlink(source)?;
    for path in &destinations { reject_symlink(path)?; }
    let source_bytes = fs::read(source).map_err(|_| {
        "Bundled sensor is missing. Build the Python sidecar before building the desktop app."
    })?;
    #[cfg(target_os = "macos")]
    if let Some(runtime) = sensor_runtime::Runtime::inspect(source, &source_bytes)? {
        reject_symlink(directory)?;
        runtime.stage(directory)?;
    }
    let bytes = source_bytes;
    for destination in &destinations {
        if fs::read(destination)
            .map(|old| Sha256::digest(old) == Sha256::digest(&bytes))
            .unwrap_or(false)
        {
            continue;
        }
        let temporary = directory.join(format!(".{}-{}.tmp", destination.file_name().unwrap().to_string_lossy(), std::process::id()));
        reject_symlink(&temporary)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let result = (|| {
            let mut output = options.open(&temporary).map_err(|e| e.to_string())?;
            output.write_all(&bytes).map_err(|e| e.to_string())?;
            output.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&temporary, destination).map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
    }
    Ok(destinations[0].clone())
}

/// The version an executable reports, or None when it cannot run or answer.
#[cfg(not(windows))]
fn sensor_version(executable: &Path) -> Option<String> {
    let mut command = Command::new(executable);
    command.arg("version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    hide_console(&mut command);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().ok()?;
    let (status, output) = child_output(&mut child, Duration::from_secs(60), 4096).ok()?;
    if !status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output);
    let word = text.lines().next()?.split_whitespace().last()?.trim().to_owned();
    version_key(&word).map(|_| word)
}

fn child_output(
    child: &mut std::process::Child,
    timeout: Duration,
    limit: u64,
) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    child_output_pending(child, timeout, limit, None, None)
}

fn child_output_pending(
    child: &mut std::process::Child,
    timeout: Duration,
    limit: u64,
    preview: Option<PreviewCancellation<'_>>,
    input: Option<thread::JoinHandle<Result<(), String>>>,
) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    child_output_progress(child, timeout, limit, preview, input, None)
}

fn child_output_progress(
    child: &mut std::process::Child, timeout: Duration, limit: u64,
    preview: Option<PreviewCancellation<'_>>, mut input: Option<thread::JoinHandle<Result<(), String>>>,
    mut progress: Option<&mut removal_progress::Progress>,
) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    let stderr = if progress.is_some() { child.stderr.take().map(removal_progress::read_helper) } else { None };
    let stdout = child.stdout.take().ok_or("Cannot read sensor output.")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(limit + 1).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    loop {
        if let (Some(progress), Some((receive, _))) = (progress.as_deref_mut(), &stderr) {
            for event in receive.try_iter() { progress.helper(event); }
        }
        if let Err(error) = check_preview(preview) {
            stop_child(child);
            return Err(error);
        }
        if input.as_ref().is_some_and(|writer| writer.is_finished()) {
            let result = input.take().unwrap().join()
                .map_err(|_| "Sensor request writer failed.".to_string())
                .and_then(|result| result);
            if let Err(error) = result {
                stop_child(child);
                return Err(error);
            }
        }
        match child.try_wait() {
            Ok(Some(status)) if reader.is_finished() && input.is_none() && stderr.as_ref().is_none_or(|(_, reader)| reader.is_finished()) => {
                if let (Some(progress), Some((receive, _))) = (progress.as_deref_mut(), &stderr) {
                    for event in receive.try_iter() { progress.helper(event); }
                }
                let output = reader.join().map_err(|_| "Sensor response reader failed.")?
                    .map_err(|_| "Cannot read sensor response.")?;
                if output.len() as u64 > limit {
                    return Err("Sensor response exceeded the size limit.".into());
                }
                return Ok((status, output));
            }
            Err(_) => {
                stop_child(child);
                return Err("Cannot check the sensor process.".into());
            }
            _ => {}
        }
        if started.elapsed() >= timeout {
            stop_child(child);
            // A descendant can retain stdout after its parent exits. Never
            // join a reader still waiting on that pipe while holding a lock.
            return Err(format!("The sensor did not respond within {} seconds. Check the background service and try again.", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn stop_child(child: &mut std::process::Child) {
    #[cfg(target_os = "macos")]
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        // End the sensor's whole process tree, not only the direct child.
        let mut taskkill = Command::new("taskkill");
        taskkill
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        hide_console(&mut taskkill);
        let _ = taskkill.status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// PEP 440 style ordering key: dev < alpha < beta < rc < final < post, with
/// trailing zeros in the release ignored. Mirrors the Python sensor's key.
#[cfg_attr(windows, allow(dead_code))]
fn version_key(text: &str) -> Option<(Vec<u64>, i64, u64, i64, (u8, u64))> {
    let text = if let Some((date, commit)) = text.split_once('+') {
        if date.split('.').next()?.len() != 4 || !(7..=40).contains(&commit.len())
            || !commit.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return None;
        }
        date
    } else { text };
    let mut rest = text.trim().strip_prefix('v').unwrap_or(text.trim());
    let mut release = Vec::new();
    loop {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return None;
        }
        release.push(digits.parse().ok()?);
        rest = &rest[digits.len()..];
        match rest.strip_prefix('.') {
            Some(after) if after.starts_with(|c: char| c.is_ascii_digit()) => rest = after,
            _ => break,
        }
    }
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let lower = rest.to_ascii_lowercase();
    let mut tail = lower.as_str();
    let mut rank = 3;
    let mut pre_n = 0;
    let mut post = -1;
    let mut dev = (1, 0);
    fn number(s: &str) -> (u64, usize) {
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        (digits.parse().unwrap_or(0), digits.len())
    }
    fn strip_sep(s: &str) -> &str {
        s.trim_start_matches(['-', '.', '_'])
    }
    tail = strip_sep(tail);
    for (name, value) in [("alpha", 0), ("a", 0), ("beta", 1), ("b", 1), ("rc", 2), ("c", 2), ("preview", 2), ("pre", 2)] {
        if let Some(after) = tail.strip_prefix(name) {
            let after = strip_sep(after);
            let (n, used) = number(after);
            rank = value;
            pre_n = n;
            tail = strip_sep(&after[used..]);
            break;
        }
    }
    if let Some(after) = tail.strip_prefix("post") {
        let after = strip_sep(after);
        let (n, used) = number(after);
        post = n as i64;
        tail = strip_sep(&after[used..]);
    }
    if let Some(after) = tail.strip_prefix("dev") {
        let after = strip_sep(after);
        let (n, used) = number(after);
        dev = (0, n);
        if rank == 3 && post < 0 {
            rank = -1;
        }
        tail = strip_sep(&after[used..]);
    }
    if !tail.is_empty() {
        return None;
    }
    Some((release, rank, pre_n, post, dev))
}

fn require_sensor_version(executable: &Path, expected: &str) -> Result<(), String> {
    reject_symlink(executable)?;
    #[cfg(target_os = "macos")]
    sensor_runtime::Runtime::inspect(executable,
        &fs::read(executable).map_err(|_| "Cannot read the bundled sensor.")?)?;
    let build = sensor_build(executable);
    if build["version"].as_str() != Some(expected) || build_order(expected, &build).is_none() {
        return Err(format!("The bundled sensor does not match OpenAIDR {expected}. Reinstall this app."));
    }
    Ok(())
}

fn sensor_build(executable: &Path) -> Value {
    let mut command = Command::new(executable);
    command.arg("build-info").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    hide_console(&mut command);
    let Ok(mut child) = command.spawn() else { return Value::Null; };
    let Ok((status, output)) = child_output(&mut child, Duration::from_secs(60), 16384) else { return Value::Null; };
    if !status.success() { return Value::Null; }
    serde_json::from_slice(&output).unwrap_or(Value::Null)
}

#[cfg(not(windows))]
#[derive(Clone)]
struct SensorMetadata {
    version: Option<String>,
    build: Value,
}

#[cfg(not(windows))]
fn sensor_metadata(executable: &Path) -> SensorMetadata {
    let build = sensor_build(executable);
    let version = build["version"].as_str()
        .filter(|version| version.contains('+') && version_key(version).is_some())
        .map(str::to_owned)
        .or_else(|| sensor_version(executable));
    SensorMetadata { version, build }
}

fn build_order(version: &str, info: &Value) -> Option<(Vec<u64>, i64, u64, i64, (u8, u64))> {
    let legacy = version_key(version)?;
    let Some((_, prefix)) = version.split_once('+') else { return Some(legacy); };
    if info["version"].as_str()? != version { return None; }
    let commit = info["source_commit"].as_str()?;
    if commit.len() != 40 || !commit.starts_with(prefix)
        || !commit.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let source = info["source_timestamp"].as_u64()?;
    if source == 0 { return None; }
    let (published, stamp) = if info["published_at"].is_string() {
        (1, info["publication_timestamp"].as_u64()?)
    } else {
        if !info["published_at"].is_null() || !info["publication_timestamp"].is_null() { return None; }
        (0, source)
    };
    if stamp == 0 { return None; }
    Some((vec![10000, published, stamp], 3, 0, -1, (1, 0)))
}

fn newer_build(incoming: &str, existing: &str, new: &Value, old: &Value) -> bool {
    incoming != existing && match (build_order(incoming, new), build_order(existing, old)) {
        (Some(after), Some(before)) => after > before,
        _ => false,
    }
}

/// Bounds proxy settings from the window. The sensor validates them fully and keeps
/// the password only in the system credential store.
fn proxy_payload(action: &str, mode: String, url: String, bypass: Vec<String>, username: String,
    password: Option<String>) -> Result<Value, String> {
    if mode == "direct" {
        return Ok(json!({"action":action,"params":{"mode":"direct"}}));
    }
    if mode != "manual" || url.trim().is_empty() || url.len() > 2048 || bypass.len() > 64
        || bypass.iter().any(|host| host.is_empty() || host.len() > 255) || username.len() > 256
        || password.as_ref().is_some_and(|value| value.is_empty() || value.len() > 1024) {
        return Err("Enter valid proxy settings.".into());
    }
    let mut params = json!({"mode":"manual","url":url.trim(),"bypass":bypass,"username":username.trim()});
    if let Some(password) = password { params["password"] = json!(password); }
    Ok(json!({"action":action,"params":params}))
}

fn bridge(executable: &Path, payload: Value) -> Result<Value, String> {
    bridge_pending(executable, payload, None)
}

fn bridge_pending(executable: &Path, payload: Value, preview: Option<PreviewCancellation<'_>>) -> Result<Value, String> {
    bridge_reporting(executable, payload, preview, None)
}

fn bridge_reporting(executable: &Path, payload: Value, preview: Option<PreviewCancellation<'_>>, progress: Option<&mut removal_progress::Progress>) -> Result<Value, String> {
    check_preview(preview)?;
    let timeout = match payload["action"].as_str() {
        Some("local-runtime.prepare" | "local-runtime.docker-setup") => 1860,
        Some("local-runtime.start" | "desktop.resume") => 300,
        Some("enrollment.connect" | "free.connect" | "api-key.connect" | "local-runtime.connect" | "desktop.remove" | "desktop.purge" | "proxy.save") => 180,
        _ => 60,
    };
    let output_limit = if payload["action"] == "usage.summary" || payload["action"] == "alerts.list" { 8 * 1024 * 1024 } else { 1024 * 1024 };
    let mut command = Command::new(executable);
    command.arg("desktop-bridge").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    if progress.is_some() {
        command.env("OPENAIDR_REMOVAL_PROGRESS", "1").stderr(Stdio::piped());
    }
    hide_console(&mut command);
    if cfg!(all(feature = "simulation", unix)) && payload["action"] == "simulation.status" {
        command.env("OPENAIDR_DEVICE_SIMULATION", "1");
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    check_preview(preview)?;
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot start the sensor: {e}"))?;
    let mut input = child.stdin.take().ok_or("Cannot open sensor input.")?;
    let write_input = move || -> Result<(), String> {
        serde_json::to_writer(&mut input, &payload).map_err(|_| "Cannot send the sensor request.")?;
        input.write_all(b"\n").map_err(|_| "Cannot send the sensor request.")?;
        drop(input);
        Ok(())
    };
    // A preview can be cancelled even if its child has not started reading a
    // large link or certificate. Never wait for its input pipe on this thread.
    let writer = if preview.is_some() {
        Some(thread::spawn(write_input))
    } else {
        if let Err(error) = write_input() {
            stop_child(&mut child);
            return Err(error);
        }
        None
    };
    let (status, output) = child_output_progress(&mut child, Duration::from_secs(timeout), output_limit, preview, writer, progress)?;
    check_preview(preview)?;
    let response: Value = serde_json::from_slice(&output)
        .map_err(|_| "Sensor returned an invalid response.")?;
    if !status.success() || response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("The sensor operation failed.")
            .to_owned());
    }
    Ok(response.get("data").cloned().unwrap_or(Value::Null))
}

fn restart_updated_app(app: &tauri::AppHandle) {
    // Status reads from the menu bar must not reopen a closed window.
    // This also covers an update-status request that finishes after close.
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    if !app.get_webview_window("main").is_some_and(|window| window.is_visible().unwrap_or(false)
        && !window.is_minimized().unwrap_or(false)) { return; }
    simulation::shutdown(app);
    usage::shutdown(app);
    let mut environment = app.env();
    // A user can open a window in a running background updater.
    // Its replacement must start with a normal desktop window.
    if updater::Mode::from_args().headless() {
        environment.args_os.truncate(1);
    }
    #[cfg(target_os = "macos")]
    if let Some(instance) = app.try_state::<single_instance::Instance>() {
        instance.begin_restart();
    }
    tauri::process::restart(&environment);
}

#[tauri::command]
async fn menu_bar_settings(app: tauri::AppHandle, window: tauri::Window, enabled: Option<bool>) -> Result<Value, String> {
    if window.label() != "main" { return Err("Unknown application window.".into()); }
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    {
        let (send, receive) = tokio::sync::oneshot::channel();
        let handle = app.clone();
        app.run_on_main_thread(move || {
            let _ = send.send(menu_bar::settings(&handle, enabled));
        }).map_err(|e| e.to_string())?;
        receive.await.map_err(|_| "Could not read menu bar settings.".to_owned())?
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    { let _ = (app, enabled); Ok(json!({"supported":false,"enabled":false})) }
}

#[tauri::command]
async fn menu_bar_health(app: tauri::AppHandle, window: tauri::Window, label: String, attention: bool) -> Result<(), String> {
    if window.label() != "main" { return Err("Unknown application window.".into()); }
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    {
        let (send, receive) = tokio::sync::oneshot::channel();
        let handle = app.clone();
        app.run_on_main_thread(move || {
            let _ = send.send(menu_bar::health(&handle, label, attention));
        }).map_err(|e| e.to_string())?;
        receive.await.map_err(|_| "Could not update menu bar status.".to_owned())?
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    { let _ = (app, label, attention); Ok(()) }
}

#[tauri::command]
async fn sensor_request(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    request: Request,
    on_progress: Option<tauri::ipc::JavaScriptChannelId>,
    gate: tauri::State<'_, Mutex<()>>,
) -> Result<Value, String> {
    if window.label() != "main" {
        return Err("Unknown application window.".into());
    }
    if matches!(&request, Request::AlertsFocus {}) {
        #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
        {
            menu_bar::open_window(&app).map_err(|_| "Could not show OpenAIDR.")?;
            return Ok(Value::Null);
        }
        #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
        {
        window.unminimize().map_err(|_| "Could not show OpenAIDR.")?;
        window.show().map_err(|_| "Could not show OpenAIDR.")?;
        window.set_focus().map_err(|_| "Could not focus OpenAIDR.")?;
        return Ok(Value::Null);
        }
    }
    match &request {
        Request::Support {} => return tauri::async_runtime::spawn_blocking(links::contact_support)
            .await.map_err(|_| "Could not open your email app.".to_owned())?
            .map(|_| Value::Null),
        Request::Dashboard { server_url } => {
            let server_url = server_url.clone();
            return tauri::async_runtime::spawn_blocking(move || links::open_dashboard(&server_url, || {
                let state = app.state::<Mutex<()>>();
                let _guard = lock_sensor(&state, None)?;
                let _operation = updater::operation_lock(&app)?;
                let result = bridge(&bundled_binary(&app)?, json!({"action":"local-runtime.dashboard"}))?;
                if result["managed"] == false { return Ok(None); }
                let session = result["session"].as_str().ok_or("Invalid local dashboard session.")?;
                let nonce = result["nonce"].as_str().ok_or("Invalid local dashboard handoff.")?;
                Ok(Some((session.to_owned(), nonce.to_owned())))
            }))
                .await.map_err(|_| "Could not open your browser.".to_owned())?
                .map(|_| Value::Null);
        }
        Request::UpdateCheck {} => return updater::manual(&app, None).await,
        Request::UpdateInstall { version } => return updater::manual(&app, Some(version.clone())).await,
        Request::UpdateCancel {} => return updater::cancel(&app),
        _ => {}
    }
    if matches!(&request, Request::UpdateStatus {}) {
        return tauri::async_runtime::spawn_blocking(move || {
            let status = updater::read_status(&app)?.unwrap_or(Value::Null);
            if status["state"] != "updated" { return Ok(status); }
            // Finish a manual update even when the sensor cannot answer status.
            // Never interrupt an enrollment, removal, or sensor operation.
            let gate = app.state::<Mutex<()>>();
            if let Ok(sensor) = gate.try_lock() {
                if let Ok(operation) = updater::operation_lock(&app) {
                    if updater::restart_after_update(&app) {
                        drop(operation);
                        drop(sensor);
                        restart_updated_app(&app);
                    }
                }
            };
            Ok(status)
        })
            .await
            .map_err(|_| "Cannot read automatic-update status.".to_string())?;
    }
    let on_progress = on_progress.map(|id| id.channel_on(window.as_ref().clone()));
    let previews = app.state::<EnrollmentPreviews>();
    if matches!(&request, Request::EnrollmentPreviewInvalidate {}) {
        return Ok(json!({"generation":previews.invalidate()?}));
    }
    let generation = match &request {
        Request::EnrollmentPreview { generation, .. } => Some(*generation),
        _ => None,
    };
    check_preview(generation.map(|generation| PreviewCancellation { previews: &previews, generation }))?;
    drop(previews);
    let payload = request.payload()?;
    if payload["action"] == "desktop.capabilities" {
        return Ok(json!({"removal_supported":updater::removal_supported(), "native_uninstaller":cfg!(windows)}));
    }
    let action = payload["action"].as_str().unwrap_or_default().to_owned();
    let started = Instant::now();
    let log = app.clone();
    // Requests are serialized inside a blocking task to keep the webview responsive.
    let _ = gate;
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut progress = (payload["action"] == "desktop.trash").then(|| removal_progress::Progress::new(app.path().app_log_dir().ok(), on_progress));
        if let Some(action) = payload["action"].as_str().filter(|action| action.starts_with("simulation.")) {
            return simulation::request(&app, action);
        }
        let previews = app.state::<EnrollmentPreviews>();
        let preview = generation.map(|generation| PreviewCancellation { previews: &previews, generation });
        check_preview(preview)?;
        let state = app.state::<Mutex<()>>();
        let _guard = lock_sensor(&state, preview)?;
        if let Some(progress) = &mut progress { progress.stage("locks"); }
        let is_status = payload["action"] == "status";
        let show_configuration = payload["action"] == "guardrails.configuration";
        let removing = payload["action"] == "desktop.remove";
        #[cfg(windows)]
        if removing {
            usage::shutdown(&app);
            updater::launch_uninstaller(&app)?;
            app.exit(0);
            return Ok(json!({}));
        }
        let resuming = payload["action"] == "desktop.resume";
        let trashing = payload["action"] == "desktop.trash";
        let removal_guard = if removing || resuming || trashing { Some(updater::removal_lock(&app)?) } else { None };
        let _operation = match updater::operation_lock(&app) {
            Ok(guard) => guard,
            Err(error) => {
                if is_status {
                    let snapshot = app.state::<SensorSnapshot>();
                    if let (Ok(cache), Some(mut update)) = (snapshot.0.lock(), updater::status(&app)) {
                        if let Some(mut response) = cache.clone().filter(|_| {
                            matches!(update["state"].as_str(), Some("installing" | "restarting"))
                        }) {
                            update["status_cached"] = json!(true);
                            response["desktop_update"] = update;
                            return Ok(response);
                        }
                    };
                }
                return Err(error);
            }
        };
        check_preview(preview)?;
        if let Some(progress) = &mut progress { progress.stage("usage_shutdown"); }
        if matches!(payload["action"].as_str(), Some("setup" | "desktop.update.setup" | "enrollment.connect" | "free.connect" | "api-key.connect" | "local-runtime.connect" | "desktop.resume" | "desktop.trash")) {
            usage::shutdown(&app);
        }
        if trashing {
            if payload["delete_data"] == true {
                #[cfg(not(target_os = "macos"))]
                return Err("Local data deletion is available only on macOS.".into());
                #[cfg(target_os = "macos")]
                {
                    if let Some(progress) = &mut progress { progress.stage("preparation"); }
                    updater::validate_trash_app(&app)?;
                    updater::prepare_removal(&app)?;
                    if let Some(progress) = &mut progress { progress.stage("helper_startup"); }
                    let deleted = bridge_reporting(&bundled_binary(&app)?, json!({"action":"desktop.purge"}), preview, progress.as_mut())?;
                    if deleted["desktop_removal"]["data_deleted"] != true {
                        return Err("Local data deletion did not finish. Retry deletion before moving the app to Trash.".into());
                    }
                }
            }
            if let Some(progress) = &mut progress { progress.stage("trash"); }
            updater::trash_app(&app)?;
            if let Some(progress) = &mut progress { progress.finish(true); }
            app.exit(0);
            return Ok(json!({}));
        }
        if let Some(removal) = updater::removal_status(&app) {
            if is_status {
                return Ok(json!({"desktop_removal":removal}));
            }
            if !removing && !resuming {
                return Err("Removal was requested. Choose Install to resume collection.".into());
            }
        }
        if removing {
            usage::shutdown(&app);
            updater::prepare_removal(&app)?;
        }
        if payload["action"] == "usage.summary" {
            return usage::request(&app, &payload);
        }
        if !is_status && payload["action"] != "usage.summary" {
            if let Ok(mut snapshot) = app.state::<SensorSnapshot>().0.lock() {
                *snapshot = None;
            }
        }
        // Removal must not stage another executable or depend on a retained
        // sensor version supporting this app's removal protocol.
        let executable = if removing || resuming { bundled_binary(&app)? } else { stable_binary(&app)? };
        let mut response = bridge_pending(&executable, payload, preview)?;
        if show_configuration {
            links::show_configuration(response["path"].as_str().ok_or("Missing configuration path.")?)?;
            return Ok(json!({}));
        }
        if resuming {
            updater::resume_removal(&app)?;
            drop(_operation);
            drop(removal_guard);
            updater::initialize(&app, updater::Mode::Window);
            return Ok(response);
        }
        if is_status {
            if let Ok(mut snapshot) = app.state::<SensorSnapshot>().0.lock() {
                *snapshot = Some(response.clone());
            }
            if let Some(status) = updater::status(&app) {
                response["desktop_update"] = status;
            }
            if updater::restart_after_update(&app) {
                drop(_operation);
                drop(_guard);
                restart_updated_app(&app);
            }
        }
        Ok(response)
    })
    .await
    .map_err(|_| "Sensor request task failed.".to_string())
    .and_then(|result| result);
    // Routine status reads are recorded only when they fail.
    if action != "status" || result.is_err() {
        record_request(&log, &action, started, &result);
    }
    result
}

/// A bounded local record of window requests for troubleshooting, as ADR keeps
/// desktop-helper.log. Request parameters, such as enrollment links, and
/// responses are never written; the sensor never returns credentials in errors.
fn record_request(app: &tauri::AppHandle, action: &str, started: Instant, result: &Result<Value, String>) {
    let Ok(directory) = app.path().app_log_dir() else { return; };
    record_event(&directory, action, json!({
        "ms": started.elapsed().as_millis() as u64,
        "ok": result.is_ok(),
        "error": result.as_ref().err(),
    }));
}

fn record_event(directory: &Path, action: &str, mut line: Value) {
    let path = directory.join("desktop.log");
    if fs::create_dir_all(&directory).is_err() || reject_symlink(&path).is_err() {
        return;
    }
    if fs::metadata(&path).map(|meta| meta.len() > 1 << 20).unwrap_or(false) {
        let _ = fs::rename(&path, directory.join("desktop.log.1"));
    }
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    line["at"] = json!(at);
    line["version"] = json!(env!("OPENAIDR_VERSION"));
    line["action"] = json!(action);
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{line}");
    }
}

fn main() {
    #[cfg(any(windows, target_os = "linux"))]
    if let Some(code) = updater::early_command() {
        std::process::exit(code);
    }
    let mode = updater::Mode::from_args();
    #[cfg(target_os = "macos")]
    if !platform::macos::install_location::check_launch(!mode.headless()) {
        return;
    }
    let mut context = tauri::generate_context!();
    #[cfg(target_os = "macos")]
    let instance = if mode.headless() {
        // Update workers must complete their service handoff while a window is
        // open. Their existing updater and operation locks serialize that work.
        None
    } else {
        let directory = single_instance::directory(&context.config().identifier)
            .expect("Cannot locate the OpenAIDR desktop instance directory");
        match single_instance::Instance::acquire(&directory)
            .expect("Cannot establish the OpenAIDR desktop instance")
        {
            Some(instance) => Some(instance),
            None => return,
        }
    };
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    let main_window = context
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .cloned();
    #[cfg(target_os = "macos")]
    let activation_window = main_window.clone();
    if mode.headless() {
        context.config_mut().app.windows.clear();
    }
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(Mutex::new(()))
        .manage(SensorSnapshot::default())
        .manage(EnrollmentPreviews::default())
        .manage(updater::ManualUpdate::default())
        .manage(simulation::Simulation::default())
        .manage(usage::Usage::default())
        .invoke_handler(tauri::generate_handler![sensor_request, window_fit::fit_window, menu_bar_settings, menu_bar_health]);
    #[cfg(all(target_os = "macos", feature = "e2e-ui"))]
    let builder = {
        assert!(std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"),
            "The E2E UI build may run only on a disposable GitHub-hosted runner");
        // This optional dependency binds only to loopback and is absent from release builds.
        builder.plugin(tauri_plugin_wdio_webdriver::init_with_port(4445))
    };
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    let builder = builder.on_window_event(menu_bar::on_window_event);
    #[cfg(target_os = "macos")]
    let builder = builder.activate_ignoring_other_apps(!mode.headless());
    #[cfg(target_os = "macos")]
    let builder = builder.menu(about::menu).on_menu_event(|app, event| {
        if event.id().as_ref() == "openaidr-about" {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.eval("document.getElementById('show-about')?.click()");
            }
        }
    });
    #[cfg(target_os = "linux")]
    let builder = builder.plugin(updater::window_plugin());
    // One desktop window per user: a second launch focuses the first one
    // before it touches the sensor, then exits.
    #[cfg(windows)]
    let builder = if mode.headless() { builder } else {
        builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = menu_bar::open_window(app);
        })).plugin(updater::window_plugin())
    };
    #[cfg(any(target_os = "macos", windows))]
    let builder = if updater::enabled(context.config()) {
        builder.plugin(tauri_plugin_updater::Builder::new().build())
    } else {
        builder
    };
    let app = builder
        .setup(move |app| {
            #[cfg(any(windows, target_os = "linux"))]
            if !mode.headless() {
                if let Some(config) = &main_window {
                    menu_bar::initialize(app.handle(), config)?;
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(instance) = instance {
                if let Some(config) = &activation_window {
                    menu_bar::initialize(app.handle(), config)?;
                }
                listen_for_activation(app.handle(), instance, activation_window)?;
            }
            updater::initialize(app.handle(), mode);
            Ok(())
        })
        .build(context)
        .expect("Cannot start OpenAIDR");
    let on_event = move |app: &tauri::AppHandle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            simulation::shutdown(app);
            usage::shutdown(app);
        }
        #[cfg(target_os = "macos")]
        if matches!(event, tauri::RunEvent::Reopen { .. }) {
            if let Some(config) = &main_window {
                let _ = reopen_single_window(app, config);
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (app, event);
    };
    #[cfg(target_os = "macos")]
    platform::macos::window::run(app, mode.headless(), on_event);
    #[cfg(not(target_os = "macos"))]
    app.run(on_event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use window_fit::{place_in_work_area, window_height, WINDOW_HEIGHT_RANGE};

    #[cfg(target_os = "macos")]
    mod menu_bar_permissions {
        // Exercise the packaged ACL without starting the sensor or changing preferences.
        #[tauri::command]
        fn menu_bar_settings() -> bool { true }
        #[tauri::command]
        fn menu_bar_health() -> bool { true }

        #[test]
        fn only_the_local_main_window_can_invoke_menu_bar_commands() {
            let mut context = tauri::generate_context!(test = true);
            context.config_mut().app.windows.clear();
            let app = tauri::test::mock_builder()
                .invoke_handler(tauri::generate_handler![self::menu_bar_settings, self::menu_bar_health])
                .build(context).unwrap();
            for label in ["main", "untrusted"] {
                let window = tauri::WebviewWindowBuilder::new(&app, label, Default::default()).build().unwrap();
                for command in ["menu_bar_settings", "menu_bar_health"] {
                    for url in ["tauri://localhost", "https://example.invalid"] {
                        let result = tauri::test::get_ipc_response(&window, tauri::webview::InvokeRequest {
                            cmd: command.into(), callback: tauri::ipc::CallbackFn(0), error: tauri::ipc::CallbackFn(1),
                            url: url.parse().unwrap(), body: tauri::ipc::InvokeBody::default(),
                            headers: Default::default(), invoke_key: tauri::test::INVOKE_KEY.into(),
                        });
                        assert_eq!(result.is_ok(), label == "main" && url == "tauri://localhost",
                            "{command} from {label} at {url}: {:?}", result.err());
                    }
                }
            }
        }
    }

    #[test]
    fn local_runtime_actions_cannot_choose_commands_paths_or_servers() {
        for action in ["check", "docker-setup", "prepare", "start", "connect", "credentials"] {
            let mut input = json!({"action":format!("local-runtime.{action}")});
            if action == "connect" { input["password"] = json!("local-password"); }
            assert!(serde_json::from_value::<Request>(input.clone()).unwrap().payload().is_ok());
            for key in ["command", "path", "server_url", "project"] {
                let mut invalid = input.clone(); invalid[key] = json!("untrusted");
                assert!(serde_json::from_value::<Request>(invalid).is_err());
            }
        }
        assert!(Request::LocalRuntimeConnect { password:"a".repeat(1025) }.payload().is_err());
    }

    #[test]
    fn alert_receipts_allow_only_bounded_ids_and_enrollment_scopes() {
        let id = "01000000-0000-7000-8000-000000000042";
        let scope = "a".repeat(64);
        let input = json!({"action":"alerts.acknowledge","id":id,"scope":scope});
        let request: Request = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(request.payload().unwrap(), json!({"action":"alerts.acknowledge","params":{"id":id,"scope":scope}}));
        for replacement in ["../commands", "", "01000000-0000-7000-8000-00000000004;"] {
            let mut invalid = input.clone(); invalid["id"] = json!(replacement);
            assert!(serde_json::from_value::<Request>(invalid).unwrap().payload().is_err());
        }
        let mut invalid = input.clone(); invalid["command"] = json!("execute this");
        assert!(serde_json::from_value::<Request>(invalid).is_err());
        assert!(Request::AlertsReceived {ids:vec![id.into(); 101],scope:scope.clone()}.payload().is_err());
        assert!(Request::AlertsAcknowledge {id:id.into(),scope:"foreign".into()}.payload().is_err());
        assert_eq!(Request::AlertsList {}.payload().unwrap(), json!({"action":"alerts.list"}));
    }

    #[test]
    fn support_accepts_only_the_fixed_desktop_action() {
        let request = serde_json::from_value::<Request>(json!({"action":"desktop.support"})).unwrap();
        assert!(matches!(request, Request::Support {}));
        assert!(request.payload().is_err());
        for key in ["url", "email", "command", "body"] {
            let mut input = json!({"action":"desktop.support"});
            input[key] = json!("untrusted");
            assert!(serde_json::from_value::<Request>(input).is_err());
        }
    }
    #[test]
    fn dashboard_links_stay_in_the_desktop_and_accept_only_a_server_address() {
        let input = json!({"action":"desktop.dashboard","server_url":"https://tenant.example"});
        let request = serde_json::from_value::<Request>(input.clone()).unwrap();
        assert!(matches!(request, Request::Dashboard { .. }));
        assert!(request.payload().is_err());
        assert!(serde_json::from_value::<Request>(json!({"action":"desktop.dashboard"})).is_err());
        for key in ["url", "command", "args"] {
            let mut invalid = input.clone();
            invalid[key] = json!("untrusted");
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
    }
    #[test]
    fn simulation_actions_require_an_explicit_development_build() {
        for action in ["simulation.start", "simulation.stop"] {
            let request = serde_json::from_value::<Request>(json!({"action":action})).unwrap();
            assert_eq!(request.payload().is_ok(), cfg!(all(feature = "simulation", unix)));
            assert!(serde_json::from_value::<Request>(json!({"action":action,"server_url":"https://example.com"})).is_err());
        }
        assert!(Request::SimulationStatus {}.payload().is_ok());
    }
    #[test]
    fn usage_reads_accept_only_a_bounded_period() {
        for days in [1, 7, 14, 30] {
            assert_eq!(Request::UsageSummary { days }.payload().unwrap(),
                json!({"action":"usage.summary","params":{"days":days}}));
        }
        for days in [0, 13, 15, 31, 255] {
            assert!(Request::UsageSummary { days }.payload().is_err());
        }
        assert!(serde_json::from_value::<Request>(json!({"action":"usage.summary","days":14,"sensor_id":"other"})).is_err());
    }

    #[test]
    fn posture_reads_cannot_select_another_device_or_path() {
        let input = json!({"action":"posture.summary"});
        assert_eq!(serde_json::from_value::<Request>(input.clone()).unwrap().payload().unwrap(), input);
        for field in ["sensor_id", "server_url", "scope", "path", "command", "params"] {
            let mut invalid = input.clone();
            invalid[field] = json!("untrusted");
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
    }

    #[test]
    fn posture_consent_accepts_only_a_boolean_and_connection_scope() {
        let scope = "a".repeat(64);
        for automatic in [true, false] {
            let input = json!({"action":"posture.configure","automatic":automatic,"scope":scope});
            assert_eq!(serde_json::from_value::<Request>(input.clone()).unwrap().payload().unwrap(),
                json!({"action":"posture.configure","params":{"automatic":automatic,"scope":scope}}));
            for field in ["sensor_id", "server_url", "path", "command", "params"] {
                let mut invalid = input.clone();
                invalid[field] = json!("untrusted");
                assert!(serde_json::from_value::<Request>(invalid).is_err());
            }
        }
        for invalid in [json!({"action":"posture.configure","scope":scope}),
                        json!({"action":"posture.configure","automatic":"true","scope":scope}),
                        json!({"action":"posture.configure","automatic":true})] {
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
        for scope in ["".to_string(), "x".repeat(64), "a".repeat(65)] {
            assert!(Request::PostureConfigure { automatic: true, scope }.payload().is_err());
        }
    }

    #[test]
    fn guardrail_actions_accept_only_fixed_agents_and_periods() {
        for agent in ["codex", "claude", "copilot", "cursor", "antigravity", "opencode", "hermes", "workbuddy"] {
            for enabled in [true, false] {
                let input = json!({"action":"guardrails.configure","agent":agent,"enabled":enabled});
                assert_eq!(serde_json::from_value::<Request>(input).unwrap().payload().unwrap(),
                    json!({"action":"guardrails.configure","params":{"agent":agent,"enabled":enabled}}));
            }
        }
        assert_eq!(Request::CreditsSummary {}.payload().unwrap(), json!({"action":"credits.summary"}));
        assert!(serde_json::from_value::<Request>(json!({"action":"credits.summary","tenant_id":"other"})).is_err());
        assert_eq!(Request::FreeUsage {}.payload().unwrap(), json!({"action":"free.usage"}));
        for action in ["guardrails.configure", "guardrails.configuration"] {
            let mut input = json!({"action":action,"agent":"codex","profile":"/Users/example/.codex-account2/hooks.json"});
            if action == "guardrails.configure" { input["enabled"] = json!(true); }
            let payload = serde_json::from_value::<Request>(input).unwrap().payload().unwrap();
            assert_eq!(payload["params"]["profile"], "/Users/example/.codex-account2/hooks.json");
            assert_eq!(payload["params"]["agent"], "codex");
        }
        assert!(serde_json::from_value::<Request>(json!({"action":"free.usage","tenant_id":"other"})).is_err());
        for days in [1, 30] { assert!(Request::GuardrailsSummary { days }.payload().is_ok()); }
        for days in [0, 7, 31] { assert!(Request::GuardrailsSummary { days }.payload().is_err()); }
        for input in [
            json!({"action":"guardrails.configure","agent":"all","enabled":true}),
            json!({"action":"guardrails.configure","agent":"claude","enabled":"true"}),
            json!({"action":"guardrails.configure","agent":"claude","enabled":true,"command":"run"}),
            json!({"action":"guardrails.configuration","agent":"claude","path":"/tmp/code.js"}),
            json!({"action":"guardrails.summary","days":1,"sensor_id":"other"}),
        ] { assert!(serde_json::from_value::<Request>(input).is_err()); }
    }

    #[test]
    fn guardrail_reviews_accept_only_bounded_feedback() {
        let input = json!({"action":"guardrails.review","id":"00000000-0000-4000-8000-000000000001",
            "scope":"a".repeat(64),"label":"false_positive","note":"Expected cleanup"});
        let payload = serde_json::from_value::<Request>(input.clone()).unwrap().payload().unwrap();
        assert_eq!(payload["params"]["label"], "false_positive");
        assert!(payload["params"].get("review_version").is_none());
        let mut versioned = input.clone();
        versioned["review_version"] = json!(1);
        versioned["label"] = json!("insufficient_context");
        versioned["evidence_sha256"] = json!("b".repeat(64));
        versioned["expected_revision"] = json!(2);
        versioned["request_id"] = json!("00000000-0000-4000-8000-000000000002");
        let bound = serde_json::from_value::<Request>(versioned.clone()).unwrap().payload().unwrap();
        assert_eq!(bound["params"]["expected_revision"], 2);
        assert_eq!(bound["params"]["evidence_sha256"], "b".repeat(64));
        for (key, value) in [("review_version", json!(2)), ("evidence_sha256", json!("bad")),
                            ("request_id", json!("bad")), ("expected_revision", Value::Null)] {
            let mut bad = versioned.clone(); bad[key] = value;
            assert!(serde_json::from_value::<Request>(bad).unwrap().payload().is_err());
        }
        versioned.as_object_mut().unwrap().remove("review_version");
        assert!(serde_json::from_value::<Request>(versioned).unwrap().payload().is_err());
        for mut read in [json!({"action":"guardrails.denials","days":1,"until":"2026-10-30T00:00:00Z","cursor":""}),
                         json!({"action":"guardrails.check","id":input["id"],"scope":input["scope"]})] {
            assert!(serde_json::from_value::<Request>(read.clone()).unwrap().payload().unwrap()["params"].get("review_version").is_none());
            read["review_version"] = json!(1);
            assert_eq!(serde_json::from_value::<Request>(read.clone()).unwrap().payload().unwrap()["params"]["review_version"], 1);
            read["decision"] = json!("ask");
            assert_eq!(serde_json::from_value::<Request>(read.clone()).unwrap().payload().unwrap()["params"]["decision"], "ask");
            let mut invalid = read.clone(); invalid["decision"] = json!("allow");
            assert!(serde_json::from_value::<Request>(invalid).is_err());
            read["review_version"] = json!(2);
            assert!(serde_json::from_value::<Request>(read).unwrap().payload().is_err());
        }
        for (key, value) in [("id", "../check".to_owned()), ("scope", "wrong".to_owned()),
            ("label", "allow".to_owned()), ("note", "x".repeat(2001))] {
            let mut bad = input.clone(); bad[key] = json!(value);
            assert!(serde_json::from_value::<Request>(bad).unwrap().payload().is_err());
        }
        let mut bad = input; bad["sensor_id"] = json!("other");
        assert!(serde_json::from_value::<Request>(bad).is_err());
    }

    #[test]
    fn window_height_is_bounded() {
        assert_eq!(window_height(300.2), Some(301.0));
        assert_eq!(window_height(10.0), Some(WINDOW_HEIGHT_RANGE.0));
        assert_eq!(window_height(1e9), Some(WINDOW_HEIGHT_RANGE.1));
        assert_eq!(window_height(f64::NAN), None);
        assert_eq!(window_height(f64::INFINITY), None);
    }

    #[test]
    fn a_growing_window_stays_inside_the_work_area() {
        // Room below: the window grows in place.
        assert_eq!(
            place_in_work_area(100.0, 56.0, 760.0, 50.0, 1900.0),
            (760.0, 100.0)
        );
        // Near the bottom edge: the window moves up just enough.
        assert_eq!(
            place_in_work_area(1500.0, 56.0, 760.0, 50.0, 1900.0),
            (760.0, 1084.0)
        );
        // Taller than the area: the height is capped and the window sits at the top.
        assert_eq!(
            place_in_work_area(400.0, 56.0, 2000.0, 50.0, 1100.0),
            (994.0, 50.0)
        );
    }

    #[test]
    fn rejects_arbitrary_actions_and_paths() {
        for value in [
            json!({"action":"exec","command":"anything"}),
            json!({"action":"enroll","server_url":"https://tenant.example","token":"oaet_secret","label":"Laptop","host_kind":"workstation"}),
            json!({"action":"status","config_path":"/tmp/config"}),
            json!({"action":"telemetry.install","agents":["codex"]}),
            json!({"action":"telemetry.remove","agents":["claude"]}),
            json!({"action":"service.install"}),
            json!({"action":"service.restart"}),
            json!({"action":"setup","agents":["codex"]}),
            json!({"action":"update.check","url":"https://example.com"}),
            json!({"action":"update.check"}),
            json!({"action":"desktop.update.setup"}),
        ] {
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
    }
    #[test]
    fn version_key_orders_releases_and_keeps_a_newer_staged_sensor() {
        let ordered = [
            "0.1.0.dev1", "0.1.0a1", "0.1.0a2", "0.1.0b1", "0.1.0rc1", "0.1.0", "0.1.0.post1",
            "0.1.1", "1.0",
        ];
        let keys: Vec<_> = ordered.iter().map(|v| version_key(v).unwrap()).collect();
        for pair in keys.windows(2) {
            assert!(pair[0] < pair[1], "{:?} < {:?}", pair[0], pair[1]);
        }
        assert_eq!(version_key("0.1"), version_key("0.1.0"));
        assert_eq!(version_key("v1.2.3"), version_key("1.2.3"));
        assert!(version_key("dev").is_none());
        assert!(version_key("").is_none());
        assert!(version_key("0.3.0").unwrap() > version_key("0.2.0").unwrap());
        assert!(version_key("0.2.0").unwrap() < version_key("0.2.0.post1").unwrap());
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn staging_keeps_complete_runtimes_for_both_real_aliases() {
        let scratch = tempfile::tempdir().unwrap();
        let source = sensor_runtime::tests::fixture(&scratch.path().join("old"), 'a', 1791334800);
        let script = fs::read_to_string(&source).unwrap();
        fs::write(&source, script.replacen("#!/bin/sh\n", "#!/bin/sh\nprintf x > \"$0.executed\"\n", 1)).unwrap();
        let newer = sensor_runtime::tests::fixture(&scratch.path().join("new"), 'b', 1791334801);
        let directory = scratch.path().join("bin");
        fs::create_dir(&directory).unwrap();
        let canonical = directory.join("openaidr");
        let legacy = directory.join("openaidr-sensor");
        let source_manifest = source.parent().unwrap()
            .join(format!("openaidr-runtime-{}", "a".repeat(64))).join("runtime.json");
        let manifest = fs::read(&source_manifest).unwrap();
        fs::remove_file(&source_manifest).unwrap();
        assert!(require_sensor_version(&source, "2026.10.8+aaaaaaa").is_err());
        assert!(!source.with_extension("executed").exists());
        assert!(stage_binary(&source, &directory).is_err());
        assert!(!canonical.exists() && !legacy.exists());
        fs::write(&source_manifest, manifest).unwrap();
        stage_binary(&source, &directory).unwrap();
        // Digest reuse must not accept a symbolic link to matching bytes.
        for alias in [&canonical, &legacy] {
            fs::remove_file(alias).unwrap();
            std::os::unix::fs::symlink(&source, alias).unwrap();
            assert!(stage_binary(&source, &directory).is_err());
            assert!(alias.is_symlink());
            fs::remove_file(alias).unwrap();
            fs::copy(&source, alias).unwrap();
        }
        let linked_directory = scratch.path().join("linked-bin");
        std::os::unix::fs::symlink(&directory, &linked_directory).unwrap();
        assert!(stage_binary(&source, &linked_directory).is_err());
        stage_binary(&newer, &directory).unwrap();
        let expected = fs::read(&newer).unwrap();
        let newer_runtime = directory.join(format!("openaidr-runtime-{}", "b".repeat(64)));
        assert!(directory.join(format!("openaidr-runtime-{}", "a".repeat(64))).is_dir());
        // Matching executables must repair a wholly absent support directory.
        fs::remove_dir_all(&newer_runtime).unwrap();
        stage_binary(&newer, &directory).unwrap();
        assert_eq!(fs::read_to_string(newer_runtime.join("Python")).unwrap(), "runtime b");
        for alias in [&canonical, &legacy] { assert_eq!(fs::read(alias).unwrap(), expected); }
        // Explicitly opening an older app stages its exact sensor too.
        stage_binary(&source, &directory).unwrap();
        let expected = fs::read(&source).unwrap();
        for alias in [&canonical, &legacy] {
            assert_eq!(fs::read(alias).unwrap(), expected);
            assert!(!alias.is_symlink());
        }
        // A partial runtime must not publish either alias or run metadata.
        fs::remove_file(newer_runtime.join("Python.framework/Versions/3.14/Python")).unwrap();
        assert!(stage_binary(&newer, &directory).is_err());
        for alias in [&canonical, &legacy] { assert_eq!(fs::read(alias).unwrap(), expected); }
        fs::remove_dir_all(&newer_runtime).unwrap();
        std::os::unix::fs::symlink(scratch.path().join("new"), &newer_runtime).unwrap();
        assert!(stage_binary(&newer, &directory).is_err());
        for alias in [&canonical, &legacy] { assert_eq!(fs::read(alias).unwrap(), expected); }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn staging_uses_the_opened_app_for_both_sensor_names() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let scratch = tempfile::tempdir().unwrap();
        let incoming = scratch.path().join("bundle");
        let directory = scratch.path().join("bin");
        fs::create_dir(&directory).unwrap();
        let canonical = directory.join("openaidr");
        let legacy = directory.join("openaidr-sensor");
        let version = "2026.10.20+c3eb326";
        let build = json!({"version":version,"source_commit":"c3eb3265a1c7a3b4913754ff7d2d7300b755de0e",
            "source_timestamp":1792555171_u64});
        fs::write(&incoming, format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", build)).unwrap();
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
        require_sensor_version(&incoming, version).unwrap();
        assert!(require_sensor_version(&incoming, "2026.10.20+aaaaaaa").is_err());
        let expected = fs::read(&incoming).unwrap();
        // Published, newer, conflicting, and unreadable old versions all yield
        // to the bundled source; no existing sensor is executed to choose it.
        for bytes in [b"published sensor".as_slice(), b"newer sensor", b"invalid sensor"] {
            fs::write(&canonical, bytes).unwrap();
            fs::write(&legacy, b"different legacy sensor").unwrap();
            assert_eq!(stage_binary(&incoming, &directory).unwrap(), canonical);
            for alias in [&canonical, &legacy] {
                assert_eq!(fs::read(alias).unwrap(), expected);
                assert!(!alias.is_symlink());
            }
        }
        fs::remove_file(&legacy).unwrap();
        stage_binary(&incoming, &directory).unwrap();
        assert_eq!(fs::read(&legacy).unwrap(), expected);
        fs::remove_file(&legacy).unwrap();
        symlink(&incoming, &legacy).unwrap();
        assert!(require_sensor_version(&legacy, version).is_err());
        assert!(stage_binary(&incoming, &directory).is_err());
        assert_eq!(fs::read(&canonical).unwrap(), expected);
    }

    #[test]
    fn api_key_connect_accepts_only_a_bounded_key_parameter() {
        let payload = serde_json::from_value::<Request>(json!({"action":"api-key.connect","api_key":" synthetic-key "}))
            .unwrap().payload().unwrap();
        assert_eq!(payload, json!({"action":"api-key.connect","params":{"api_key":"synthetic-key"}}));
        for key in [" ".to_string(), "x".repeat(257)] {
            assert_eq!(Request::ApiKeyConnect { api_key: key }.payload().unwrap_err(), "Enter a valid OpenSecura API key.");
        }
        for extra in ["server_url", "tenant_id"] {
            let mut request = json!({"action":"api-key.connect","api_key":"synthetic-key"});
            request[extra] = json!("untrusted");
            assert!(serde_json::from_value::<Request>(request).is_err());
        }
    }

    #[test]
    fn proxy_requests_forward_bounded_settings_only() {
        let request = |value: Value| serde_json::from_value::<Request>(value).map(Request::payload);
        assert_eq!(request(json!({"action":"proxy.status"})).unwrap().unwrap(), json!({"action":"proxy.status"}));
        assert_eq!(request(json!({"action":"proxy.save","mode":"direct","url":"http://ignored:1"})).unwrap().unwrap(),
            json!({"action":"proxy.save","params":{"mode":"direct"}}));
        let manual = json!({"action":"proxy.test","mode":"manual","url":" http://proxy.example:3128 ",
            "bypass":["internal.example"],"username":"svc","password":"pw"});
        assert_eq!(request(manual.clone()).unwrap().unwrap(), json!({"action":"proxy.test","params":{
            "mode":"manual","url":"http://proxy.example:3128","bypass":["internal.example"],"username":"svc","password":"pw"}}));
        for (field, value) in [("mode", json!("system")), ("url", json!("")), ("url", json!("x".repeat(2049))),
            ("bypass", json!(vec!["h"; 65])), ("username", json!("u".repeat(257))), ("password", json!(""))] {
            let mut invalid = manual.clone();
            invalid[field] = value;
            assert_eq!(request(invalid).unwrap().unwrap_err(), "Enter valid proxy settings.");
        }
        let mut extra = manual;
        extra["server_url"] = json!("https://untrusted.example");
        assert!(request(extra).is_err());
    }

    #[test]
    fn setup_carries_no_parameters() {
        let payload = serde_json::from_value::<Request>(json!({"action":"setup"}))
            .unwrap()
            .payload()
            .unwrap();
        assert_eq!(payload, json!({"action":"desktop.update.setup"}));
        for action in ["desktop.remove", "desktop.resume", "desktop.capabilities", "free.connect"] {
            assert_eq!(serde_json::from_value::<Request>(json!({"action":action})).unwrap().payload().unwrap(), json!({"action":action}));
            assert!(serde_json::from_value::<Request>(json!({"action":action,"path":"/anything"})).is_err());
            assert!(serde_json::from_value::<Request>(json!({"action":action,"delete_data":true})).is_err());
        }
        for delete_data in [false, true] {
            let request = json!({"action":"desktop.trash","delete_data":delete_data});
            assert_eq!(serde_json::from_value::<Request>(request.clone()).unwrap().payload().unwrap(), request);
        }
        assert_eq!(serde_json::from_value::<Request>(json!({"action":"desktop.trash"})).unwrap().payload().unwrap(), json!({"action":"desktop.trash","delete_data":false}));
        for request in [json!({"action":"desktop.trash","path":"/anything"}), json!({"action":"desktop.trash","delete_data":"true"}), json!({"action":"desktop.purge"})] {
            assert!(serde_json::from_value::<Request>(request).is_err());
        }
        let update = serde_json::from_value::<Request>(json!({"action":"desktop.update.status"})).unwrap();
        assert!(update.payload().is_err());
        for field in ["path", "endpoint", "pubkey", "install"] {
            assert!(serde_json::from_value::<Request>(json!({"action":"desktop.update.status",field:true})).is_err());
        }
        for action in ["desktop.update.check", "desktop.update.cancel", "desktop.update.install"] {
            let mut payload = json!({"action":action});
            if action == "desktop.update.install" { payload["version"] = json!("2026.10.17+1234567"); }
            assert!(serde_json::from_value::<Request>(payload.clone()).unwrap().payload().is_err());
            for field in ["url", "path", "command", "endpoint", "pubkey", "install"] {
                let mut invalid = payload.clone();
                invalid[field] = json!("https://example.invalid");
                assert!(serde_json::from_value::<Request>(invalid).is_err());
            }
        }
        assert!(serde_json::from_value::<Request>(json!({"action":"desktop.update.install"})).is_err());
        assert!(serde_json::from_value::<Request>(json!({"action":"desktop.update.downloads"})).is_err());
    }
    #[test]
    fn enrollment_links_are_bounded_and_cannot_select_local_configuration() {
        let link = "https://tenant.example/enroll#token=oaet_secret";
        let tenant = "01000000-0000-7000-8000-000000000001";
        for value in [
            json!({"action":"enrollment.preview","link":link,"generation":1}),
            json!({"action":"enrollment.connect","link":link,"tenant_id":tenant}),
        ] {
            let payload = serde_json::from_value::<Request>(value.clone())
                .unwrap()
                .payload()
                .unwrap();
            assert_eq!(payload["params"]["link"], link);
            let mut forbidden = value;
            forbidden["config_path"] = json!("/tmp/other-device.yaml");
            assert!(serde_json::from_value::<Request>(forbidden).is_err());
        }
        for link in ["".to_string(), "a".repeat(8193)] {
            assert!(Request::EnrollmentPreview { link, ca_certificate: None, generation: 1 }.payload().is_err());
        }
        assert!(Request::EnrollmentConnect {
            link: link.into(),
            tenant_id: "".into(),
            ca_certificate: None,
        }
        .payload()
        .is_err());
    }

    #[test]
    fn enrollment_certificate_text_is_optional_bounded_and_cannot_select_a_file() {
        for action in ["enrollment.preview", "enrollment.connect"] {
            let mut value = json!({"action":action,"link":"https://tenant.example/enroll#token=oaet_secret"});
            if action == "enrollment.connect" {
                value["tenant_id"] = json!("01000000-0000-7000-8000-000000000001");
            } else {
                value["generation"] = json!(1);
            }
            let plain = serde_json::from_value::<Request>(value.clone()).unwrap().payload().unwrap();
            assert!(plain["params"].get("ca_certificate").is_none());
            value["ca_certificate"] = json!("public certificate text");
            let certificate = serde_json::from_value::<Request>(value.clone()).unwrap().payload().unwrap();
            assert_eq!(certificate["params"]["ca_certificate"], "public certificate text");
            for invalid in ["".into(), "x".repeat(32769), "é".into()] {
                value["ca_certificate"] = json!(invalid);
                assert!(serde_json::from_value::<Request>(value.clone()).unwrap().payload().is_err());
            }
            value["ca_certificate"] = json!(123);
            assert!(serde_json::from_value::<Request>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove("ca_certificate");
            value["ca_cert"] = json!("/tmp/arbitrary.pem");
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
    }

    #[test]
    fn preview_generations_stay_in_the_desktop_protocol() {
        let value = json!({"action":"enrollment.preview","link":"https://tenant.example/enroll#token=secret","generation":7});
        let payload = serde_json::from_value::<Request>(value.clone()).unwrap().payload().unwrap();
        assert!(payload.get("generation").is_none());
        assert!(payload["params"].get("generation").is_none());
        for generation in [Value::Null, json!(-1), json!("7")] {
            let mut invalid = value.clone();
            invalid["generation"] = generation;
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("generation");
        assert!(serde_json::from_value::<Request>(missing).is_err());
        assert!(serde_json::from_value::<Request>(json!({"action":"enrollment.preview.invalidate"})).is_ok());
        for action in ["enrollment.preview.invalidate", "setup", "desktop.remove"] {
            assert!(serde_json::from_value::<Request>(json!({"action":action,"generation":7})).is_err());
        }
    }

    #[test]
    fn cancelled_queued_preview_releases_the_request_gate_before_work() {
        use std::sync::{mpsc, Arc};
        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().unwrap();
        let previews = Arc::new(EnrollmentPreviews::default());
        let generation = previews.invalidate().unwrap();
        let (started, waiting) = mpsc::channel();
        let (finished, result) = mpsc::channel();
        let worker_gate = gate.clone();
        let worker_previews = previews.clone();
        let worker = thread::spawn(move || {
            let preview = Some(PreviewCancellation { previews: &worker_previews, generation });
            check_preview(preview).unwrap();
            started.send(()).unwrap();
            let outcome = lock_sensor(&worker_gate, preview).map(|_guard| panic!("Stale preview reached staging"));
            finished.send(outcome).unwrap();
        });
        waiting.recv_timeout(Duration::from_secs(3)).unwrap();
        let current = previews.invalidate().unwrap();
        drop(held);
        assert_eq!(result.recv_timeout(Duration::from_secs(3)).unwrap().unwrap_err(), "The enrollment preview was cancelled.");
        worker.join().unwrap();
        // Both a new preview and a mutation can acquire the same gate.
        drop(lock_sensor(&gate, Some(PreviewCancellation { previews: &previews, generation: current })).unwrap());
        drop(lock_sensor(&gate, None).unwrap());
    }

    #[cfg(target_os = "macos")]
    fn wait_for_preview_file(path: &Path) {
        let started = Instant::now();
        while !path.exists() {
            assert!(started.elapsed() < Duration::from_secs(5), "Sensor fixture did not start");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(target_os = "macos")]
    fn preview_script(directory: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn preview_cancellation_kills_descendants_after_the_parent_exits() {
        use std::sync::{mpsc, Arc};
        let scratch = tempfile::tempdir().unwrap();
        let pid_file = scratch.path().join("descendant");
        let script = preview_script(scratch.path(), "sensor", &format!(
            "cat > /dev/null\nsleep 30 &\nprintf '%s %s' \"$$\" \"$!\" > '{}.tmp'\nmv '{}.tmp' '{}'", pid_file.display(), pid_file.display(), pid_file.display()));
        let previews = Arc::new(EnrollmentPreviews::default());
        let generation = previews.invalidate().unwrap();
        let worker_previews = previews.clone();
        let (finished, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            finished.send(bridge_pending(&script, json!({"action":"enrollment.preview"}),
                Some(PreviewCancellation { previews: &worker_previews, generation }))).unwrap();
        });
        wait_for_preview_file(&pid_file);
        let pids: Vec<i32> = fs::read_to_string(&pid_file).unwrap()
            .split_whitespace().map(|pid| pid.parse().unwrap()).collect();
        let parent_exited = Instant::now();
        while unsafe { libc::kill(pids[0], 0) } == 0 {
            assert!(parent_exited.elapsed() < Duration::from_secs(3), "Preview parent was not reaped");
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(unsafe { libc::kill(pids[1], 0) }, 0, "Preview descendant exited before cancellation");
        previews.invalidate().unwrap();
        assert_eq!(result.recv_timeout(Duration::from_secs(3)).unwrap().unwrap_err(), "The enrollment preview was cancelled.");
        worker.join().unwrap();
        let stopped = Instant::now();
        while unsafe { libc::kill(pids[1], 0) } == 0 {
            assert!(stopped.elapsed() < Duration::from_secs(3), "Preview descendant survived cancellation");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn preview_cancellation_interrupts_blocked_input_without_stopping_a_new_preview_or_mutation() {
        use std::sync::{mpsc, Arc};
        let scratch = tempfile::tempdir().unwrap();
        let blocked = scratch.path().join("blocked");
        let script = preview_script(scratch.path(), "blocked-sensor", &format!(
            "touch '{}'\nexec sleep 30", blocked.display()));
        let gate = Arc::new(Mutex::new(()));
        let previews = Arc::new(EnrollmentPreviews::default());
        let generation = previews.invalidate().unwrap();
        let worker_gate = gate.clone();
        let worker_previews = previews.clone();
        let (finished, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            let preview = Some(PreviewCancellation { previews: &worker_previews, generation });
            let _guard = lock_sensor(&worker_gate, preview).unwrap();
            let payload = Request::EnrollmentPreview {
                link: "\"".repeat(8192), ca_certificate: Some("\"".repeat(32768)), generation,
            }.payload().unwrap();
            finished.send(bridge_pending(&script, payload, preview)).unwrap();
        });
        wait_for_preview_file(&blocked);
        let current = previews.invalidate().unwrap();
        assert_eq!(result.recv_timeout(Duration::from_secs(3)).unwrap().unwrap_err(), "The enrollment preview was cancelled.");
        worker.join().unwrap();
        let responsive = preview_script(scratch.path(), "responsive-sensor",
            "cat > /dev/null\nprintf '%s\\n' '{\"ok\":true,\"data\":{\"fresh\":true}}'");
        let current_preview = Some(PreviewCancellation { previews: &previews, generation: current });
        let _guard = lock_sensor(&gate, current_preview).unwrap();
        assert_eq!(bridge_pending(&responsive, json!({"action":"enrollment.preview"}), current_preview).unwrap(), json!({"fresh":true}));
        drop(_guard);

        let started = scratch.path().join("mutation-started");
        let release = scratch.path().join("mutation-release");
        let mutation = preview_script(scratch.path(), "mutation-sensor", &format!(
            "cat > /dev/null\ntouch '{}'\nwhile [ ! -f '{}' ]; do sleep 0.01; done\nprintf '%s\\n' '{{\"ok\":true,\"data\":{{\"installed\":true}}}}'",
            started.display(), release.display()));
        let worker_gate = gate.clone();
        let (finished, result) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _guard = lock_sensor(&worker_gate, None).unwrap();
            finished.send(bridge(&mutation, json!({"action":"setup"}))).unwrap();
        });
        wait_for_preview_file(&started);
        previews.invalidate().unwrap();
        fs::write(&release, "").unwrap();
        assert_eq!(result.recv_timeout(Duration::from_secs(3)).unwrap().unwrap(), json!({"installed":true}));
        worker.join().unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn sensor_stdout_deadline_applies_after_the_parent_exits() {
        use std::os::unix::process::CommandExt;
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 10 & printf 'openaidr-sensor 0.2.0\\n'"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn().unwrap();
        let started = Instant::now();
        assert!(child_output(&mut child, Duration::from_millis(200), 4096).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn purge_progress_pipe_respects_the_child_deadline() {
        use std::os::unix::process::CommandExt;
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 10 >&2 & printf '{\"ok\":true}'"])
            .process_group(0).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        let mut progress = removal_progress::Progress::new(None, None);
        let started = Instant::now();
        assert!(child_output_progress(&mut child, Duration::from_millis(200), 4096, None, None, Some(&mut progress)).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn purge_progress_reaches_the_channel_while_the_sensor_lock_is_held() {
        use std::sync::{Arc, mpsc};
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
        let release = root.join("release");
        let script = preview_script(&root, "purge-sensor", &format!(
            "cat > /dev/null\nprintf '%s\\n' 'OPENAIDR_REMOVAL {{\"stage\":\"deletion\",\"event\":\"start\"}}' >&2\nwhile [ ! -e '{}' ]; do sleep 0.02; done\nprintf '%s\\n' 'OPENAIDR_REMOVAL {{\"stage\":\"deletion\",\"event\":\"failed\",\"operation\":\"unlink\",\"errno\":13,\"error_type\":\"PermissionError\",\"path\":\"data/entry-012345abcdef\"}}' >&2\nprintf '%s\\n' '{{\"ok\":false,\"error\":\"Local data deletion is incomplete. Retry deletion.\"}}'", release.display()));
        let gate = Arc::new(Mutex::new(()));
        let worker_gate = gate.clone();
        let (send, receive) = mpsc::channel();
        let channel = tauri::ipc::Channel::new(move |body| {
            if let tauri::ipc::InvokeResponseBody::Json(body) = body {
                send.send(serde_json::from_str::<Value>(&body).unwrap()).unwrap();
            }
            Ok(())
        });
        let logs = root.join("logs");
        let worker_logs = logs.clone();
        let worker = thread::spawn(move || {
            let _guard = worker_gate.lock().unwrap();
            let mut progress = removal_progress::Progress::new(Some(worker_logs), Some(channel));
            progress.stage("helper_startup");
            bridge_reporting(&script, json!({"action":"desktop.purge"}), None, Some(&mut progress))
        });
        let mut deletion_seen = false;
        while let Ok(event) = receive.recv_timeout(Duration::from_secs(5)) {
            if event["stage"] == "deletion" { deletion_seen = true; break; }
        }
        let locked = gate.try_lock().is_err();
        fs::write(&release, "").unwrap();
        assert!(worker.join().unwrap().unwrap_err().contains("incomplete"));
        assert!(deletion_seen && locked);
        let records = fs::read_to_string(logs.join("desktop.log")).unwrap();
        assert!(records.lines().map(|line| serde_json::from_str::<Value>(line).unwrap())
            .any(|record| record["event"] == "failed" && record["errno"] == 13 && record["path"] == "data/entry-012345abcdef"));
        assert!(receive.try_iter().any(|record| record["event"] == "failed" && record["errno"] == 13));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn usage_bridge_accepts_larger_breakdowns_with_a_bounded_response() {
        let scratch = tempfile::tempdir().unwrap();
        let response = scratch.path().join("response.json");
        let row = json!({"application":"codex","model":"gpt-6-astra","reasoning_effort":"xhigh",
            "calls":100,"priced_calls":100,"tokens":1000000,"cost_usd":100.0});
        let data = json!({"breakdown":vec![row; 10000]});
        let bytes = serde_json::to_vec(&json!({"ok":true,"data":data})).unwrap();
        assert!(bytes.len() > 1024 * 1024 && bytes.len() < 8 * 1024 * 1024);
        fs::write(&response, bytes).unwrap();
        let sensor = preview_script(scratch.path(), "usage-sensor",
            &format!("cat > /dev/null\ncat '{}'", response.display()));
        assert_eq!(bridge(&sensor, json!({"action":"usage.summary"})).unwrap(), data);
        assert!(bridge(&sensor, json!({"action":"status"})).is_err());
        fs::write(&response, serde_json::to_vec(&json!({"ok":true,"data":"x".repeat(8 * 1024 * 1024)})).unwrap()).unwrap();
        assert!(bridge(&sensor, json!({"action":"usage.summary"})).is_err());
    }
}
