use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Mutex},
    thread,
    time::{Duration, SystemTime},
};
use tauri::Manager;

const RESPONSE_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Default)]
pub struct Usage(Mutex<Worker>);

#[derive(Default)]
struct Worker {
    child: Option<Child>,
    output: Option<mpsc::Receiver<Result<Value, String>>>,
    executable: Option<(PathBuf, u64, SystemTime)>,
}

fn identity(path: &Path) -> Option<(PathBuf, u64, SystemTime)> {
    let metadata = path.metadata().ok()?;
    Some((path.to_owned(), metadata.len(), metadata.modified().ok()?))
}

impl Worker {
    fn current(&mut self) -> bool {
        self.child.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)))
            && self.executable.as_ref().is_some_and(|previous| identity(&previous.0).as_ref() == Some(previous))
    }

    fn stop(&mut self) {
        self.output = None;
        self.executable = None;
        if let Some(mut child) = self.child.take() {
            drop(child.stdin.take());
            super::stop_child(&mut child);
        }
    }

    fn start(&mut self, executable: &Path) -> Result<(), String> {
        self.stop();
        let mut command = Command::new(executable);
        command.arg("desktop-usage").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        super::hide_console(&mut command);
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|_| "Cannot start the usage helper.")?;
        let stdout = child.stdout.take().ok_or("Cannot read usage output.")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let result = match input.by_ref().take(RESPONSE_LIMIT + 1).read_until(b'\n', &mut bytes) {
                    Ok(0) | Err(_) => Err("The usage helper stopped responding.".into()),
                    Ok(_) if bytes.len() as u64 > RESPONSE_LIMIT => Err("Usage response exceeded the size limit.".into()),
                    Ok(_) if bytes.last() != Some(&b'\n') => Err("The usage helper returned an incomplete response.".into()),
                    Ok(_) => serde_json::from_slice(&bytes).map_err(|_| "The usage helper returned an invalid response.".into()),
                };
                let failed = result.is_err();
                if sender.send(result).is_err() || failed { break; }
            }
        });
        self.executable = identity(executable);
        self.child = Some(child);
        self.output = Some(receiver);
        Ok(())
    }

    fn exchange(&mut self, payload: &Value, timeout: Duration) -> Result<Value, String> {
        let result = (|| {
            let input = self.child.as_mut().and_then(|child| child.stdin.as_mut())
                .ok_or("The usage helper is unavailable.")?;
            serde_json::to_writer(&mut *input, payload).map_err(|_| "Cannot send the usage request.")?;
            input.write_all(b"\n").map_err(|_| "Cannot send the usage request.")?;
            let response = self.output.as_ref().ok_or("Cannot read usage output.")?
                .recv_timeout(timeout).map_err(|_| "The usage helper did not respond in time.")??;
            if response["ok"] != true || !response["data"].is_object() {
                return Err(response["error"].as_str().unwrap_or("The usage helper returned an invalid response.").to_owned());
            }
            Ok(response["data"].clone())
        })();
        if result.is_err() { self.stop(); }
        result
    }
}

impl Drop for Worker {
    fn drop(&mut self) { self.stop(); }
}

pub fn request(app: &tauri::AppHandle, payload: &Value) -> Result<Value, String> {
    let state = app.state::<Usage>();
    let mut worker = state.0.lock().map_err(|_| "Cannot lock the usage helper.")?;
    if !worker.current() {
        // Stage and validate only when starting a helper, not on every refresh.
        worker.start(&super::stable_binary(app)?)?;
    }
    worker.exchange(payload, Duration::from_secs(60))
}

pub fn shutdown(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<Usage>() {
        if let Ok(mut worker) = state.0.lock() { worker.stop(); }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn script(directory: &Path, content: &str) -> PathBuf {
        let path = directory.join("usage-helper");
        std::fs::write(&path, format!("#!/bin/sh\n{content}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn usage_worker_reuses_process_and_detects_replaced_binary() {
        let directory = tempfile::tempdir().unwrap();
        let path = script(directory.path(), "while read -r request; do printf '{\"ok\":true,\"data\":{\"pid\":%s}}\\n' \"$$\"; done");
        let mut worker = Worker::default();
        worker.start(&path).unwrap();
        let request = json!({"action":"usage.summary","params":{"days":30}});
        let first = worker.exchange(&request, Duration::from_secs(2)).unwrap();
        assert!(worker.current());
        assert_eq!(worker.exchange(&request, Duration::from_secs(2)).unwrap(), first);
        std::fs::write(&path, "#!/bin/sh\nexit 1\n").unwrap();
        assert!(!worker.current());
        worker.stop();
        assert!(worker.child.is_none());
    }

    #[test]
    fn usage_worker_recovers_after_invalid_output_and_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let mut worker = Worker::default();
        let request = json!({"action":"usage.summary"});
        for script_text in ["read -r request; printf 'invalid\\n'", "read -r request; read -r another"] {
            let path = script(directory.path(), script_text);
            worker.start(&path).unwrap();
            assert!(worker.exchange(&request, Duration::from_millis(100)).is_err());
            assert!(worker.child.is_none());
        }
        let path = script(directory.path(), "while read -r request; do printf '{\"ok\":true,\"data\":{}}\\n'; done");
        worker.start(&path).unwrap();
        assert_eq!(worker.exchange(&request, Duration::from_secs(2)).unwrap(), json!({}));
    }

    #[test]
    fn usage_worker_rejects_oversized_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = script(directory.path(), "read -r request; head -c 8388609 /dev/zero");
        let mut worker = Worker::default();
        worker.start(&path).unwrap();
        assert!(worker.exchange(&json!({}), Duration::from_secs(2)).unwrap_err().contains("size limit"));
        assert!(worker.child.is_none());
    }
}
