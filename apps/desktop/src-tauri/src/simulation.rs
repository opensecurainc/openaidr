use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tauri::Manager;

#[derive(Default)]
pub struct Simulation(Mutex<Runner>);

#[derive(Default)]
struct Runner {
    child: Option<Child>,
    reader: Option<thread::JoinHandle<()>>,
    snapshot: Arc<Mutex<Value>>,
}

impl Runner {
    fn snapshot(&self) -> Value {
        self.snapshot.lock().map(|value| value.clone()).unwrap_or_else(|_| {
            json!({"enabled":true,"state":"error","error":"Cannot read simulation status."})
        })
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Closing stdin also stops the worker if the desktop exits unexpectedly.
            drop(child.stdin.take());
            let started = Instant::now();
            loop {
                if matches!(child.try_wait(), Ok(Some(_)))
                    && self
                        .reader
                        .as_ref()
                        .map_or(true, |reader| reader.is_finished())
                {
                    break;
                }
                if started.elapsed() >= Duration::from_secs(7) {
                    super::stop_child(&mut child);
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            if let Some(reader) = self.reader.take() {
                if reader.is_finished() {
                    let _ = reader.join();
                }
            }
            self.snapshot = Arc::new(Mutex::new(self.snapshot()));
            if let Ok(mut snapshot) = self.snapshot.lock() {
                if snapshot["state"] != "error" {
                    snapshot["state"] = json!("stopped");
                }
            }
        }
    }

    fn poll(&mut self) {
        if let Some(child) = &mut self.child {
            if let Ok(Some(exit)) = child.try_wait() {
                if self
                    .reader
                    .as_ref()
                    .is_some_and(|reader| !reader.is_finished())
                {
                    return;
                }
                if let Some(reader) = self.reader.take() {
                    let _ = reader.join();
                }
                self.child = None;
                if let Ok(mut snapshot) = self.snapshot.lock() {
                    if snapshot["state"] != "error" {
                        snapshot["state"] = json!(if exit.success() { "stopped" } else { "error" });
                        if !exit.success() {
                            snapshot["error"] = json!("Simulation exited unexpectedly.");
                        }
                    }
                }
            }
        }
    }

    fn start(&mut self, executable: &std::path::Path) -> Result<(), String> {
        self.poll();
        if self.child.is_some() {
            return Ok(());
        }
        let mut command = Command::new(executable);
        command
            .arg("simulate-devices")
            .env("OPENAIDR_DEVICE_SIMULATION", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "Cannot start the simulation worker.")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("Cannot read simulation output.")?;
        let destination = self.snapshot()["destination"].clone();
        self.snapshot = Arc::new(Mutex::new(
            json!({"enabled":true,"configured":true,"state":"starting","devices":100,"destination":destination,
                   "enrolled":0,"records_sent":0,"inventories_sent":0,"errors":0,"error":""}),
        ));
        let snapshot = self.snapshot.clone();
        self.reader = Some(thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match input.by_ref().take(65537).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    _ if line.len() > 65536 => break,
                    _ => {
                        if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                            if value.is_object() {
                                if let Ok(mut current) = snapshot.lock() {
                                    *current = value;
                                }
                            }
                        }
                    }
                }
            }
        }));
        self.child = Some(child);
        Ok(())
    }
}

pub fn request(app: &tauri::AppHandle, action: &str) -> Result<Value, String> {
    if !cfg!(all(feature = "simulation", unix)) {
        return if action == "simulation.status" {
            Ok(json!({"enabled":false}))
        } else {
            Err("Device simulation is unavailable in this build.".into())
        };
    }
    let state = app.state::<Simulation>();
    let mut runner = state
        .0
        .lock()
        .map_err(|_| "Cannot lock simulation controls.")?;
    runner.poll();
    if runner.child.is_none() {
        let mut configured = super::bridge(
            &super::bundled_binary(app)?,
            json!({"action":"simulation.status"}),
        )?;
        let previous = runner.snapshot();
        for key in [
            "state",
            "enrolled",
            "records_sent",
            "inventories_sent",
            "errors",
        ] {
            if !previous[key].is_null() {
                configured[key] = previous[key].clone();
            }
        }
        if configured["configured"] == true && previous["state"] == "error" {
            configured["error"] = previous["error"].clone();
        }
        *runner
            .snapshot
            .lock()
            .map_err(|_| "Cannot read simulation status.")? = configured;
    }
    match action {
        "simulation.start" if runner.snapshot()["configured"] == true => {
            runner.start(&super::bundled_binary(app)?)?
        }
        "simulation.stop" => runner.stop(),
        _ => {}
    }
    Ok(runner.snapshot())
}

pub fn shutdown(app: &tauri::AppHandle) {
    if let Ok(mut runner) = app.state::<Simulation>().0.lock() {
        runner.stop();
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn simulation_worker_is_single_and_stops_when_its_input_closes() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("sensor");
        std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' '{\"enabled\":true,\"state\":\"running\",\"records_sent\":5}'\nread -r ignored\nprintf '%s\\n' '{\"enabled\":true,\"state\":\"stopped\",\"records_sent\":5}'\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut runner = Runner::default();
        runner.start(&script).unwrap();
        let pid = runner.child.as_ref().unwrap().id();
        runner.start(&script).unwrap();
        assert_eq!(runner.child.as_ref().unwrap().id(), pid);
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.snapshot()["state"] != "running" && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(runner.snapshot()["state"], "running");
        runner.stop();
        assert!(runner.child.is_none());
        assert_eq!(runner.snapshot()["state"], "stopped");
        assert_eq!(runner.snapshot()["records_sent"], 5);
        runner.start(&script).unwrap();
        runner.stop();
        assert!(runner.child.is_none());
    }
}
