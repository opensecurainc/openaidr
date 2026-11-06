use serde_json::{json, Value};
use std::{io::Read, sync::mpsc::{self, Receiver}, thread, path::PathBuf, time::Instant};

pub struct Progress {
    directory: Option<PathBuf>,
    channel: Option<tauri::ipc::Channel<Value>>,
    started: Instant,
    stage: String,
    stage_started: Instant,
}

impl Progress {
    pub fn new(directory: Option<PathBuf>, channel: Option<tauri::ipc::Channel<Value>>) -> Self {
        let mut progress = Self { directory, channel, started: Instant::now(), stage: "waiting".into(), stage_started: Instant::now() };
        progress.emit(json!({"stage":"waiting","event":"start"}));
        progress
    }

    fn emit(&mut self, mut event: Value) {
        event["elapsed_ms"] = json!(self.started.elapsed().as_millis() as u64);
        if let Some(directory) = &self.directory { crate::record_event(directory, "desktop.trash.progress", event.clone()); }
        if let Some(channel) = &self.channel { let _ = channel.send(event); }
    }

    pub fn stage(&mut self, stage: &'static str) {
        self.finish(true);
        self.stage = stage.into();
        self.stage_started = Instant::now();
        self.emit(json!({"stage":stage,"event":"start"}));
    }

    pub fn finish(&mut self, ok: bool) {
        if !self.stage.is_empty() {
            self.emit(json!({"stage":self.stage,"event":if ok {"complete"} else {"failed"},
                "ms":self.stage_started.elapsed().as_millis() as u64}));
            self.stage.clear();
        }
    }

    pub fn helper(&mut self, event: Value) {
        if self.stage == "helper_startup" { self.finish(true); }
        if event["event"] == "start" {
            self.stage = event["stage"].as_str().unwrap_or_default().to_owned();
            self.stage_started = Instant::now();
        } else { self.stage.clear(); }
        self.emit(event);
    }
}

impl Drop for Progress {
    fn drop(&mut self) { self.finish(false); }
}

// Consume stderr separately from the final stdout JSON. Bound line storage,
// record count, and the queue; ignore ordinary stderr and unknown fields.
pub fn read_helper(input: impl Read + Send + 'static) -> (Receiver<Value>, thread::JoinHandle<()>) {
    let (send, receive) = mpsc::sync_channel(64);
    let reader = thread::spawn(move || {
        let mut input = input;
        let mut chunk = [0; 1024];
        let mut line = Vec::new();
        let mut oversized = false;
        let mut records = 0;
        while let Ok(size) = input.read(&mut chunk) {
            if size == 0 { break; }
            for byte in &chunk[..size] {
                if *byte == b'\n' {
                    if !oversized && records < 64 {
                        if let Some(event) = parse(&line) {
                            records += 1;
                            let _ = send.try_send(event);
                        }
                    }
                    line.clear();
                    oversized = false;
                } else if line.len() < 1024 && !oversized {
                    line.push(*byte);
                } else {
                    oversized = true;
                }
            }
        }
    });
    (receive, reader)
}

fn parse(line: &[u8]) -> Option<Value> {
    let raw: Value = serde_json::from_slice(line.strip_prefix(b"OPENAIDR_REMOVAL ")?).ok()?;
    let stage = raw["stage"].as_str()?;
    if !matches!(stage, "validation" | "configuration_lock" | "scan" | "services" | "integrations" | "deletion" | "record") { return None; }
    let event = raw["event"].as_str()?;
    if !matches!(event, "start" | "complete" | "failed") { return None; }
    let mut safe = json!({"stage":stage,"event":event});
    for key in ["ms", "files", "directories", "errno"] {
        if let Some(value) = raw[key].as_u64() { safe[key] = json!(value); }
    }
    if let Some(operation) = raw["operation"].as_str().filter(|value| matches!(*value,
        "validate" | "close" | "islink" | "open" | "fstat" | "listdir" | "stat" | "lstat" | "scandir" | "rmtree" | "unlink" | "rmdir" | "identity" | "write")) {
        safe["operation"] = json!(operation);
    }
    if let Some(kind) = raw["error_type"].as_str().filter(|value| matches!(*value,
        "OSError" | "PermissionError" | "FileNotFoundError" | "NotADirectoryError" | "IsADirectoryError" | "FileExistsError" | "BlockingIOError")) {
        safe["error_type"] = json!(kind);
    }
    if let Some(path) = raw["path"].as_str().filter(|value| value.len() <= 200 && value.split('/').all(|part|
        matches!(part, "." | "outside-root" | "data" | "bin" | "logs" | "credentials" | "sensor.yaml" | "desktop-removal.json")
        || part.strip_prefix("entry-").is_some_and(|hash| hash.len() == 12 && hash.bytes().all(|c| c.is_ascii_hexdigit())))) {
        safe["path"] = json!(path);
    }
    Some(safe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_progress_is_bounded_and_does_not_forward_arbitrary_output() {
        let mut input = vec![b'x'; 10_000];
        input.extend_from_slice(b"\nraw secret\nOPENAIDR_REMOVAL {\"stage\":\"deletion\",\"event\":\"failed\",\"operation\":\"unlink\",\"errno\":13,\"error_type\":\"PermissionError\",\"path\":\"data/entry-012345abcdef\",\"secret\":\"credential\"}\n");
        let (events, reader) = read_helper(std::io::Cursor::new(input));
        reader.join().unwrap();
        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(events, vec![json!({"stage":"deletion","event":"failed","operation":"unlink","errno":13,
            "error_type":"PermissionError","path":"data/entry-012345abcdef"})]);
        assert!(parse(b"OPENAIDR_REMOVAL {\"stage\":\"secret\",\"event\":\"start\"}").is_none());
        let unsafe_path = parse(b"OPENAIDR_REMOVAL {\"stage\":\"deletion\",\"event\":\"failed\",\"path\":\"/Users/private/token\"}").unwrap();
        assert!(unsafe_path.get("path").is_none());
        let (events, reader) = read_helper(std::io::Cursor::new(b"OPENAIDR_REMOVAL {\"stage\":\"scan\",\"event\":\"start\"}\n".repeat(1000)));
        reader.join().unwrap();
        assert_eq!(events.try_iter().count(), 64);
    }
}
