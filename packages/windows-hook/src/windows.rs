use super::*;
use std::{
    ffi::c_void,
    fs,
    io::{self, Write},
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    ptr::{null, null_mut},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::FILETIME,
        Networking::WinHttp::*,
        System::{
            Com::CoCreateGuid,
            Threading::{
                GetCurrentProcess, GetProcessTimes, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
                DETACHED_PROCESS,
            },
        },
    },
};

fn now() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())
}

fn started() -> Result<u128> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    check(unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    })?;
    let ticks = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    Ok((ticks
        .checked_sub(116_444_736_000_000_000)
        .ok_or("invalid process time")? as u128)
        * 100)
}

fn execution_id() -> Result<String> {
    let mut guid = GUID::from_u128(0);
    if unsafe { CoCreateGuid(&mut guid) } < 0 {
        return Err("execution ID unavailable".into());
    }
    Ok(format!(
        "{:08x}{:04x}{:04x}{}",
        guid.data1,
        guid.data2,
        guid.data3,
        hex(&guid.data4)
    ))
}

fn check(ok: i32) -> Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

struct Handle(*mut c_void);
impl Handle {
    fn new(value: *mut c_void) -> Result<Self> {
        if value.is_null() {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(Self(value))
        }
    }
    fn option(&self, option: u32, value: u32) -> Result<()> {
        check(unsafe { WinHttpSetOption(self.0, option, (&value as *const u32).cast(), 4) })
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}

fn post(address: SocketAddr, token: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
    // Numeric loopback only, no proxy discovery, automatic authentication,
    // cookies, redirects or retries. The agent owns process cancellation.
    let session = Handle::new(unsafe {
        WinHttpOpen(
            wide("OpenAIDR hook").as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            null(),
            null(),
            0,
        )
    })?;
    check(unsafe { WinHttpSetTimeouts(session.0, 0, 0, 0, 0) })?;
    session.option(WINHTTP_OPTION_CONNECT_RETRIES, 0)?;
    let host = address.ip().to_string();
    let connect =
        Handle::new(unsafe { WinHttpConnect(session.0, wide(&host).as_ptr(), address.port(), 0) })?;
    let request = Handle::new(unsafe {
        WinHttpOpenRequest(
            connect.0,
            wide("POST").as_ptr(),
            wide(path).as_ptr(),
            null(),
            null(),
            null(),
            0,
        )
    })?;
    request.option(
        WINHTTP_OPTION_DISABLE_FEATURE,
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION,
    )?;
    let mut headers = "Content-Type: application/json\r\n".to_string();
    if !token.is_empty() {
        headers += &format!("Authorization: Bearer {token}\r\n");
    }
    let headers = wide(&headers);
    check(unsafe {
        WinHttpSendRequest(
            request.0,
            headers.as_ptr(),
            (headers.len() - 1) as u32,
            body.as_ptr().cast(),
            body.len() as u32,
            body.len() as u32,
            0,
        )
    })?;
    check(unsafe { WinHttpReceiveResponse(request.0, null_mut()) })?;
    let mut status = 0u32;
    let mut size = 4;
    check(unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status as *mut u32).cast(),
            &mut size,
            null_mut(),
        )
    })?;
    if status != 200 {
        return Err("hook HTTP error".into());
    }
    let mut response = Vec::new();
    loop {
        let mut buffer = [0u8; 8192];
        let mut read = 0;
        check(unsafe {
            WinHttpReadData(
                request.0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
            )
        })?;
        if read == 0 {
            break;
        }
        if response.len() + read as usize > MAX_BYTES as usize {
            return Err("oversized response".into());
        }
        response.extend_from_slice(&buffer[..read as usize]);
    }
    Ok(response)
}

fn managed(config: &Value, start: u128, deadline: u128, execution: &str) -> Result<Vec<u8>> {
    // Managed launches have their own bridge contract. Keep the existing CLI
    // for this special path, without an additional PowerShell wrapper.
    let args = config["args"].as_array().ok_or("missing managed command")?;
    let args: Vec<&str> = args
        .iter()
        .map(|v| v.as_str().ok_or("invalid command"))
        .collect::<std::result::Result<_, _>>()?;
    let mut child = Command::new(args.first().ok_or("missing executable")?)
        .args(&args[1..])
        .env("OPENAIDR_HOOK_WRAPPED", "1")
        .env("OPENAIDR_HOOK_TIMEOUT_OWNER", "agent")
        .env("OPENAIDR_HOOK_STARTED_NS", start.to_string())
        .env("OPENAIDR_HOOK_DEADLINE_NS", deadline.to_string())
        .env("OPENAIDR_HOOK_EXECUTION_ID", execution)
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    let result = bounded(child.stdout.take().ok_or("missing child output")?);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let bytes = result?;
    if !status.success() {
        return Err("managed hook failed".into());
    }
    if bytes.is_empty() {
        return Ok(bytes);
    }
    let reply: Value = serde_json::from_slice(&bytes)?;
    if !reply.is_object() {
        return Err("invalid managed output".into());
    }
    Ok(bytes)
}

fn decide(config: &Value, start: u128, deadline: u128, execution: &str) -> Result<Vec<u8>> {
    if std::env::var_os("OPENAIDR_MANAGED_BRIDGE").is_some_and(|s| !s.is_empty()) {
        return managed(config, start, deadline, execution);
    }
    let path = if config["explicit_config"].as_bool() == Some(true) {
        PathBuf::from(field(config, "sensor_config")?)
    } else {
        std::env::var_os("OPENAIDR_SENSOR_CONFIG")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or(PathBuf::from(field(config, "sensor_config")?))
    };
    let (address, token) = endpoint(&path)?;
    let bytes = bounded(io::stdin().lock())?;
    if !serde_json::from_slice::<Value>(&bytes)?.is_object() {
        return Err("invalid hook input".into());
    }
    if now()? >= deadline {
        return Err("expired hook".into());
    }
    let agent = field(config, "agent")?;
    let event = field(config, "event")?;
    let route = match agent {
        "claude" => "claude-code",
        "codex" => "codex",
        "copilot" => "github-copilot",
        "cursor" => "cursor",
        "antigravity" => "antigravity",
        "opencode" => "opencode",
        "workbuddy" => "workbuddy",
        _ => return Err("invalid hook identity".into()),
    };
    let mut path = format!("/v1/hooks/{route}?event={event}&started={start}&deadline={deadline}&execution={execution}&timeout_owner=agent&client_pid={}", std::process::id());
    if event == "PreToolUse" {
        // Match the user profile used by Python Path.home(), not the project.
        if let Some(home) = std::env::var_os("USERPROFILE") {
            path += &format!("&path_home={}", query(&home.to_string_lossy()));
        }
    }
    output(&post(address, &token, &path, &bytes)?)
}

fn report(value: &Value) -> Result<()> {
    let directory = Path::new(field(value, "directory")?);
    let name = field(value, "name")?;
    if name.len() > 200 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.') {
        return Err("invalid receipt".into());
    }
    fs::create_dir_all(directory)?;
    if fs::read_dir(directory)?.take(4096).count() < 4096 {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?;
    }
    Ok(())
}

pub fn main(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err("invalid invocation".into());
    }
    if args[1] == "--report" {
        return report(&serde_json::from_slice(&unhex(&args[2])?)?);
    }
    if args[1] != "--openaidr-hook" {
        return Err("invalid invocation".into());
    }
    let start = started()?;
    let descriptor = String::from_utf8(unhex(&args[2])?)?;
    let config: Value = serde_json::from_slice(&bounded(fs::File::open(descriptor)?)?)?;
    let seconds = config["seconds"]
        .as_u64()
        .filter(|s| *s > 0)
        .ok_or("invalid hook timeout")?;
    let deadline = start + u128::from(seconds) * 1_000_000_000;
    let agent = field(&config, "agent")?;
    let event = field(&config, "event")?;
    if !["claude", "codex", "copilot", "cursor", "antigravity", "opencode", "workbuddy"].contains(&agent)
        || event.is_empty()
        || !event.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return Err("invalid hook identity".into());
    }
    let execution = execution_id()?;
    let result = decide(&config, start, deadline, &execution);
    let code = if now()? >= deadline {
        124
    } else if let Ok(bytes) = result {
        if io::stdout().lock().write_all(&bytes).is_ok() {
            0
        } else {
            1
        }
    } else {
        1
    };
    let receipt = serde_json::json!({"directory":field(&config, "directory")?,
        "name":format!("{agent}.{event}.{}.{code}.{execution}.agent", now()? / 1_000_000_000)});
    // Disk writes occur in another native process. Explicit null standard
    // handles prevent it from keeping the agent's output pipes open.
    let _ = Command::new(std::env::current_exe()?)
        .args(["--report", &hex(&serde_json::to_vec(&receipt)?)])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(std::env::var_os("SystemRoot").unwrap_or("C:\\Windows".into()))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn();
    Ok(())
}
