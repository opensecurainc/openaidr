pub fn contact_support() -> Result<(), String> {
    open_external("mailto:contact@opensecura.ai",
        "Could not open your email app. Email contact@opensecura.ai for support.")
}

fn google_url(value: &str) -> Result<&str, String> {
    let id = value.strip_prefix("https://console.opensecura.ai/connect/?request=")
        .ok_or("Invalid Google sign-in address.")?;
    if id.len() != 36 || !id.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    }) { return Err("Invalid Google sign-in address.".into()); }
    Ok(value)
}

pub fn open_google(value: &str) -> Result<(), String> {
    open_external(google_url(value)?, "Could not open your browser. Retry Google sign-in.")
}

pub fn open_dashboard(server_url: &str, local_session: impl FnOnce() -> Result<Option<(String, String)>, String>) -> Result<(), String> {
    let url = dashboard_url(server_url)?;
    if url.as_str() == "http://localhost:8080/" {
        if let Some((session, nonce)) = local_session()? {
            let handoff = crate::local_dashboard::Handoff::new(&session, &nonce, 8080)
                .map_err(|_| "Could not prepare local dashboard sign-in.")?;
            let target = handoff.url();
            std::thread::Builder::new().name("dashboard-sign-in".into())
                .spawn(move || handoff.serve(std::time::Duration::from_secs(60)))
                .map_err(|_| "Could not start local dashboard sign-in.")?;
            return open_external(&target, "Could not open your browser.");
        }
    }
    open_external(url.as_str(), "Could not open your browser.")
}

pub fn show_configuration(path: &str) -> Result<(), String> {
    // The sensor resolves a fixed agent's file. Open its folder so an executable
    // plugin (for example OpenCode's .js file) can never run via a file association.
    let _directory = configuration_directory(path)?;
    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        // Reveal in Finder, including when the parent happens to be an app bundle.
        let result = Command::new("/usr/bin/open").arg("-R").arg(path)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .status().map_err(|_| "Could not show the configuration in Finder.".to_owned())?;
        if !result.success() { return Err("Could not show the configuration in Finder.".into()); }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    open_external(_directory.to_str().ok_or("Invalid configuration directory.")?,
        "Could not open the configuration folder.")
}

fn configuration_directory(path: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() || !path.is_file() { return Err("Configuration file is unavailable.".into()); }
    path.parent().map(std::path::Path::to_path_buf).ok_or("Invalid configuration directory.".into())
}

fn dashboard_url(server_url: &str) -> Result<tauri::Url, String> {
    let error = "The dashboard address must be an HTTP(S) server origin.";
    let url = tauri::Url::parse(server_url).map_err(|_| error.to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some()
        || url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(error.into());
    }
    Ok(url)
}

fn open_external(target: &str, error: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        let url: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
        let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        // Callers supply a fixed support address, validated web origin, or existing folder.
        let result = unsafe {
            ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), url.as_ptr(),
                std::ptr::null(), std::ptr::null(), 1)
        };
        if result as isize <= 32 { return Err(error.into()); }
    }
    #[cfg(not(windows))]
    {
        use std::process::{Command, Stdio};
        let opener = if cfg!(target_os = "macos") { "/usr/bin/open" } else { "xdg-open" };
        let status = Command::new(opener).arg(target)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .status().map_err(|_| error.to_owned())?;
        if !status.success() { return Err(error.into()); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::dashboard_url;

    #[test]
    fn google_sign_in_opens_only_a_fixed_console_pairing_address() {
        let good = "https://console.opensecura.ai/connect/?request=01000000-0000-7000-8000-000000000001";
        assert_eq!(super::google_url(good).unwrap(), good);
        for value in [good.replace("console.opensecura.ai", "other.example"), format!("{good}&token=secret"),
                      good.replace("https:", "http:"), good.replace("/connect/", "/"), format!("{good}#secret")] {
            assert!(super::google_url(&value).is_err());
        }
    }

    #[test]
    fn configuration_opens_only_the_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let plugin = dir.path().join("openaidr.js");
        std::fs::write(&plugin, "throw new Error('must not run');").unwrap();
        assert_eq!(super::configuration_directory(plugin.to_str().unwrap()).unwrap(), dir.path());
        for path in ["../openaidr.js", "https://example.test", dir.path().to_str().unwrap()] {
            assert!(super::configuration_directory(path).is_err());
        }
    }

    #[test]
    fn dashboard_links_allow_only_web_origins() {
        for (input, expected) in [
            ("https://tenant.example", "https://tenant.example/"),
            ("https://192.168.1.50:8443/", "https://192.168.1.50:8443/"),
            ("http://localhost:8080", "http://localhost:8080/"),
            ("http://[::1]:8080", "http://[::1]:8080/"),
        ] {
            assert_eq!(dashboard_url(input).unwrap().as_str(), expected);
        }
        for input in [
            "", "tenant.example", "//tenant.example", "https://", "-a Calculator",
            "javascript:alert(1)", "file:///Applications/Calculator.app", "mailto:user@example.com",
            "https://user:secret@tenant.example", "https://tenant.example/enroll",
            "https://tenant.example/?token=secret", "https://tenant.example/#token=secret",
        ] {
            assert!(dashboard_url(input).is_err(), "{input}");
        }
    }
}
