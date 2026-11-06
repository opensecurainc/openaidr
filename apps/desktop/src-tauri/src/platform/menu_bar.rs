#[cfg(target_os = "linux")]
#[path = "linux/tray_host.rs"]
mod tray_host;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{TrayIcon, TrayIconBuilder},
    Manager, Runtime,
};

const TRAY_ID: &str = "openaidr-menu-bar";
const REFRESH: Duration = Duration::from_secs(15);
const STALE: Duration = Duration::from_secs(45);

#[derive(Default, Deserialize, Serialize)]
struct Preferences {
    show_in_menu_bar: bool,
}

struct State<R: Runtime> {
    path: PathBuf,
    window: tauri::utils::config::WindowConfig,
    tray: Option<TrayIcon<R>>,
    status: Option<MenuItem<R>>,
    health: Option<(String, Instant)>,
}

pub(crate) fn initialize<R: Runtime>(
    app: &tauri::AppHandle<R>,
    window: &tauri::utils::config::WindowConfig,
) -> tauri::Result<()> {
    if app.try_state::<Mutex<State<R>>>().is_some() {
        return Ok(());
    }
    let path = app
        .path()
        .app_config_dir()?
        .join("desktop-preferences.json");
    let enabled = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Preferences>(&bytes).ok())
        .unwrap_or_default()
        .show_in_menu_bar;
    app.manage(Mutex::new(State::<R> {
        path,
        window: window.clone(),
        tray: None,
        status: None,
        health: Some(("Checking sensor…".into(), Instant::now())),
    }));
    #[cfg(target_os = "linux")]
    tray_host::initialize(app);
    // A missing or unreadable preference must never stop the desktop from opening.
    if enabled {
        let _ = configure(app, true, false);
    }
    app.on_menu_event(on_menu_event);
    let handle = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(REFRESH);
        let app = handle.clone();
        if handle.run_on_main_thread(move || refresh(&app)).is_err() {
            break;
        }
    });
    Ok(())
}

pub(crate) fn on_menu_event<R: Runtime>(app: &tauri::AppHandle<R>, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        "menu-bar-open" => {
            let _ = open_window(app);
        }
        "menu-bar-quit" => app.exit(0),
        _ => {}
    }
}

pub(crate) fn enabled<R: Runtime>(app: &tauri::AppHandle<R>) -> bool {
    app.try_state::<Mutex<State<R>>>()
        .and_then(|state| state.lock().ok().map(|state| state.tray.is_some()))
        .unwrap_or(false)
}

pub(crate) fn available<R: Runtime>(app: &tauri::AppHandle<R>) -> bool {
    #[cfg(target_os = "linux")]
    { tray_host::available(app) }
    #[cfg(not(target_os = "linux"))]
    { let _ = app; true }
}

pub(crate) fn settings<R: Runtime>(
    app: &tauri::AppHandle<R>,
    enabled: Option<bool>,
) -> Result<Value, String> {
    if let Some(enabled) = enabled {
        configure(app, enabled, true)?;
    }
    Ok(json!({"supported":true,"enabled":self::enabled(app),"available":available(app),
        "label":if cfg!(target_os = "macos") { "Show in menu bar" } else { "Show in system tray" }}))
}

fn configure<R: Runtime>(
    app: &tauri::AppHandle<R>,
    enabled: bool,
    persist: bool,
) -> Result<(), String> {
    let state = app.state::<Mutex<State<R>>>();
    let mut state = state
        .lock()
        .map_err(|_| "Could not read the tray setting.")?;
    let created = if enabled && state.tray.is_none() {
        let status = MenuItem::with_id(
            app,
            "menu-bar-status",
            "Checking sensor…",
            false,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;
        let open = MenuItem::with_id(app, "menu-bar-open", "Open OpenAIDR", true, None::<&str>)
            .map_err(|e| e.to_string())?;
        let quit = MenuItem::with_id(app, "menu-bar-quit", "Quit OpenAIDR", true, None::<&str>)
            .map_err(|e| e.to_string())?;
        let note = MenuItem::with_id(
            app,
            "menu-bar-quit-note",
            "Quitting does not stop the sensor",
            false,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;
        let separator = PredefinedMenuItem::separator(app).map_err(|e| e.to_string())?;
        let menu = Menu::with_items(app, &[&status, &open, &separator, &note, &quit])
            .map_err(|e| e.to_string())?;
        #[cfg(target_os = "macos")]
        let icon = include_bytes!("../../icons/menu-bar-macos.png").as_slice();
        #[cfg(not(target_os = "macos"))]
        let icon = include_bytes!("../../icons/icon.png").as_slice();
        let tray = TrayIconBuilder::with_id(TRAY_ID)
            .icon(Image::from_bytes(icon).map_err(|e| e.to_string())?)
            .icon_as_template(cfg!(target_os = "macos"))
            .tooltip("OpenAIDR: Checking sensor…")
            .menu(&menu)
            .build(app)
            .map_err(|e| e.to_string())?;
        Some((tray, status))
    } else {
        None
    };
    if persist {
        let save = || -> Result<(), Box<dyn std::error::Error>> {
            let directory = state.path.parent().ok_or("Missing preferences directory")?;
            fs::create_dir_all(directory)?;
            let mut file = tempfile::NamedTempFile::new_in(directory)?;
            serde_json::to_writer(
                &mut file,
                &Preferences {
                    show_in_menu_bar: enabled,
                },
            )?;
            file.flush()?;
            file.persist(&state.path)?;
            Ok(())
        };
        if save().is_err() {
            if created.is_some() {
                app.remove_tray_by_id(TRAY_ID);
            }
            return Err("Could not save the tray setting. Try again.".into());
        }
    }
    if let Some((tray, status)) = created {
        state.tray = Some(tray);
        state.status = Some(status);
    }
    if !enabled {
        app.remove_tray_by_id(TRAY_ID);
        state.tray = None;
        state.status = None;
    }
    if let Some((label, updated)) = &state.health {
        if updated.elapsed() < STALE {
            display(&state, label)?;
        }
    }
    Ok(())
}

fn display<R: Runtime>(state: &State<R>, label: &str) -> Result<(), String> {
    if let (Some(status), Some(tray)) = (&state.status, &state.tray) {
        #[cfg(target_os = "linux")]
        let _ = tray;
        status.set_text(label).map_err(|e| e.to_string())?;
        #[cfg(not(target_os = "linux"))]
        tray.set_tooltip(Some(format!("OpenAIDR: {label}")))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn health<R: Runtime>(
    app: &tauri::AppHandle<R>,
    label: String,
    _attention: bool,
) -> Result<(), String> {
    if label.is_empty() || label.len() > 160 || label.chars().any(char::is_control) {
        return Err("Invalid tray status.".into());
    }
    let state = app.state::<Mutex<State<R>>>();
    let mut state = state
        .lock()
        .map_err(|_| "Could not update the tray status.")?;
    display(&state, &label)?;
    state.health = Some((label, Instant::now()));
    Ok(())
}

fn refresh<R: Runtime>(app: &tauri::AppHandle<R>) {
    let state = app.state::<Mutex<State<R>>>();
    let Ok(state) = state.lock() else {
        return;
    };
    if state.tray.is_none() {
        return;
    }
    if state
        .health
        .as_ref()
        .is_none_or(|(_, updated)| updated.elapsed() >= STALE)
    {
        let _ = display(&state, "Status unavailable");
    }
    // Native scheduling also works when WebKit throttles hidden-page timers.
    if let Some(window) = app.get_webview_window(&state.window.label) {
        let _ = window.eval("window.dispatchEvent(new Event('openaidr-background-status'))");
    }
}

pub(crate) fn open_window<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    let config = app
        .try_state::<Mutex<State<R>>>()
        .ok_or_else(|| std::io::Error::other("The desktop window is not initialized"))?
        .lock()
        .map_err(|_| std::io::Error::other("Could not read the window configuration"))?
        .window
        .clone();
    #[cfg(target_os = "macos")]
    { super::window::reopen_single_window(app, &config) }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let window = match app.get_webview_window(&config.label) {
            Some(window) => window,
            None => tauri::WebviewWindowBuilder::from_config(app, &config)?.build()?,
        };
        window.unminimize()?;
        window.show()?;
        window.set_focus()?;
        window.eval("window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:true}))")
    }
}

pub(crate) fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &tauri::WindowEvent) {
    if window.label() != "main" || !enabled(window.app_handle()) || !available(window.app_handle()) {
        return;
    }
    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
        // Keep the existing webview and its health state; never stop the sensor.
        if window.hide().is_ok() {
            api.prevent_close();
            #[cfg(target_os = "macos")]
            let _ = window
                .app_handle()
                .set_activation_policy(tauri::ActivationPolicy::Accessory);
            if let Some(webview) = window.app_handle().get_webview_window(window.label()) {
                let _ = webview.eval("window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:false}))");
            }
        }
    }
}
