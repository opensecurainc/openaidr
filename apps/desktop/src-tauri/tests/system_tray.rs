// Real Windows windows and notification-area icons, without a sensor or updater.
#[cfg(windows)]
#[allow(dead_code)]
#[path = "../src/platform/menu_bar.rs"]
mod menu_bar;

#[cfg(windows)]
fn main() {
    use std::process::Command;
    if let Some(mode) = std::env::args().nth(1) {
        check_tray(&mode);
        return;
    }
    let id = format!("com.opensecura.tray-test.{}", std::process::id());
    for mode in ["enable", "restore", "disabled"] {
        println!("Checking Windows tray mode: {mode}");
        assert!(Command::new(std::env::current_exe().unwrap()).arg(mode)
            .env("OPENAIDR_TRAY_TEST_ID", &id).status().unwrap().success(), "{mode}");
    }
    println!("PASS: Windows tray preference persists, close hides, Open restores, Quit exits, and disabling restores normal close");
}

#[cfg(windows)]
fn check_tray(mode: &str) {
    use std::{fs, time::Duration};
    use tauri::Manager;
    let (ready, startup) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Cold WebView2 startup must not consume the tray interaction budget.
        if let Err(error) = startup.recv_timeout(Duration::from_secs(90)) {
            eprintln!("Native Windows tray startup failed: {error}");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_secs(30));
        eprintln!("Native Windows tray interactions timed out");
        std::process::exit(1);
    });
    let restore = mode == "restore";
    let disabled = mode == "disabled";
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().identifier = std::env::var("OPENAIDR_TRAY_TEST_ID").unwrap();
    context.config_mut().app.windows.clear();
    let config = tauri::utils::config::WindowConfig {
        title:"OpenAIDR tray test".into(), width:350.0, height:160.0, ..Default::default()
    };
    println!("Building native tray application");
    let app = tauri::Builder::default()
        .on_window_event(menu_bar::on_window_event)
        .setup(move |app| {
            println!("Creating native WebView window");
            tauri::WebviewWindowBuilder::from_config(app, &config)?.build()?;
            println!("Initializing tray preferences");
            menu_bar::initialize(app.handle(), &config)?;
            println!("Native tray setup complete");
            Ok(())
        }).build(context).unwrap();
    let handle = app.handle().clone();
    // MainEventsCleared is not a timer: a hidden window may leave the Windows
    // event loop idle. Wake it so each asynchronous transition is observed.
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(20));
        if handle.run_on_main_thread(|| {}).is_err() { break; }
    });
    let mut phase = 0;
    let mut quit_requested = false;
    println!("Starting native tray event loop");
    app.run(move |app, event| match event {
        tauri::RunEvent::Ready => {
            ready.send(()).unwrap();
            println!("Window ready; checking the preference and requesting close");
            assert_eq!(menu_bar::enabled(app), restore);
            assert_eq!(menu_bar::settings(app, None).unwrap()["label"], "Show in system tray");
            if disabled {
                assert!(app.tray_by_id("openaidr-menu-bar").is_none());
                quit_requested = true;
            } else {
                menu_bar::settings(app, Some(true)).unwrap();
                assert!(app.tray_by_id("openaidr-menu-bar").is_some());
                menu_bar::health(app, "Sensor running".into(), false).unwrap();
                menu_bar::health(app, "Connection lost".into(), true).unwrap();
                assert!(menu_bar::health(app, "invalid\nstatus".into(), true).is_err());
            }
            app.get_webview_window("main").unwrap().close().unwrap();
            phase = 1;
        }
        tauri::RunEvent::MainEventsCleared if phase == 1 && !disabled => {
            let window = app.get_webview_window("main").expect("Closing must retain the window");
            if window.is_visible().unwrap() { return; }
            println!("Closed window is hidden; requesting Open");
            menu_bar::on_menu_event(app, tauri::menu::MenuEvent {id:"menu-bar-open".into()});
            phase = 2;
        }
        tauri::RunEvent::MainEventsCleared if phase == 2 => {
            let window = app.get_webview_window("main").unwrap();
            if !window.is_visible().unwrap() { return; }
            println!("Window reopened; checking Quit or disabled close");
            assert!(!window.is_minimized().unwrap());
            assert_eq!(app.webview_windows().len(), 1);
            if restore {
                let path = app.path().app_config_dir().unwrap().join("desktop-preferences.json");
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
                assert!(menu_bar::settings(app, Some(false)).is_err());
                assert!(menu_bar::enabled(app), "Failed save must retain the icon and close behavior");
                fs::remove_dir(&path).unwrap();
                menu_bar::settings(app, Some(false)).unwrap();
                assert!(app.tray_by_id("openaidr-menu-bar").is_none());
                window.close().unwrap();
            } else {
                menu_bar::on_menu_event(app, tauri::menu::MenuEvent {id:"menu-bar-quit".into()});
            }
            quit_requested = true;
            phase = 3;
        }
        tauri::RunEvent::Exit => {
            assert!(quit_requested, "Closing with the tray enabled must not quit");
            if disabled { fs::remove_dir_all(app.path().app_config_dir().unwrap()).unwrap(); }
        }
        _ => {}
    });
}

#[cfg(not(windows))]
fn main() {}
