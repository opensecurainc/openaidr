// Real AppKit launches, isolated from the installed app, sensor, and updater.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[path = "../src/platform/macos/single_instance.rs"]
mod single_instance;
#[cfg(target_os = "macos")]
#[path = "../src/platform/macos/window.rs"]
mod window;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[path = "../src/platform/menu_bar.rs"]
mod menu_bar;

#[cfg(target_os = "macos")]
fn main() {
    use std::{fs, process::Command};

    if let Some(mode) = std::env::args().nth(1) {
        if mode.starts_with("menu-bar") { check_menu_bar(mode == "menu-bar-restore"); }
        else { check_launch(&mode); }
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let contents = scratch.path().join("Activation.app/Contents");
    fs::create_dir_all(contents.join("MacOS")).unwrap();
    let executable = contents.join("MacOS/window-activation");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let mut plist = plist::Value::from_reader_xml(include_bytes!("../Info.plist").as_slice()).unwrap();
    let fields = plist.as_dictionary_mut().unwrap();
    let version = env!("OPENAIDR_VERSION");
    for (key, value) in [
        ("CFBundleIdentifier", format!("com.opensecura.activation-test.{}", std::process::id())),
        ("CFBundleExecutable", "window-activation".into()),
        ("CFBundleName", "OpenAIDR activation test".into()),
        ("CFBundlePackageType", "APPL".into()),
        ("CFBundleShortVersionString", version.split('+').next().unwrap().into()),
        ("CFBundleVersion", version.split('+').next().unwrap().into()),
        ("OpenAIDRVersion", version.into()),
    ] {
        fields.insert(key.into(), value.into());
    }
    plist.to_file_xml(contents.join("Info.plist")).unwrap();
    for mode in ["window", "--background-update", "--finish-update", "menu-bar", "menu-bar-restore"] {
        assert!(Command::new(&executable).arg(mode)
            .env("OPENAIDR_ACTIVATION_TEST_ID", format!("com.opensecura.menu-bar-test.{}", std::process::id()))
            .status().unwrap().success(), "{mode}");
    }
    println!("PASS: background launches stay out of the Dock; normal and reopened windows appear");
    println!("PASS: menu bar preference persists; status, close, reopen, stale status, and quit work natively");
}

#[cfg(target_os = "macos")]
fn check_launch(mode: &str) {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy as Policy};
    use tauri::Manager;

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(10));
        eprintln!("Native activation check timed out");
        std::process::exit(1);
    });
    let mtm = MainThreadMarker::new().unwrap();
    let native = NSApplication::sharedApplication(mtm);
    // The plist must hide the Dock icon before Tauri can apply its own policy.
    assert_eq!(native.activationPolicy(), Policy::Accessory);
    let headless = mode != "window";
    let expected = if headless { Policy::Accessory } else { Policy::Regular };
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().app.windows.clear();
    context.config_mut().identifier = format!("com.opensecura.activation-test.{}", std::process::id());
    let directory = single_instance::directory(&context.config().identifier).unwrap();
    let config = tauri::utils::config::WindowConfig {
        title: "OpenAIDR activation test".into(),
        width: 350.0,
        height: 160.0,
        ..Default::default()
    };
    let startup_window = config.clone();
    let app = tauri::Builder::default()
        .activate_ignoring_other_apps(!headless)
        .setup(move |app| {
            // setup is too late to prevent a temporary Regular launch policy.
            let native = NSApplication::sharedApplication(MainThreadMarker::new().unwrap());
            assert_eq!(native.activationPolicy(), expected);
            if !headless {
                tauri::WebviewWindowBuilder::from_config(app, &startup_window)?.build()?;
            }
            Ok(())
        })
        .build(context).unwrap();
    let mut opened = false;
    window::run(app, headless, move |app, event| match event {
        tauri::RunEvent::Ready => {
            assert_eq!(native.activationPolicy(), expected);
            if headless {
                assert!(app.webview_windows().is_empty());
                assert!(app.tray_by_id("openaidr-menu-bar").is_none());
                // Exercise the same path as an explicit user reopening a worker.
                window::reopen_single_window(app, &config).unwrap();
                window::reopen_single_window(app, &config).unwrap();
            }
            opened = true;
        }
        tauri::RunEvent::MainEventsCleared if opened => {
            assert_eq!(native.activationPolicy(), Policy::Regular);
            assert_eq!(app.webview_windows().len(), 1);
            assert!(app.get_webview_window("main").unwrap().is_visible().unwrap());
            opened = false;
            app.exit(0);
        }
        tauri::RunEvent::Exit => {
            if directory.exists() { std::fs::remove_dir_all(&directory).unwrap(); }
        }
        _ => {}
    });
}

#[cfg(target_os = "macos")]
fn check_menu_bar(restore: bool) {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy as Policy};
    use std::time::{Duration, Instant};
    use tauri::Manager;

    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(90));
        eprintln!("Native menu bar check timed out");
        std::process::exit(1);
    });
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().app.windows.clear();
    context.config_mut().identifier = std::env::var("OPENAIDR_ACTIVATION_TEST_ID").unwrap();
    let config = tauri::utils::config::WindowConfig {
        title: "OpenAIDR menu bar test".into(), width:350.0, height:160.0, ..Default::default()
    };
    let app = tauri::Builder::default()
        .on_window_event(menu_bar::on_window_event)
        .setup(move |app| {
            tauri::WebviewWindowBuilder::from_config(app, &config)?.build()?;
            menu_bar::initialize(app.handle(), &config)?;
            Ok(())
        }).build(context).unwrap();
    let native = NSApplication::sharedApplication(MainThreadMarker::new().unwrap());
    let mut phase = 0;
    let started = Instant::now();
    let mut quit_requested = false;
    window::run(app, false, move |app, event| match event {
        tauri::RunEvent::Ready => {
            assert_eq!(menu_bar::enabled(app), restore);
            menu_bar::settings(app, Some(true)).unwrap();
            menu_bar::health(app, "Sensor running".into(), false).unwrap();
            inspect_menu(app, "Sensor running", None);
            assert!(menu_bar::health(app, "invalid\nstatus".into(), false).is_err());
            app.get_webview_window("main").unwrap().close().unwrap();
            phase = 1;
        }
        tauri::RunEvent::MainEventsCleared if phase == 1 => {
            let window = app.get_webview_window("main").expect("Close must retain the window");
            if window.is_visible().unwrap() { return; }
            assert_eq!(native.activationPolicy(), Policy::Accessory);
            // A stalled or suspended webview must not leave a healthy status indefinitely.
            if !restore && started.elapsed() < Duration::from_secs(62) { return; }
            inspect_menu(app, if restore { "Sensor running" } else { "Status unavailable" }, Some("menu-bar-open"));
            phase = 2;
        }
        tauri::RunEvent::MainEventsCleared if phase == 2 => {
            if !app.get_webview_window("main").unwrap().is_visible().unwrap() { return; }
            assert_eq!(native.activationPolicy(), Policy::Regular);
            menu_bar::health(app, "Connection lost".into(), true).unwrap();
            inspect_menu(app, "Connection lost", None);
            if restore {
                let path = app.path().app_config_dir().unwrap().join("desktop-preferences.json");
                std::fs::remove_file(&path).unwrap();
                std::fs::create_dir(&path).unwrap();
                assert!(menu_bar::settings(app, Some(false)).is_err());
                assert!(menu_bar::enabled(app));
                std::fs::remove_dir(&path).unwrap();
                menu_bar::settings(app, Some(false)).unwrap();
                assert!(app.tray_by_id("openaidr-menu-bar").is_none());
                app.get_webview_window("main").unwrap().close().unwrap();
            } else {
                inspect_menu(app, "Connection lost", Some("menu-bar-quit"));
            }
            quit_requested = true;
            phase = 3;
        }
        tauri::RunEvent::Exit => {
            assert!(quit_requested, "Closing a window with the menu enabled must not quit");
            if restore {
                std::fs::remove_dir_all(app.path().app_config_dir().unwrap()).unwrap();
            }
            if let Ok(directory) = single_instance::directory(&app.config().identifier) {
                let _ = std::fs::remove_dir_all(directory);
            }
        }
        _ => {}
    });
}

#[cfg(target_os = "macos")]
fn inspect_menu(app: &tauri::AppHandle, expected: &str, activate: Option<&str>) {
    let expected = expected.to_owned();
    app.tray_by_id("openaidr-menu-bar").unwrap().with_inner_tray_icon(move |tray| {
        let item = tray.ns_status_item().unwrap();
        let button = item.button(objc2::MainThreadMarker::new().unwrap()).unwrap();
        assert_eq!(button.toolTip().unwrap().to_string(), format!("OpenAIDR: {expected}"));
        assert_eq!(button.title().to_string(), "");
        let image = button.image().unwrap();
        assert!(image.isTemplate(), "macOS must provide the menu bar foreground color");
        assert_eq!((image.size().width, image.size().height), (18.0, 18.0));
        let bitmap = objc2_app_kit::NSBitmapImageRep::imageRepWithData(
            &image.TIFFRepresentation().unwrap(),
        ).unwrap();
        assert_eq!((bitmap.pixelsWide(), bitmap.pixelsHigh()), (36, 36));
        assert_eq!(bitmap.samplesPerPixel(), 4);
        assert_eq!(bitmap.bitsPerSample(), 8);
        // Main mark, former red band, former navy tile, and transparent corner.
        for (x, y, alpha) in [(18, 8, 242), (15, 12, 140), (4, 18, 38), (0, 0, 0)] {
            let mut pixel = [0; 4];
            unsafe { bitmap.getPixel_atX_y(std::ptr::NonNull::new(pixel.as_mut_ptr()).unwrap(), x, y); }
            assert_eq!(pixel[3], alpha, "menu bar opacity at ({x}, {y})");
        }
        if let Some(path) = std::env::var_os("OPENAIDR_MENU_BAR_SCREENSHOT") {
            let bounds = button.bounds();
            let capture = button.bitmapImageRepForCachingDisplayInRect(bounds).unwrap();
            button.cacheDisplayInRect_toBitmapImageRep(bounds, &capture);
            let png = unsafe { capture.representationUsingType_properties(
                objc2_app_kit::NSBitmapImageFileType::PNG, &objc2_foundation::NSDictionary::new(),
            ) }.unwrap();
            std::fs::write(path, png.to_vec()).unwrap();
        }
    }).unwrap();
    if let Some(id) = activate { menu_bar::on_menu_event(app, tauri::menu::MenuEvent {id:id.into()}); }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
