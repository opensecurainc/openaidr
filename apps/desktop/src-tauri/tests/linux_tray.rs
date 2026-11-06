// Real GTK windows and AppIndicator registration against an isolated D-Bus host.
// Run with dbus-run-session and Xvfb; never uses the user's desktop or sensor.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/platform/menu_bar.rs"]
mod menu_bar;

#[cfg(target_os = "linux")]
fn main() {
    use std::process::Command;
    if let Some(mode) = std::env::args().nth(1) { check_tray(&mode); return; }
    let id = format!("com.opensecura.linux-tray-test.{}", std::process::id());
    for mode in ["host-loss", "bus-loss", "no-host", "no-bus"] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.arg(mode).env("OPENAIDR_TRAY_TEST_ID", &id);
        if mode == "no-bus" { command.env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/openaidr-test-bus"); }
        assert!(command.status().unwrap().success(), "{mode}");
    }
    println!("PASS: Linux tray registers, closes and reopens; host and bus loss restore the window; unavailable hosts retain normal close");
}

#[cfg(target_os = "linux")]
fn check_tray(mode: &str) {
    use gio::glib::{self, variant::ToVariant};
    use std::{sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}, time::{Duration, Instant}};
    use tauri::Manager;

    const WATCHER: &str = "org.kde.StatusNotifierWatcher";
    const PATH: &str = "/StatusNotifierWatcher";
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(30));
        eprintln!("Native Linux tray check timed out");
        std::process::exit(1);
    });
    let has_host = matches!(mode, "host-loss" | "bus-loss");
    let lose_bus = mode == "bus-loss";
    let cleanup = mode == "no-bus";
    let registrations = Arc::new(AtomicUsize::new(0));
    let mut owner = None;
    let mut connection = None;
    if has_host {
        // Keep the fake desktop host on a separate connection from the app.
        let bus = gio::DBusConnection::for_address_sync(&std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap(),
            gio::DBusConnectionFlags::AUTHENTICATION_CLIENT | gio::DBusConnectionFlags::MESSAGE_BUS_CONNECTION,
            None::<&gio::DBusAuthObserver>, None::<&gio::Cancellable>).unwrap();
        bus.set_exit_on_close(false);
        let node = gio::DBusNodeInfo::for_xml(r#"<node><interface name="org.kde.StatusNotifierWatcher">
          <method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
          <property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
          <property name="ProtocolVersion" type="i" access="read"/>
          <property name="RegisteredStatusNotifierItems" type="as" access="read"/>
          <signal name="StatusNotifierHostRegistered"/>
          <signal name="StatusNotifierHostUnregistered"/>
        </interface></node>"#).unwrap();
        let count = registrations.clone();
        bus.register_object(PATH, &node.lookup_interface(WATCHER).unwrap(),
            move |_, _, _, _, method, _, invocation| {
                assert_eq!(method, "RegisterStatusNotifierItem");
                count.fetch_add(1, Ordering::SeqCst);
                invocation.return_value(None);
            },
            |_, _, _, _, property| match property {
                "IsStatusNotifierHostRegistered" => true.to_variant(),
                "ProtocolVersion" => 0i32.to_variant(),
                "RegisteredStatusNotifierItems" => Vec::<String>::new().to_variant(),
                _ => panic!("Unexpected property: {property}"),
            }, |_, _, _, _, _, _| false).unwrap();
        owner = Some(gio::bus_own_name_on_connection(&bus, WATCHER, gio::BusNameOwnerFlags::NONE, |_, _| {}, |_, _| {}));
        connection = Some(bus);
    }
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().identifier = std::env::var("OPENAIDR_TRAY_TEST_ID").unwrap();
    context.config_mut().app.windows.clear();
    let config = tauri::utils::config::WindowConfig {
        title:"OpenAIDR Linux tray test".into(), width:350.0, height:160.0, ..Default::default()
    };
    let app = tauri::Builder::default().on_window_event(menu_bar::on_window_event)
        .setup(move |app| {
            tauri::WebviewWindowBuilder::from_config(app, &config)?.build()?;
            menu_bar::initialize(app.handle(), &config)?;
            Ok(())
        }).build(context).unwrap();
    let quit = Arc::new(AtomicBool::new(false));
    let quitting = quit.clone();
    let handle = app.handle().clone();
    let started = Instant::now();
    let mut phase = 0;
    glib::timeout_add_local(Duration::from_millis(20), move || {
        let window = handle.get_webview_window("main").unwrap();
        if !has_host {
            if started.elapsed() < Duration::from_millis(300) { return glib::ControlFlow::Continue; }
            assert!(menu_bar::enabled(&handle), "Saved preference must survive an absent host");
            assert!(!menu_bar::available(&handle));
            quitting.store(true, Ordering::SeqCst);
            window.close().unwrap();
            return glib::ControlFlow::Break;
        }
        match phase {
            0 if menu_bar::available(&handle) => {
                menu_bar::settings(&handle, Some(true)).unwrap();
                menu_bar::health(&handle, "Sensor running".into(), false).unwrap();
                phase = 1;
            }
            1 if registrations.load(Ordering::SeqCst) > 0 => {
                window.close().unwrap();
                phase = 2;
            }
            2 if !window.is_visible().unwrap() => {
                connection.as_ref().unwrap().emit_signal(None, PATH, WATCHER, "StatusNotifierHostUnregistered", None).unwrap();
                phase = 3;
            }
            3 if !menu_bar::available(&handle) && window.is_visible().unwrap() => {
                let bus = connection.as_ref().unwrap();
                if lose_bus {
                    bus.emit_signal(None, PATH, WATCHER, "StatusNotifierHostRegistered", None).unwrap();
                } else {
                    let changed = std::collections::HashMap::from([("IsStatusNotifierHostRegistered", true.to_variant())]);
                    bus.emit_signal(None, PATH, "org.freedesktop.DBus.Properties", "PropertiesChanged",
                        Some(&(WATCHER, changed, Vec::<String>::new()).to_variant())).unwrap();
                }
                phase = 4;
            }
            4 if menu_bar::available(&handle) => {
                window.close().unwrap();
                phase = 5;
            }
            5 if !window.is_visible().unwrap() => {
                if lose_bus {
                    gio::bus_get_sync(gio::BusType::Session, None::<&gio::Cancellable>).unwrap()
                        .close_sync(None::<&gio::Cancellable>).unwrap();
                }
                else { gio::bus_unown_name(owner.take().unwrap()); }
                phase = 6;
            }
            6 if !menu_bar::available(&handle) && window.is_visible().unwrap() => {
                assert_eq!(handle.webview_windows().len(), 1);
                quitting.store(true, Ordering::SeqCst);
                menu_bar::on_menu_event(&handle, tauri::menu::MenuEvent {id:"menu-bar-quit".into()});
                return glib::ControlFlow::Break;
            }
            _ => {}
        }
        glib::ControlFlow::Continue
    });
    app.run(move |app, event| if matches!(event, tauri::RunEvent::Exit) {
        assert!(quit.load(Ordering::SeqCst), "Close with an available tray must retain the app");
        if cleanup { std::fs::remove_dir_all(app.path().app_config_dir().unwrap()).unwrap(); }
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {}
