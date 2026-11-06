use gio::{prelude::*, BusType, DBusProxy, DBusProxyFlags};
use std::sync::Mutex;
use tauri::{Manager, Runtime};

#[derive(Default)]
struct Host(Mutex<Option<DBusProxy>>);

pub(super) fn available<R: Runtime>(app: &tauri::AppHandle<R>) -> bool {
    app.try_state::<Host>()
        .and_then(|host| host.0.lock().ok().and_then(|proxy| proxy.as_ref().map(|proxy| {
            !proxy.connection().is_closed() && proxy.name_owner().is_some()
                && proxy.cached_property("IsStatusNotifierHostRegistered")
                    .and_then(|value| value.get::<bool>()).unwrap_or(false)
        })))
        .unwrap_or(false)
}

fn changed<R: Runtime>(app: &tauri::AppHandle<R>) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let available = available(&handle);
        if let Some(window) = handle.get_webview_window("main") {
            // A disappeared panel or bus must never strand the hidden window.
            if !available && super::enabled(&handle) && !window.is_visible().unwrap_or(true) {
                let _ = super::open_window(&handle);
            }
            let _ = window.eval(&format!("window.dispatchEvent(new CustomEvent('openaidr-tray-availability', {{detail:{available}}}))"));
        }
    });
}

pub(super) fn initialize<R: Runtime>(app: &tauri::AppHandle<R>) {
    app.manage(Host::default());
    let app = app.clone();
    // Query and subscribe asynchronously; an absent or stalled session bus must
    // not block startup or close. Until discovery completes, close exits normally.
    DBusProxy::for_bus(BusType::Session, DBusProxyFlags::DO_NOT_AUTO_START, None,
        "org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher",
        None::<&gio::Cancellable>, move |result| {
            let Ok(proxy) = result else { changed(&app); return; };
            let handle = app.clone();
            proxy.connect_g_name_owner_notify(move |_| changed(&handle));
            let handle = app.clone();
            proxy.connect("g-properties-changed", false, move |_| { changed(&handle); None });
            let handle = app.clone();
            proxy.connect_g_signal(move |proxy, _, signal, _| {
                let registered = match signal {
                    "StatusNotifierHostRegistered" => true,
                    "StatusNotifierHostUnregistered" => false,
                    _ => return,
                };
                proxy.set_cached_property("IsStatusNotifierHostRegistered", Some(&registered.to_variant()));
                changed(&handle);
            });
            let handle = app.clone();
            proxy.connection().set_exit_on_close(false);
            proxy.connection().connect_closed(move |_, _, _| changed(&handle));
            *app.state::<Host>().0.lock().unwrap() = Some(proxy);
            changed(&app);
        });
}
