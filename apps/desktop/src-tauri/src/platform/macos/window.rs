use super::single_instance;
use std::{
    io::{Read, Write},
    thread,
    time::Duration,
};
use tauri::Manager;

pub(crate) fn run<R: tauri::Runtime>(
    mut app: tauri::App<R>,
    headless: bool,
    on_event: impl FnMut(&tauri::AppHandle<R>, tauri::RunEvent) + 'static,
) {
    // setup runs after AppKit finishes launching. Set the initial policy before
    // the event loop so Tauri never promotes an updater to a Dock-visible app.
    app.set_activation_policy(if headless {
        tauri::ActivationPolicy::Accessory
    } else {
        tauri::ActivationPolicy::Regular
    });
    app.run(on_event);
}

fn reopen_window<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    config: &tauri::utils::config::WindowConfig,
) -> tauri::Result<()> {
    super::menu_bar::initialize(app, config)?;
    let window = match app.get_webview_window(&config.label) {
        Some(window) => window,
        None => tauri::WebviewWindowBuilder::from_config(app, config)?.build()?,
    };
    app.set_activation_policy(tauri::ActivationPolicy::Regular)?;
    app.show()?;
    window.unminimize()?;
    window.show()?;
    window.set_focus()?;
    window.eval("window.dispatchEvent(new CustomEvent('openaidr-window-visibility', {detail:true}))")
}

pub(crate) fn listen_for_activation<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    instance: single_instance::Instance,
    config: Option<tauri::utils::config::WindowConfig>,
) -> std::io::Result<()> {
    let socket = instance.socket.try_clone()?;
    app.manage(instance);
    let app = app.clone();
    thread::Builder::new()
        .name("desktop-activation".into())
        .spawn(move || loop {
            match socket.accept() {
                Ok((mut stream, _)) => {
                    if stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .is_err()
                        || stream
                            .set_write_timeout(Some(Duration::from_millis(100)))
                            .is_err()
                    {
                        continue;
                    }
                    let mut message = [0];
                    if stream.read_exact(&mut message).is_err() || message != [1] {
                        continue;
                    }
                    let handle = app.clone();
                    let config = config.clone();
                    let _ = app.run_on_main_thread(move || {
                        if handle.state::<single_instance::Instance>().is_restarting() {
                            return;
                        }
                        if let Some(config) = config {
                            if reopen_window(&handle, &config).is_ok() {
                                let _ = stream.write_all(&[1]);
                            }
                        }
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        })?;
    Ok(())
}

pub(crate) fn reopen_single_window<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    config: &tauri::utils::config::WindowConfig,
) -> tauri::Result<()> {
    if app.try_state::<single_instance::Instance>().is_none() {
        let Some(instance) = single_instance::Instance::acquire(&single_instance::directory(
            &app.config().identifier,
        )?)?
        else {
            return Ok(());
        };
        listen_for_activation(app, instance, Some(config.clone()))?;
    }
    reopen_window(app, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reopening_a_background_update_creates_one_foreground_window() {
        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        context.config_mut().app.windows.clear();
        context.config_mut().identifier = format!("openaidr.reopen.test.{}", std::process::id());
        let directory = single_instance::directory(&context.config().identifier).unwrap();
        let app = tauri::test::mock_builder().build(context).unwrap();
        assert!(app.webview_windows().is_empty());
        let config = tauri::utils::config::WindowConfig::default();

        let owner = single_instance::Instance::acquire(&directory)
            .unwrap()
            .unwrap();
        let socket = owner.socket.try_clone().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = socket.accept().unwrap();
            let mut request = [0];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [1]);
            stream.write_all(&[1]).unwrap();
            send.send(()).unwrap();
        });
        reopen_single_window(app.handle(), &config).unwrap();
        receive.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(app.webview_windows().is_empty());
        assert!(app.try_state::<single_instance::Instance>().is_none());
        drop(owner);

        reopen_single_window(app.handle(), &config).unwrap();
        reopen_single_window(app.handle(), &config).unwrap();
        assert_eq!(app.webview_windows().len(), 1);
        assert!(app
            .get_webview_window("main")
            .unwrap()
            .is_visible()
            .unwrap());
        assert!(app.try_state::<single_instance::Instance>().is_some());
        fs::remove_dir_all(directory).unwrap();
    }
}
