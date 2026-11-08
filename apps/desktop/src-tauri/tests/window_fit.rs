// A real AppKit/WKWebView boundary check. No sensor or updater is initialized.
// Run in a macOS desktop session (WindowServer required). A temporary window
// uses the production configuration; the event loop must run on the main thread.
#[cfg(target_os = "macos")]
#[path = "../src/window_fit.rs"]
mod window_fit;

#[cfg(target_os = "macos")]
use serde_json::{json, Value};
#[cfg(target_os = "macos")]
use std::sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc};

#[cfg(target_os = "macos")]
#[derive(Default)]
struct SensorFixture {
    released: AtomicBool,
    reads: AtomicUsize,
}

// Only the user's environment is simulated. The frontend, IPC, WebKit, and
// native fit_window command are the production implementations.
#[cfg(target_os = "macos")]
#[tauri::command]
async fn sensor_request(app: tauri::AppHandle, request: Value) -> Result<Value, String> {
    use tauri::Manager;
    match request["action"].as_str().unwrap_or("") {
        "status" => {
            let fixture = app.state::<Arc<SensorFixture>>().inner().clone();
            fixture.reads.fetch_add(1, Ordering::SeqCst);
            while !fixture.released.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok(json!({"enrolled":false,"service":"not installed","running":false,"telemetry":{}}))
        }
        "desktop.update.status" => Ok(Value::Null),
        "desktop.capabilities" => Ok(json!({"removal_supported":true})),
        "simulation.status" => Ok(json!({"enabled":false})),
        "enrollment.preview.invalidate" => Ok(json!({"generation":1})),
        "alerts.focus" => Ok(json!({})),
        action => Err(format!("Unexpected fixture request: {action}")),
    }
}

#[cfg(target_os = "macos")]
#[tauri::command]
fn menu_bar_settings() -> Value { json!({"supported":true,"enabled":false}) }

#[cfg(target_os = "macos")]
#[tauri::command]
fn menu_bar_health() {}

#[cfg(target_os = "macos")]
fn evaluate(webview: &tauri::WebviewWindow, script: &str) -> Value {
    let (send, receive) = std::sync::mpsc::channel();
    webview.eval_with_callback(script, move |value| { let _ = send.send(value); }).unwrap();
    serde_json::from_str(&receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap()).unwrap()
}

#[cfg(target_os = "macos")]
fn until(webview: &tauri::WebviewWindow, script: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while evaluate(webview, script) != json!(true) {
        assert!(std::time::Instant::now() < deadline, "Timed out: {script}");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(target_os = "macos")]
fn viewport_height(webview: &tauri::WebviewWindow) -> f64 {
    evaluate(webview, "window.innerHeight").as_f64().unwrap()
}

#[cfg(target_os = "macos")]
fn evidence(webview: &tauri::WebviewWindow, scenario: &str, ocr: &std::path::Path) {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../build/e2e-startup");
    std::fs::create_dir_all(&directory).unwrap();
    let mut metrics = evaluate(webview, include_str!("../../e2e/startup-layout.js"));
    let build: Value = serde_json::from_str(env!("OPENAIDR_BUILD_INFO")).unwrap();
    let edition = build["desktop_edition"].as_str().unwrap_or("standard");
    assert_eq!(metrics["edition"], edition, "Startup must test the compiled desktop edition");
    println!("{scenario}: {metrics}");
    std::fs::write(directory.join(format!("{scenario}.json")), serde_json::to_vec_pretty(&metrics).unwrap()).unwrap();
    // Capture this exact window without activation, reopen, scrolling, or resize.
    let (send, receive) = std::sync::mpsc::channel();
    let handle = webview.clone();
    webview.run_on_main_thread(move || {
        let pointer = handle.ns_window().unwrap();
        let native = unsafe { &*pointer.cast::<objc2_app_kit::NSWindow>() };
        let _ = send.send(native.windowNumber());
    }).unwrap();
    let id = receive.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    let image = directory.join(format!("{scenario}.png"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let result = std::process::Command::new("/usr/sbin/screencapture")
            .args(["-x", "-o", "-l", &id.to_string()]).arg(&image).status().unwrap();
        assert!(result.success(), "Could not capture the native startup window");
        // Preserve a failing layout immediately. A successful resize can precede
        // WebKit's painted frame; wait only by reading the captured pixels.
        if metrics["fits"] != json!(true) { break; }
        let output = std::process::Command::new(ocr).arg("--text").arg(&image).output().unwrap();
        assert!(output.status.success(), "Could not read startup screenshot: {}", String::from_utf8_lossy(&output.stderr));
        let text = String::from_utf8(output.stdout).unwrap().split_whitespace().collect::<Vec<_>>().join(" ");
        let labels = if edition == "enterprise" {
            ["Connect your organization", "Enrollment link", "Settings", "Check updates"]
        } else {
            ["Continue without signing in", "Connect organization", "Settings", "Check updates"]
        };
        let painted = labels.iter().all(|label| text.contains(label));
        metrics["screenshot_text"] = json!(text);
        std::fs::write(directory.join(format!("{scenario}.json")), serde_json::to_vec_pretty(&metrics).unwrap()).unwrap();
        if painted { break; }
        assert!(std::time::Instant::now() < deadline, "The resized window has not painted its setup choices and footer controls: {metrics}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn main() {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    use tauri::Manager;

    let scenario = std::env::args().find(|arg| arg.starts_with("--startup-"));
    let Some(scenario) = scenario else {
        let temporary = tempfile::tempdir().unwrap();
        let ocr = temporary.path().join("e2e-window");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/e2e_window.swift");
        assert!(std::process::Command::new("/usr/bin/xcrun")
            .arg("swiftc").arg(source).arg("-o").arg(&ocr).status().unwrap().success());
        let mut passed = true;
        for scenario in ["visible", "hidden"] {
            passed &= std::process::Command::new(std::env::current_exe().unwrap())
                .arg(format!("--startup-{scenario}")).arg(&ocr).status().unwrap().success();
        }
        std::process::exit(if passed { 0 } else { 1 });
    };
    let scenario = scenario.strip_prefix("--startup-").unwrap().to_owned();
    let hidden = scenario == "hidden";
    let ocr = std::path::PathBuf::from(std::env::args().nth(2).expect("Missing screenshot OCR helper"));
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../dist");
    assert!(assets.join("index.html").is_file(), "Build the desktop frontend before window_fit");
    let fixture = Arc::new(SensorFixture::default());
    let config: tauri::Config = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let mut window_config = config.app.windows[0].clone();
    window_config.url = tauri::WebviewUrl::CustomProtocol("window-test://localhost".parse().unwrap());
    window_config.visible = !hidden;
    window_config.title = "OpenAIDR".into();
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context.config_mut().version = Some(env!("OPENAIDR_VERSION").into());
    context.config_mut().identifier = format!("com.opensecura.openaidr.window-test.{}", std::process::id());
    let (loaded, load_events) = std::sync::mpsc::channel();
    let load_events = std::sync::Mutex::new(Some(load_events));
    let mut app = tauri::Builder::default()
        .activate_ignoring_other_apps(true)
        .manage(fixture.clone())
        .invoke_handler(tauri::generate_handler![sensor_request, menu_bar_settings, menu_bar_health, window_fit::fit_window])
        .register_uri_scheme_protocol("window-test", move |_, request| {
            let file = request.uri().path().trim_start_matches('/');
            let file = if file.is_empty() { "index.html" } else { file };
            let mime = match std::path::Path::new(file).extension().and_then(|value| value.to_str()) {
                Some("js") => "text/javascript", Some("css") => "text/css",
                Some("svg") => "image/svg+xml", Some("png") => "image/png",
                Some("woff2") => "font/woff2", _ => "text/html",
            };
            let bytes = std::fs::read(assets.join(file));
            tauri::http::Response::builder().status(if bytes.is_ok() { 200 } else { 404 })
                .header("Content-Type", mime).body(bytes.unwrap_or_default()).unwrap()
        })
        .on_page_load(move |_, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                let _ = loaded.send(());
            }
        })
        .setup(move |app| {
            tauri::WebviewWindowBuilder::from_config(app, &window_config)?
                .initialization_script(r#"
                  window.__startupEvents = [{event:'initial', hidden:document.hidden, height:innerHeight}];
                  window.__startupErrors = [];
                  for (const event of ['focus', 'blur', 'visibilitychange'])
                    addEventListener(event, () => window.__startupEvents.push({event, hidden:document.hidden, height:innerHeight}));
                  addEventListener('error', event => window.__startupErrors.push(event.message));
                  addEventListener('unhandledrejection', event => window.__startupErrors.push(String(event.reason)));
                  addEventListener('DOMContentLoaded', () => new ResizeObserver(() => {
                    window.__startupObserved = Math.ceil(document.querySelector('main').getBoundingClientRect().height);
                  }).observe(document.querySelector('main')));
                "#).build()?;
            Ok(())
        })
        .build(context)
        .unwrap();
    app.set_activation_policy(tauri::ActivationPolicy::Regular);
    app.run(move |app, event| {
        if !matches!(event, tauri::RunEvent::Ready) {
            return;
        }
        let app = app.clone();
        let load_events = load_events.lock().unwrap().take().unwrap();
        let fixture = fixture.clone();
        let scenario = scenario.clone();
        let ocr = ocr.clone();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                load_events.recv_timeout(Duration::from_secs(10)).unwrap();
                let webview = app.get_webview_window("main").unwrap();
                let startup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    until(&webview, "document.readyState === 'complete' && document.fonts.status === 'loaded' && [...document.images].every(image => image.complete && image.naturalWidth > 0)");
                    until(&webview, if hidden { "document.hidden" } else { "!document.hidden" });
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while fixture.reads.load(Ordering::SeqCst) == 0 {
                        assert!(Instant::now() < deadline, "Initial status must be pending");
                        thread::sleep(Duration::from_millis(20));
                    }
                    fixture.released.store(true, Ordering::SeqCst);
                    until(&webview, "document.getElementById('health-title')?.textContent === 'Welcome to OpenAIDR' && window.__startupObserved === Math.ceil(document.querySelector('main').getBoundingClientRect().height)");
                    if hidden {
                        assert_eq!(evaluate(&webview, "document.hidden"), json!(true));
                        // Ordinary first visibility, without the app's reopen event.
                        webview.show().unwrap();
                        webview.set_focus().unwrap();
                    }
                    until(&webview, &format!("({}).fits", include_str!("../../e2e/startup-layout.js")));
                }));
                // Save the failing state before any geometry checks can repair it.
                evidence(&webview, &scenario, &ocr);
                if let Err(error) = startup { std::panic::resume_unwind(error); }
                if hidden { return; }
                let window = webview.as_ref().window();
                let scale = window.scale_factor().unwrap();
                let area = window.current_monitor().unwrap().unwrap().work_area().clone();
                let chrome = f64::from(window.outer_size().unwrap().height) / scale
                    - viewport_height(&webview);
                for height in [300.0_f64, 500.0, 220.0, 900.0] {
                    if height == 500.0 {
                        // Force the growing window to move up from the bottom edge.
                        window
                            .set_position(tauri::PhysicalPosition::new(
                                area.position.x,
                                area.position.y + area.size.height as i32 - 100,
                            ))
                            .unwrap();
                    }
                    let expected = height
                        .min(720.0)
                        .min(f64::from(area.size.height) / scale - chrome);
                    window_fit::fit_window(window.clone(), height).unwrap();
                    let deadline = Instant::now() + Duration::from_secs(3);
                    loop {
                        let actual = viewport_height(&webview);
                        if (actual - expected).abs() <= 1.0 {
                            break;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "requested viewport {height}, expected {expected}, actual {actual}"
                        );
                        thread::sleep(Duration::from_millis(20));
                    }
                    let area = window.current_monitor().unwrap().unwrap().work_area().clone();
                    let top = window.outer_position().unwrap().y;
                    let bottom = i64::from(top) + i64::from(window.outer_size().unwrap().height);
                    assert!(top >= area.position.y);
                    assert!(bottom <= i64::from(area.position.y) + i64::from(area.size.height));
                }
            }));
            if result.is_ok() {
                println!("PASS: {scenario} startup fits before interaction; native sizing stays within the work area");
            }
            app.exit(if result.is_ok() { 0 } else { 1 });
        });
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {}
