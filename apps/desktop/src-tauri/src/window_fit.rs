// The window keeps a fixed width and follows the height of the rendered content.
const WINDOW_WIDTH: f64 = 580.0;
pub(super) const WINDOW_HEIGHT_RANGE: (f64, f64) = (160.0, 720.0);

pub(super) fn window_height(height: f64) -> Option<f64> {
    height.is_finite().then(|| {
        height
            .ceil()
            .clamp(WINDOW_HEIGHT_RANGE.0, WINDOW_HEIGHT_RANGE.1)
    })
}

/// Keeps a window inside the vertical work area `area_top..area_bottom`, in
/// physical pixels: the inner height shrinks to what fits, and the outer top
/// edge moves up when the bottom edge would leave the area.
pub(super) fn place_in_work_area(
    top: f64,
    chrome: f64,
    inner: f64,
    area_top: f64,
    area_bottom: f64,
) -> (f64, f64) {
    let inner = inner.min((area_bottom - area_top - chrome).max(0.0));
    (inner, top.min(area_bottom - chrome - inner).max(area_top))
}

// Tauri's Visible titlebar uses NSFullSizeContentViewWindowMask. Its reported
// inner_size includes the titlebar, but WebKit's viewport excludes it.
#[cfg(target_os = "macos")]
fn titlebar_height(window: &tauri::Window) -> Result<f64, String> {
    let (send, receive) = std::sync::mpsc::channel();
    let handle = window.clone();
    window
        .run_on_main_thread(move || {
            let result = handle
                .ns_window()
                .map(|pointer| {
                    // Tauri owns the NSWindow; AppKit access stays on the main thread.
                    let native = unsafe { &*pointer.cast::<objc2_app_kit::NSWindow>() };
                    (native.frame().size.height - native.contentLayoutRect().size.height).max(0.0)
                })
                .map_err(|_| "Cannot read the window titlebar.".to_owned());
            let _ = send.send(result);
        })
        .map_err(|_| "Cannot read the window titlebar.")?;
    receive.recv().map_err(|_| "Cannot read the window titlebar.")?
}

#[tauri::command]
pub fn fit_window(window: tauri::Window, height: f64) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Unknown application window.".into());
    }
    let mut height = window_height(height).ok_or("Invalid window height.")?;
    #[cfg(target_os = "macos")]
    let titlebar = titlebar_height(&window)?;
    // Keep the outer window within the work area. The page can scroll when the
    // content is taller than the available viewport.
    if let (Ok(scale), Ok(Some(monitor)), Ok(position), Ok(_outer), Ok(_inner)) = (
        window.scale_factor(),
        window.current_monitor(),
        window.outer_position(),
        window.outer_size(),
        window.inner_size(),
    ) {
        #[cfg(target_os = "macos")]
        let chrome = titlebar * scale;
        #[cfg(not(target_os = "macos"))]
        let chrome = f64::from(_outer.height.saturating_sub(_inner.height));
        let area = monitor.work_area();
        let area_top = f64::from(area.position.y);
        let (fitted, top) = place_in_work_area(
            f64::from(position.y),
            chrome,
            height * scale,
            area_top,
            area_top + f64::from(area.size.height),
        );
        height = fitted / scale;
        let top = top.round() as i32;
        if top != position.y {
            window
                .set_position(tauri::PhysicalPosition::new(position.x, top))
                .map_err(|_| "Cannot move the window.")?;
        }
    }
    // With Tauri's full-size macOS content view, setContentSize also includes
    // the titlebar. Other platforms' set_size already targets the viewport.
    #[cfg(target_os = "macos")]
    let height = height + titlebar;
    window
        .set_size(tauri::LogicalSize::new(WINDOW_WIDTH, height))
        .map_err(|_| "Cannot resize the window.".into())
}
