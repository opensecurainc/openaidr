// AppKit dialog coverage needs the main thread and a macOS desktop session.
#[cfg(target_os = "macos")]
#[allow(dead_code, unused_imports)]
#[path = "../src/platform/macos/install_location.rs"]
mod install_location;

#[cfg(target_os = "macos")]
fn main() {
    use objc2::{sel, AllocAnyThread, MainThreadMarker};
    use objc2_app_kit::{NSAlertFirstButtonReturn, NSImage, NSModalPanelRunLoopMode};
    use objc2_foundation::{NSArray, NSObjectNSDelayedPerforming, NSString};

    let mtm = MainThreadMarker::new().unwrap();
    let config: serde_json::Value = serde_json::from_str(include_str!("../tauri.macos.conf.json")).unwrap();
    let dmg = &config["bundle"]["macOS"]["dmg"];
    let background = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(dmg["background"].as_str().unwrap());
    let image = NSImage::initWithContentsOfFile(
        NSImage::alloc(), &NSString::from_str(background.to_str().unwrap()),
    ).unwrap();
    assert_eq!(image.size().width, dmg["windowSize"]["width"].as_f64().unwrap());
    assert_eq!(image.size().height, dmg["windowSize"]["height"].as_f64().unwrap());

    let alert = install_location::installation_alert(mtm);
    assert_eq!(alert.messageText().to_string(), "Move OpenAIDR to Applications");
    assert_eq!(alert.informativeText().to_string(),
        "Drag OpenAIDR to the Applications folder, then open it from there.");
    assert_eq!(alert.buttons().count(), 1);
    alert.layout();
    let quit = alert.buttons().objectAtIndex(0);
    assert_eq!(quit.title().to_string(), "Quit");
    assert_eq!(quit.keyEquivalent().to_string(), "\r");
    // The alert retains this hierarchy, and all access stays on the main thread.
    let bounds = unsafe { quit.superview() }.unwrap().bounds();
    // AppKit aligns button content; its decorative frame can extend outside
    // the containing stack view on macOS 15.
    let button = quit.alignmentRectForFrame(quit.frame());
    assert!(button.size.width > 0.0 && button.size.height > 0.0, "{button:?}");
    assert!(button.origin.x >= bounds.origin.x && button.origin.y >= bounds.origin.y,
        "Button content {button:?} starts outside {bounds:?}; frame {:?}", quit.frame());
    assert!(button.origin.x + button.size.width <= bounds.origin.x + bounds.size.width,
        "Button content {button:?} exceeds width {bounds:?}");
    assert!(button.origin.y + button.size.height <= bounds.origin.y + bounds.size.height,
        "Button content {button:?} exceeds height {bounds:?}");

    let (finished, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if receive.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
            eprintln!("The installation dialog did not close after Quit");
            std::process::exit(1);
        }
    });
    // Schedule a real button click in the modal loop, without UI automation permissions.
    unsafe {
        quit.performSelector_withObject_afterDelay_inModes(
            sel!(performClick:), None, 0.1,
            &NSArray::from_slice(&[NSModalPanelRunLoopMode]),
        );
    }
    assert_eq!(alert.runModal(), NSAlertFirstButtonReturn);
    finished.send(()).unwrap();
    println!("PASS: DMG background fits; installation instructions fit and Quit closes the native dialog");
}

#[cfg(not(target_os = "macos"))]
fn main() {}
