use objc2::{rc::Retained, MainThreadMarker};
use objc2_app_kit::{NSAlert, NSApplication, NSApplicationActivationPolicy};
use objc2_foundation::{NSBundle, NSHomeDirectory, NSString};
use std::path::{Path, PathBuf};

pub(crate) fn check_launch(interactive: bool) -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    let bundle = PathBuf::from(NSBundle::mainBundle().bundlePath().to_string());
    let home = PathBuf::from(NSHomeDirectory().to_string());
    let home = home.canonicalize().unwrap_or(home);
    if installed_bundle(&bundle, &[PathBuf::from("/Applications"), home.join("Applications")]) {
        return true;
    }
    // Background update workers must also stop, without waiting on a dialog.
    if interactive {
        let mtm = MainThreadMarker::new().expect("App startup must run on the main thread");
        installation_alert(mtm).runModal();
    }
    false
}

fn installed_bundle(bundle: &Path, applications: &[PathBuf]) -> bool {
    // Resolve the bundle itself so an Applications symlink to a DMG cannot
    // make an uninstalled copy pass. Do not require ownership or write access.
    let Ok(bundle) = bundle.canonicalize() else {
        return false;
    };
    bundle.is_dir()
        && bundle.extension().is_some_and(|extension| extension == "app")
        && applications.iter().any(|directory| bundle.parent() == Some(directory.as_path()))
}

pub(crate) fn installation_alert(mtm: MainThreadMarker) -> Retained<NSAlert> {
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Regular);
    app.finishLaunching();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("Move OpenAIDR to Applications"));
    alert.setInformativeText(&NSString::from_str(
        "Drag OpenAIDR to the Applications folder, then open it from there.",
    ));
    alert.addButtonWithTitle(&NSString::from_str("Quit"));
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
    alert
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    #[cfg(debug_assertions)]
    fn development_runs_do_not_require_installation() {
        assert!(check_launch(false));
    }

    #[test]
    fn only_installed_bundles_can_start() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let applications = [root.join("Applications"), root.join("Users/test/Applications")];
        for parent in &applications {
            for name in ["OpenAIDR.app", "OpenAIDR Sensor.app"] {
                let bundle = parent.join(name);
                fs::create_dir_all(&bundle).unwrap();
                assert!(installed_bundle(&bundle, &applications));
            }
        }
        for relative in [
            "Volumes/OpenAIDR/OpenAIDR.app",
            "private/var/folders/random/AppTranslocation/random/d/OpenAIDR.app",
            "Users/test/Downloads/OpenAIDR.app",
            "Applications-old/OpenAIDR.app",
            "Applications/OpenAIDR",
            "Applications/Nested/OpenAIDR.app",
        ] {
            let bundle = root.join(relative);
            fs::create_dir_all(&bundle).unwrap();
            assert!(!installed_bundle(&bundle, &applications), "{relative}");
        }
        let link = applications[0].join("Linked.app");
        symlink(root.join("Volumes/OpenAIDR/OpenAIDR.app"), &link).unwrap();
        assert!(!installed_bundle(&link, &applications));
        assert!(!installed_bundle(&applications[0].join("Missing.app"), &applications));
        let file = applications[0].join("File.app");
        fs::write(&file, b"").unwrap();
        assert!(!installed_bundle(&file, &applications));
    }
}
