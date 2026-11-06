// Run with: osascript -l JavaScript install-macos.js
// JavaScript for Automation and Foundation are included with macOS.
var INSTALLER = "https://releases.opensecura.ai/openaidr/latest/OpenAIDR-aarch64.dmg";
var SIGNATURE = '=anchor apple generic and certificate leaf[subject.OU] = "CLYZ4TV7UP" and ' +
    '(identifier "com.opensecura.openaidr.sensor" or identifier "com.opensecura.openaidr")';

function verifyApp(mac, path) {
    mac.exec("/usr/bin/codesign", ["--verify", "--deep", "--strict", "-R", SIGNATURE, path]);
    mac.exec("/usr/sbin/spctl", ["--assess", "--type", "execute", path]);
}

function finishMdm(mac, sensor) {
    var state = mac.bridge(sensor, "setup", {});
    if (!Array.isArray(state.steps) || state.steps.some(function (step) { return step.ok !== true; })) {
        throw new Error("OpenAIDR is enrolled, but background setup is incomplete. Retry the MDM script; the existing connection will be kept.");
    }
    for (var attempt = 0; attempt <= 30; attempt++) {
        if (state.enrolled === true && state.service === "running" && state.running === true &&
            !state.service_outdated && !state.settings_stale &&
            (state.disabled || !state.telemetry || !state.telemetry.enabled || state.telemetry.listening === true)) {
            return "OpenAIDR is enrolled and its background sensor is running. The existing connection is kept on retries. No app window was opened.";
        }
        if (attempt === 30) break;
        mac.sleep(1);
        state = mac.bridge(sensor, "status", {});
    }
    throw new Error("OpenAIDR is enrolled, but its background sensor is not ready. Retry the MDM script; the existing connection will be kept.");
}

function install(mac, mdm) {
    var uid = mac.exec("/usr/bin/id", ["-u"]).trim();
    var root = uid === "0";
    if (!mdm && root) {
        throw new Error("Run this script as your normal macOS account, without sudo.");
    }
    if (mac.exec("/usr/sbin/sysctl", ["-n", "hw.optional.arm64"]).trim() !== "1" ||
        parseInt(mac.exec("/usr/bin/sw_vers", ["-productVersion"]), 10) < 12) {
        throw new Error("OpenAIDR requires macOS 12 or later on an Apple Silicon Mac.");
    }
    if (mdm) mac.useConsoleUser(uid);
    if (mdm && mac.exists(mac.home + "/Library/Application Support/OpenAIDR/desktop-removal.json")) {
        throw new Error("OpenAIDR was removed for this account. Restore the installation before running the MDM script.");
    }

    var applications = "/Applications";
    var installed = [applications + "/OpenAIDR.app", mac.home + "/Applications/OpenAIDR.app",
        applications + "/OpenAIDR Sensor.app", mac.home + "/Applications/OpenAIDR Sensor.app"].filter(mac.exists);
    if (installed.length > 1) {
        throw new Error("More than one OpenAIDR app is installed. Keep one installed copy, then run this script again.");
    }
    var app = installed[0];
    if (!app) {
        if (!mac.writable(applications)) {
            throw new Error("Your account needs write permission for /Applications. Ask your Mac administrator to install OpenAIDR there, then run this script again without sudo.");
        }
        if (!mdm) mac.confirm("Download the signed OpenAIDR app and install it in " + applications +
            ". You will then review your organization before connecting this Mac.", "Install");
        var temporary = mac.exec("/usr/bin/mktemp", ["-d", "-t", "openaidr-install"]).trim();
        var mount = temporary + "/volume";
        var staging = null;
        var mounting = false;
        try {
            mac.progress("Downloading OpenAIDR...");
            mac.exec("/usr/bin/curl", ["--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "20",
                "--max-time", "600", "--output", temporary + "/OpenAIDR.dmg", INSTALLER]);
            mounting = true;
            mac.exec("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", mount,
                temporary + "/OpenAIDR.dmg"]);
            mac.progress("Verifying and installing OpenAIDR...");
            verifyApp(mac, mount + "/OpenAIDR.app");
            mac.exec("/bin/mkdir", ["-p", applications]);
            staging = mac.exec("/usr/bin/mktemp", ["-d", applications + "/.openaidr-install.XXXXXX"]).trim();
            mac.exec("/usr/bin/ditto", [mount + "/OpenAIDR.app", staging + "/OpenAIDR.app"]);
            if (mdm && root) mac.exec("/usr/sbin/chown", ["-R", "-P", "root:wheel", staging + "/OpenAIDR.app"]);
            verifyApp(mac, staging + "/OpenAIDR.app");
            app = applications + "/OpenAIDR.app";
            // NSFileManager refuses an existing destination, including a concurrent installation.
            mac.move(staging + "/OpenAIDR.app", app);
        } finally {
            if (staging) mac.cleanup(staging);
            var detached = !mounting;
            if (mounting) {
                try {
                    mac.exec("/usr/bin/hdiutil", ["detach", mount]);
                    detached = true;
                } catch (_) {
                    mac.progress("Could not eject the installer. Eject OpenAIDR in Finder. Temporary files: " + temporary);
                }
            }
            // Never recursively remove a directory while its disk image may still be mounted.
            if (detached) mac.cleanup(temporary);
        }
    } else {
        verifyApp(mac, app);
    }

    var sensor = app + "/Contents/MacOS/openaidr";
    if (!mac.exists(sensor)) sensor = app + "/Contents/MacOS/openaidr-sensor";
    var state = mac.bridge(sensor, "status", {});
    if (typeof state.enrolled !== "boolean") throw new Error("Cannot verify this Mac's enrollment state.");
    var removed = mac.exists(mac.home + "/Library/Application Support/OpenAIDR/desktop-removal.json");
    if (state.enrolled) {
        if (mdm) return finishMdm(mac, sensor);
        if (removed) {
            mac.confirm("Reinstall OpenAIDR for your saved organization" +
                (state.tenant_name ? ": " + state.tenant_name : "") + "?\n\nServer: " + state.server_url +
                "\n\nThis restores collection, automatic updates, and your saved agent settings. The existing connection is kept; the supplied enrollment link is not used.", "Install");
            mac.resume(sensor, app);
        }
        mac.exec("/usr/bin/open", [app]);
        return "OpenAIDR is installed. The existing connection is kept. The app is opening to finish automatic setup.";
    }

    var link = mac.enrollmentLink().trim();
    // The bundled sensor performs full URL validation. Reject malformed secrets before sending them.
    if (link.length > 4096 || !/^https:\/\/[^\s?#]+\/enroll#token=oaet_[A-Za-z0-9_-]{43}$/.test(link)) {
        throw new Error("Paste the complete HTTPS enrollment link supplied by your administrator.");
    }
    mac.progress("Checking the enrollment link...");
    var preview = mac.bridge(sensor, "enrollment.preview", {link: link});
    if (!preview.tenant || typeof preview.tenant.id !== "string" ||
        typeof preview.tenant.name !== "string" || typeof preview.server_url !== "string") {
        throw new Error("The enrollment preview is incomplete. Open OpenAIDR to connect.");
    }
    if (!mdm) mac.confirm("Connect this Mac to " + preview.tenant.name + "?\n\nServer: " + preview.server_url +
        "\n\nOpenAIDR will start its background sensor and configure detected coding agents using your organization's settings.", "Connect");
    mac.progress("Connecting to your organization...");
    var connected = mac.bridge(sensor, "enrollment.connect", {link: link, tenant_id: preview.tenant.id});
    link = "";
    if (connected.enrolled !== true) {
        throw new Error("Enrollment could not be confirmed. Open OpenAIDR to check the connection before trying again.");
    }
    if (mdm) return finishMdm(mac, sensor);
    if (removed) {
        mac.resume(sensor, app);
    }
    try {
        mac.exec("/usr/bin/open", [app]);
    } catch (_) {
        throw new Error("Enrollment succeeded. Open OpenAIDR from Applications to finish setup; do not reuse the enrollment link.");
    }
    return "This Mac is enrolled. OpenAIDR is opening to finish setup. Check its status, then restart your coding-agent sessions.";
}

function nativeMac(mdm) {
    ObjC.import("Foundation");
    ObjC.import("AppKit");
    ObjC.bindFunction("open", ["int", ["char *", "int"]]);
    ObjC.bindFunction("flock", ["int", ["int", "int"]]);
    ObjC.bindFunction("close", ["int", ["int"]]);
    var ui = mdm ? null : Application.currentApplication();
    if (ui) ui.includeStandardAdditions = true;
    var files = $.NSFileManager.defaultManager;
    var mac = {
        home: ObjC.unwrap($.NSHomeDirectory()),
        exists: function (path) { return Boolean(files.fileExistsAtPath(path)); },
        writable: function (path) { return Boolean(files.isWritableFileAtPath(path)); },
        progress: function (message) { console.log(message); },
        sleep: function (seconds) { $.NSThread.sleepForTimeInterval(seconds); },
        useConsoleUser: function (callerUid) {
            var uid = mac.exec("/usr/bin/stat", ["-f", "%u", "/dev/console"]).trim();
            if (!/^[0-9]+$/.test(uid) || Number(uid) < 501) {
                throw new Error("No user is logged in. Schedule the MDM script to retry after login.");
            }
            if (callerUid !== "0" && callerUid !== uid) {
                throw new Error("Run the MDM script as the logged-in user or as root.");
            }
            var name = mac.exec("/usr/bin/id", ["-un", uid]).trim();
            if (name === "_mbsetupuser" || name === "loginwindow" || name === "root") {
                throw new Error("Mac setup or login is incomplete. Schedule the MDM script to retry after login.");
            }
            var home = ObjC.unwrap($.NSHomeDirectoryForUser(name));
            if (typeof home !== "string" || home[0] !== "/" || home === "/" || home === "/var/root" ||
                /[\r\n\u0000]/.test(home) || !mac.exists(home)) {
                throw new Error("Cannot locate the logged-in user's home folder.");
            }
            mac.exec("/bin/launchctl", ["print", "gui/" + uid]);
            mac.user = {uid: uid, name: name, home: home, root: callerUid === "0"};
            mac.home = home;
        },
        userExec: function (executable, args, input) {
            // A clean environment prevents MDM/root HOME and agent paths from leaking into setup.
            var user = mac.user;
            var command = ["/usr/bin/env", "-i", "HOME=" + user.home, "USER=" + user.name, "LOGNAME=" + user.name,
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin", executable].concat(args);
            if (user.root) {
                // Join the login session and drop root before touching user state or running the sensor.
                return mac.exec("/bin/launchctl", ["asuser", user.uid, "/usr/bin/sudo", "-H", "-n", "-u", "#" + user.uid].concat(command), input);
            }
            return mac.exec(command[0], command.slice(1), input);
        },
        confirm: function (message, button) {
            ui.displayDialog(message, {withTitle: "Install OpenAIDR", buttons: ["Cancel", button],
                defaultButton: button, cancelButton: "Cancel"});
        },
        enrollmentLink: function () {
            return ui.displayDialog("Paste your OpenAIDR enrollment link:", {
                withTitle: "Install OpenAIDR", defaultAnswer: "", hiddenAnswer: true,
                buttons: ["Cancel", "Continue"], defaultButton: "Continue", cancelButton: "Cancel"
            }).textReturned;
        },
        move: function (source, destination) {
            if (!files.moveItemAtPathToPathError(source, destination, null)) {
                throw new Error("Could not install OpenAIDR. Check whether another copy already exists in Applications.");
            }
        },
        cleanup: function (path) {
            if (!files.removeItemAtPathError(path, null)) console.log("Could not remove temporary files: " + path);
        },
        quit: function (app) {
            // A running removal window will not register updates again until the app restarts.
            ["com.opensecura.openaidr.sensor", "com.opensecura.openaidr"].forEach(function (identifier) {
                var running = $.NSRunningApplication.runningApplicationsWithBundleIdentifier(identifier);
                for (var index = 0; index < running.count; index++) {
                    var instance = running.objectAtIndex(index);
                    if (ObjC.unwrap(instance.bundleURL.path) !== app || !instance.terminate) {
                        throw new Error("Quit the running OpenAIDR app, then run this script again to finish installation.");
                    }
                    var deadline = Date.now() + 5000;
                    while (!instance.isTerminated && Date.now() < deadline) {
                        $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1));
                    }
                    if (!instance.isTerminated) throw new Error("OpenAIDR is still closing. Run this script again after it quits.");
                }
            });
        },
        resume: function (sensor, app) {
            var directory = mac.home + "/Library/Application Support/OpenAIDR";
            var marker = directory + "/desktop-removal.json";
            var uid = mac.exec("/usr/bin/id", ["-u"]).trim();
            var attributes = ObjC.deepUnwrap(files.attributesOfItemAtPathError(directory, null));
            if (!attributes || String(attributes.NSFileOwnerAccountID) !== uid ||
                attributes.NSFileType !== "NSFileTypeDirectory" || (attributes.NSFilePosixPermissions & 18) !== 0) {
                throw new Error("The OpenAIDR data folder must belong to your account and must not be shared. Open the app to repair this installation.");
            }
            for (var parent = directory; parent; parent = parent.slice(0, parent.lastIndexOf("/"))) {
                var entry = ObjC.deepUnwrap(files.attributesOfItemAtPathError(parent, null));
                if (!entry || entry.NSFileType === "NSFileTypeSymbolicLink") {
                    throw new Error("OpenAIDR cannot reinstall through a linked data folder. Open the app to repair this installation.");
                }
            }
            var locks = [];
            try {
                // Match the app's removal lock order so updates and uninstall cannot race a reinstall.
                ["desktop-updater.lock", "desktop-operation.lock"].forEach(function (name) {
                    var path = directory + "/" + name;
                    if (!mac.exists(path)) {
                        var temporary = mac.exec("/usr/bin/mktemp", [directory + "/.install-lock.XXXXXX"]).trim();
                        try {
                            // A hard link creates the lock atomically without replacing an existing lock.
                            files.linkItemAtPathToPathError(temporary, path, null);
                        } finally { mac.cleanup(temporary); }
                    }
                    // Darwin: O_RDWR | O_NOFOLLOW | O_CLOEXEC. The lock already exists.
                    var descriptor = $.open(path, 2 | 256 | 16777216);
                    if (descriptor < 0) throw new Error("Cannot open the OpenAIDR operation lock. Open the app to repair this installation.");
                    locks.push(descriptor);
                    if ($.flock(descriptor, 2 | 4) !== 0) {
                        throw new Error("OpenAIDR is busy updating or changing its installation. Wait for it to finish, then run this script again.");
                    }
                });
                if (!mac.exists(marker)) return;
                mac.quit(app);
                mac.progress("Restoring OpenAIDR setup...");
                var resumed = mac.bridge(sensor, "desktop.resume", {});
                if (resumed.resumed !== true) throw new Error("Could not restore the saved settings. Open OpenAIDR to retry installation.");
                mac.exec("/bin/launchctl", ["enable", "gui/" + uid + "/com.opensecura.openaidr.updater"]);
                // Clear the marker last, exactly as the app does after restoring preferences and updates.
                if (!files.removeItemAtPathError(marker, null)) {
                    throw new Error("Could not clear the uninstall record. Open OpenAIDR to retry installation.");
                }
            } finally {
                locks.reverse().forEach(function (descriptor) { $.close(descriptor); });
            }
        },
        exec: function (executable, args, input) {
            var task = $.NSTask.alloc.init;
            task.launchPath = executable;
            task.arguments = args;
            var output = $.NSPipe.pipe;
            task.standardOutput = output;
            // Do not expose command diagnostics that could contain enrollment data.
            task.standardError = $.NSFileHandle.fileHandleWithNullDevice;
            var pipe = input === undefined ? null : $.NSPipe.pipe;
            task.standardInput = pipe || $.NSFileHandle.fileHandleWithNullDevice;
            task.launch;
            if (pipe) {
                pipe.fileHandleForWriting.writeData($(input).dataUsingEncoding($.NSUTF8StringEncoding));
                pipe.fileHandleForWriting.closeFile;
            }
            var data = output.fileHandleForReading.readDataToEndOfFile;
            task.waitUntilExit;
            if (task.terminationStatus !== 0) throw new Error("Could not complete " + executable.split("/").pop() +
                ". Check your connection and macOS security settings, then try again.");
            return ObjC.unwrap($.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding));
        },
        bridge: function (sensor, action, params) {
            // A pipe keeps the link out of process arguments, shell history, and temporary files.
            var execute = mac.user ? mac.userExec : mac.exec;
            var raw = execute(sensor, ["desktop-bridge"], JSON.stringify({action: action, params: params}));
            var result;
            try { result = JSON.parse(raw); } catch (_) { result = null; }
            if (!result || result.ok !== true || !result.data) {
                if (action === "enrollment.preview") {
                    throw new Error("Could not verify the enrollment link. Check that it has not expired or been used. " +
                        "For a private server certificate, connect from the OpenAIDR app.");
                }
                throw new Error("Could not confirm " + action + ". Open OpenAIDR to check the connection before trying again.");
            }
            return result.data;
        },
        notify: function (message) {
            ui.displayDialog(message, {withTitle: "Install OpenAIDR", buttons: ["OK"], defaultButton: "OK"});
        }
    };
    return mac;
}

function run(argv) {
    if (argv.length === 1 && argv[0] === "--mdm-version") return "1";
    var mdm = argv.indexOf("--mdm") !== -1;
    var fromInput = argv.indexOf("--enrollment-stdin") !== -1;
    if (argv.length !== Number(mdm) + Number(fromInput) || (mdm && !fromInput)) {
        throw new Error("Usage: osascript -l JavaScript install-macos.js [--enrollment-stdin] [--mdm --enrollment-stdin]");
    }
    var mac = nativeMac(mdm);
    if (fromInput) {
        var input = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
        var suppliedLink = ObjC.unwrap($.NSString.alloc.initWithDataEncoding(input, $.NSUTF8StringEncoding));
        mac.enrollmentLink = function () { return suppliedLink; };
    }
    try {
        var message = install(mac, mdm);
        if (!mdm) mac.notify(message);
        return message;
    } catch (error) {
        if (!mdm && error.errorNumber === -128) return "Installation cancelled. Any completed app installation is kept.";
        if (!mdm) mac.notify(error.message);
        throw error;
    }
}
