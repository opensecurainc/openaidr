# Desktop product name

The desktop application is **OpenAIDR**. It supports both AI activity monitoring
and guardrails, so its product name covers both capabilities.

Use this name in app UI, native windows, the Dock, installers, release titles,
and documentation. Keep the capitalization shown here. Use **sensor** for the
activity collection component and **guardrails** for policy enforcement when
describing those components or their status.

## User-facing names

| Surface | Name |
| --- | --- |
| App, native window title, Dock label, and HTML title | `OpenAIDR` |
| New macOS application bundle | `OpenAIDR.app` |
| macOS installer volume | `OpenAIDR` |
| Local macOS installer | `OpenAIDR_<version>_<architecture>.dmg` |
| Published installer | `OpenAIDR-<architecture>.dmg` |
| Published updater archive | `OpenAIDR-<architecture>.app.tar.gz` |
| GitHub release title | `OpenAIDR <version>` |

`apps/desktop/src-tauri/tauri.conf.json` defines the product name and native window
title. Tauri uses the product name for bundle display metadata and installers.
Keep `apps/desktop/index.html` and the manual release title consistent with it.
Future platform installers must use the same product name.

The shared version naming policy defines
`YYYY.M.D+<commit>`, such as `2026.10.6+8d5b065`, for every new build, including
local and unsigned builds. Follow the release procedure and
verify the embedded version as well as the installer name. Only an explicit
user instruction can authorize an exception; missing tooling support cannot.

## Compatibility

### Windows folder migration

The Windows layout compatibility release retains the current folders and
records `windows_layout: 1` in signed publication metadata. Publish it on the
compatibility feeds before shipping layout 2. The publisher refuses layout 2
on either compatibility feed, and requires the rollout-v1 bridge to advertise
layout 1 before layout 2 can reach rollout-v2.

Signed Windows builds run from `main` but record and verify the layout of the
source they build: 2 when it contains the folder move, 1 when it contains only the
recoverable migration, and no signed release before that
(`WINDOWS_LAYOUT_CHANGES` in `scripts/macos_release_ci.py`). Build the
compatibility release from a `main` commit with layout 1, such as the merge of
#610.

Layout 2 uses `%LOCALAPPDATA%\OpenAIDR\app` for the app,
`app\runtime` for its bundled component, and `OpenAIDR\data` for persistent
state and versioned background runtimes. A worker and its signed installer
are retained in `OpenAIDR\migration` before the update schedule changes.
The previous signed uninstaller is retained there too. It removes its recorded
app files in update mode, keeping data, services, and shortcuts. The recovery
worker then installs the new app, stops the owned background task, relocates
the state directory, rewrites only operational configuration paths and owned
hook registrations, and transfers the update schedule to the new data folder.
The migration journal permits retries after each interruption without
overwriting a second configuration. Enrollment, certificates, queued activity,
the rollout installation ID, and task disablement are preserved. A failure
before the state move restores the task’s previous enabled and running state.
After the move, recovery validates the new configuration and runtime before
restarting the task. Hook registration retries do not keep the service stopped.

The automatic relocation supports the standard per-user installation. A
custom installation, customized task, duplicate data directory, or linked
state path stops migration without overwriting that state. Locked runtimes
can require closing coding agents before retrying from OpenAIDR. Custom
configuration paths and machine-wide installations are not relocated.
No installer download or IT intervention is required for the supported path.
Restart coding-agent sessions after migration so cached hook commands use the
new paths.

Before publication, test the signed old-to-bridge-to-layout-2 sequence on a
disposable Windows account, including process termination and reboot during
the installer, state rename, and schedule handoff. Native tests and unsigned
installer tests do not substitute for this signed release check.

The `2026.10.20+067f288` compatibility worker passes `OpenAIDR/app` in the
installer's `/D` argument. NSIS removes the forward slash, producing
`OpenAIDRapp`. New installers recognize that exact command and use
`OpenAIDR\app`; new workers use backslashes. An already-failed migration keeps
its original signed installer and cannot fetch a correction by itself. Run or
deploy a later signed installer to repair that installation. After installing
the app, it starts recovery without a PowerShell command or a manual downgrade.
The new app retains its signed worker, preserves the original signed transaction,
and finishes migration using the verified installed app and matching sensor.
Opening the installed app also retries the handoff. Silent installation does
not request a new app window; a previous user-requested update can still reopen it.
When the legacy app has already been removed and migration is pending, opening
the standard installer enters passive update mode automatically. This avoids
the registered app's blocked uninstaller while showing installation progress.
Original installer arguments are retained. Silent deployment uses the same
postinstall recovery path.

Older upgrades can leave `sensor\_internal\openaidr-*.dist-info` metadata
that the previous uninstaller did not record. Recovery preserves a tree
containing only this metadata in `migration\previous-sensor-metadata` before
continuing. Runtime files or unrelated files outside those metadata folders,
linked paths, and an existing backup stop this cleanup without deleting or
overwriting them. The migration still
rejects unsigned apps, mismatched app and sensor builds, invalid publication
metadata, custom task paths, and conflicting state directories. Enrollment,
queued activity, rollout identity, and a disabled sensor remain preserved.

Before publishing this repair, exercise a signed compatibility release, an
interrupted layout-2 release with old metadata, and a later corrective installer
on Windows. Verify recovery with the release feed unavailable and with the
sensor both running and disabled. Keep the old installer, journal, and metadata
backup for diagnosis. Roll back with a later signed corrective release; do not
edit the saved release identity or bypass signature checks.

### App identifier migration

The target shared Tauri identifier is `com.opensecura.openaidr`. First ship this
compatibility release with `com.opensecura.openaidr.sensor`. Its Mac updater
accepts only these two OpenAIDR identifiers, preserves the existing instance
lock, and can finish an update whose retained backup has the old identifier.
Signatures, version checks, and publication ordering remain required.

New clients read `rollout-v2.json`. Publish the compatibility release there,
then use `bootstrap` or `promote` at unpaused 100% to advertise it on both
`rollout-v1.json` and `latest.json`. The signed Mac plist records
`OpenAIDRIdentityMigration: 1`; the publisher checks this marker and the old
bundle ID before advancing either older feed.

Only after that release is installed and a signed native migration passes
should the follow-up change switch the shared identifier. Publish the renamed
release with `publish`, which updates only `rollout-v2.json`. Keep both older
feeds on the compatibility release indefinitely so clients that skip releases
can still reach it. The publisher blocks the renamed app until both older feeds
advertise the same compatible release, and rejects legacy promotion of a
renamed app. Do not use older publisher scripts to bypass these guards.

Users with supported self-updating installations can use **Update now** twice,
with a restart after each step. Existing sensor data, enrollment, hooks, service
identities, installed paths, and updater keys remain in place. Linux DEBs and
unmanaged AppImages still need the existing explicit AppImage setup.

Keep the old signed artifacts and immutable release records. Roll back a
defective release with a later signed corrective release and the normal
publication ordering. Never point an older feed at the new app ID, remove an
installed user's data, or restore an older publication timestamp.

### Endpoint compatibility

The endpoint command is now `openaidr`. Use these executable names while
retaining the app's existing identity and data locations:

- Bundle identifier: `com.opensecura.openaidr.sensor`.
- Desktop executable and package: `openaidr-desktop`.
- Endpoint executable and new Linux/macOS service registrations: `openaidr`.
- New Windows Scheduled Task: `OpenAIDR <user SID>`.
- Legacy executable alias: `openaidr-sensor`.
- macOS data directory: `~/Library/Application Support/OpenAIDR`.
- Updater service: `com.opensecura.openaidr.updater`.
- Current release feed: `https://releases.opensecura.ai/openaidr/rollout-v2.json`.
- Compatibility feeds: `rollout-v1.json` and `latest.json` on the same origin.

Keep the existing updater signing key. Retaining these identities and paths
preserves enrollment, settings, queued events, hooks, and the single-instance
guard while service registrations migrate.
Do not rename captured evidence or paths returned by the sensor to match the
product name.

Ship both endpoint executable names during the migration. Older macOS
updaters require a real `Contents/MacOS/openaidr-sensor` file and reject a
symlink at that path. Both files must be included before signing and report
the same source-derived version and build metadata. Keep legacy installed
paths usable for existing hooks and active managed sessions.

Discover legacy service registrations before creating the new registration.
Verify that they belong to the same configuration, stop the old process before
starting the replacement, and restore the previous registration when the
handoff fails and the replacement can be stopped safely. Preserve enrollment,
retained records, native hook trust and
user disablement. Windows layout 2 uses `OpenAIDR\data` for persistent state;
the installer owns only `OpenAIDR\app`. Existing installations retain
`OpenAIDR Sensor` until the staged migration above completes.

Automatic updates preserve the installed bundle's path. An existing
`OpenAIDR Sensor.app` receives the new display metadata at that path. New
installations use `OpenAIDR.app`. The updater accepts both filenames and checks
the stable bundle identifier, version, and signatures.

For a manual replacement, quit the old desktop app, copy `OpenAIDR.app` into
Applications, remove the old desktop bundle, and open the new app. The sensor
continues running independently, and its data directory stays in place. Quit
the old app first so the single-instance guard does not activate it instead.
No new enrollment is needed. Setup migrates compatible legacy service
registrations as described in the command migration guide.
Existing version checks still prevent sensor downgrades.
