# Windows hook client

This Rust package builds `openaidr-hook.exe`, the small hook client bundled
with the Windows sensor. Ordinary hooks use Windows HTTP APIs to contact the
running sensor over authenticated loopback without starting Python or
PowerShell. Policy evaluation stays in the sensor and backend.

The client has its own Cargo package because it builds as a separate executable
with Windows API dependencies. The desktop build bundles it beside the sensor.
Source-only Windows installs without this executable use the PowerShell
compatibility launcher. macOS and Linux launchers live in
[`hook_runtime.py`](../../src/openaidr/sensor/hook_runtime.py).

- `src/main.rs`: configuration parsing, response validation, and contract tests.
- `src/windows.rs`: Windows HTTP transport, process timing, and delivery receipts.
- [`scripts/build_windows_hook.py`](../../scripts/build_windows_hook.py): builds
  the executable with source-derived metadata and verifies runtime dependencies.
- [`tests/test_hook_runtime_windows.py`](../../tests/test_hook_runtime_windows.py):
  exercises the packaged client through native Windows shells.

Run the Rust contract tests from the repository root:

```sh
cargo test --locked --manifest-path packages/windows-hook/Cargo.toml
```

The contract tests also run on macOS and Linux. Native transport and shell tests
require Windows and run in the
[Windows desktop workflow](../../.github/workflows/desktop-windows.yml).
Use the [desktop build](../../apps/desktop/README.md) for a packaged executable
with the required version metadata. See the
hook architecture
for deadlines, failure handling, and compatibility.
