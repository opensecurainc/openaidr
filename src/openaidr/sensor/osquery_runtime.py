"""Run bounded queries against bundled osquery with a private extension socket."""

from openaidr import __version__
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

TIMEOUT = 30
MAX_OUTPUT = 64 * 1024
CHECK_QUERY = (
    "SELECT o.version AS osquery_version, e.version AS extension_version, "
    "e.schema_version FROM osquery_info o CROSS JOIN openaidr_extension_info e;"
)


class OsqueryError(RuntimeError):
    """A fixed runtime diagnostic safe to include in inventory coverage."""


def runtime_directory():
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "osquery"
    return Path(__file__).resolve().parents[3] / "build" / "desktop" / "osquery"


def _run(argv, cwd, *, stdin=None, output_limit=None, timeout=None):
    """Bound stdout, stderr, and the lifetime of osquery and its extension."""
    env = {**os.environ, "LC_ALL": "C", "PYINSTALLER_RESET_ENVIRONMENT": "1"}
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=stdin if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        stdout = bytearray()
        total = 0
        duration = TIMEOUT if timeout is None else timeout
        deadline = time.monotonic() + duration
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise OsqueryError(
                            f"Bundled osquery query timed out after {duration:.2f} seconds."
                        )
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > (
                            MAX_OUTPUT if output_limit is None else output_limit
                        ):
                            raise OsqueryError(
                                "Bundled osquery exceeded its output limit."
                            )
                        if key.data:
                            stdout.extend(chunk)
                process.wait(timeout=max(0, deadline - time.monotonic()))
            if process.returncode:
                raise OsqueryError(
                    f"Bundled osquery query failed (exit {process.returncode})."
                )
            try:
                return json.loads(stdout)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise OsqueryError("Bundled osquery returned invalid JSON.") from exc
        except subprocess.TimeoutExpired as exc:
            raise OsqueryError(
                f"Bundled osquery query timed out after {duration:.2f} seconds."
            ) from exc
        finally:
            # The extension is a child of osquery. Also stop descendants when the
            # parent exits first or a child keeps an output pipe open.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                shutdown_deadline = time.monotonic() + 2
                while time.monotonic() < shutdown_deadline:
                    process.poll()
                    os.killpg(process.pid, 0)
                    # Let the frozen extension remove its temporary files even
                    # when osquery has already exited.
                    time.sleep(0.02)
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _query(query, **limits):
    if sys.platform != "darwin":
        raise OsqueryError("The bundled osquery runtime currently supports macOS.")
    runtime = runtime_directory()
    binary = runtime / "osqueryi"
    extension = runtime / "openaidr-osquery.ext"
    manifest = runtime / "osquery.lock.json"
    if not all(path.is_file() for path in (binary, extension, manifest)):
        raise OsqueryError(
            "Bundled osquery is unavailable. Build the desktop sidecar first."
        )
    pin = json.loads(manifest.read_text())
    # macOS limits Unix socket paths to 104 bytes, including the SDK's suffix.
    with tempfile.TemporaryDirectory(prefix="openaidr-oq-", dir="/tmp") as directory:
        work = Path(directory)
        (work / "config.json").write_text("{}")
        (work / "extensions.load").touch()
        # SQL goes through a private file, avoiding the OS argument-size limit
        # and keeping installation paths out of process listings.
        query_file = work / "query.sql"
        query_file.write_text(query + "\n", encoding="utf-8")
        with query_file.open("rb") as stream:
            rows = _run(
                [
                    str(binary),
                    "--json",
                    "--flagfile=/dev/null",
                    f"--config_path={work / 'config.json'}",
                    f"--extensions_autoload={work / 'extensions.load'}",
                    f"--extensions_socket={work / 'socket'}",
                    "--extensions_timeout=10",
                    "--extensions_interval=1",
                    "--extensions_require=openaidr",
                    f"--extension={extension}",
                    "--disable_logging",
                    "--disable_events",
                    "--disable_database",
                    "--disable_enrollment",
                    "--read_max=1048576",
                ],
                work,
                stdin=stream,
                **limits,
            )
    expected = {
        "osquery_version": pin["version"],
        "extension_version": __version__,
        "schema_version": "1",
    }
    return rows, expected


def check_runtime():
    """Verify the packaged versions and extension registration without enrollment."""
    rows, expected = _query(CHECK_QUERY)
    if rows != [expected]:
        raise OsqueryError("Bundled osquery or OpenAIDR extension version mismatch.")
    return expected


def inventory_rows(source, paths, *, timeout=TIMEOUT):
    """Only allow selected metadata columns and equality-constrained locations."""
    queries = {
        "osquery-apps": (
            "openaidr_apps",
            "path",
            "path",
            "name",
            "identifier",
            "version",
            "''",
            "''",
        ),
        "osquery-npm-packages": (
            "npm_packages",
            "directory",
            "directory",
            "name",
            "name",
            "version",
            "author",
            "license",
        ),
        "osquery-python-packages": (
            "python_packages",
            "directory",
            "directory",
            "name",
            "name",
            "version",
            "author",
            "license",
        ),
        "openaidr-skills": (
            "openaidr_skills",
            "directory",
            "directory",
            "name",
            "name",
            "version",
            "publisher",
            "''",
        ),
        "openaidr-mcp-servers": (
            "openaidr_mcp_servers",
            "path",
            "path",
            "name",
            "identifier",
            "''",
            "''",
            "''",
        ),
        "openaidr-plugins": (
            "openaidr_plugins",
            "directory",
            "directory",
            "name",
            "name",
            "version",
            "publisher",
            "''",
        ),
    }
    (
        table,
        constraint,
        directory,
        name,
        identifier,
        version_field,
        author,
        license_field,
    ) = queries[source]
    literals = ",".join("'" + str(path).replace("'", "''") + "'" for path in paths)
    query = (
        "SELECT 'runtime' AS record, '' AS path, '' AS directory, "
        "e.version AS name, o.version AS identifier, e.schema_version AS version, "
        "'' AS publisher, '' AS license, '' AS metadata, '' AS status, '' AS message, "
        "'' AS skill_directories "
        "FROM osquery_info o "
        "CROSS JOIN openaidr_extension_info e"
    )
    extension = source in (
        "openaidr-skills",
        "openaidr-mcp-servers",
        "openaidr-plugins",
    )
    if paths:
        record = "record" if extension else "'component'"
        extra = "'', '', ''"
        if source in ("openaidr-skills", "openaidr-plugins"):
            extra = "metadata, status, message"
        elif extension:
            extra = "'', status, message"
        extra += ", skill_directories" if source == "openaidr-plugins" else ", ''"
        query += (
            f" UNION ALL SELECT {record}, path, {directory}, {name}, {identifier}, "
            f"{version_field}, {author}, {license_field}, {extra} FROM {table} "
            f"WHERE {constraint} IN ({literals})"
        )
        if source == "osquery-npm-packages":
            query += " AND max_depth = 8"
    rows, expected = _query(query + ";", output_limit=16 << 20, timeout=timeout)
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise OsqueryError("Bundled osquery returned an invalid result.")
    checks = [row for row in rows if row.get("record") == "runtime"]
    if (
        len(checks) != 1
        or {
            "osquery_version": checks[0].get("identifier"),
            "extension_version": checks[0].get("name"),
            "schema_version": checks[0].get("version"),
        }
        != expected
    ):
        raise OsqueryError("Bundled osquery or OpenAIDR extension version mismatch.")
    records = ("component", "coverage") if extension else ("component",)
    return [row for row in rows if row.get("record") in records]
