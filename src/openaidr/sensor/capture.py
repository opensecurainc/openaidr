"""Coordinate native observations with one immutable managed launch binding."""

from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import sqlite3
import uuid

from openaidr.core.event import validate_event
from openaidr.core.files import durable_directory, sync_directory
from openaidr.core.redact import redact_event, redact_string

from openaidr.guardrail.journal import Journal, JournalError, _private, canonical

LAUNCH_ATTRIBUTE = "openaidr.managed.launch_id"
REGISTRATION_ATTRIBUTE = "openaidr.session.registration_id"
PRODUCTS = {"codex-cli", "claude-code"}


class CaptureDeferred(ValueError):
    def __init__(self, code="managed_capture_pending"):
        self.code = code
        super().__init__(code)


def effective_capture(current, managed):
    """A launch can restrict current collection permission, never widen it."""
    result = copy.deepcopy(current)
    for key in ("prompt_text", "response_text", "tool_input", "tool_output", "raw"):
        result[key] = bool(current.get(key)) and bool(managed.get(key))
    result["redact"] = bool(current.get("redact")) or bool(managed.get("redact"))
    limits = [v.get("max_text_bytes") for v in (current, managed)]
    limits = [value for value in limits if type(value) is int and value > 0]
    result["max_text_bytes"] = min(limits) if limits else 16384
    return result


def _captured_observation(event, capture, binding):
    from openaidr.guardrail.gate import _capture_event

    result = _capture_event(event, capture, binding)
    # Collector provenance and execution metadata are observations, not additional
    # action arguments. Keep their typed fields beside the captured content.
    fields = {
        "agent": ("model",),
        "tool": ("is_error", "success", "duration_ms", "caller"),
        "source": ("collector", "line", "record_id"),
    }
    if capture.get("tool_input"):
        fields.update(
            session=("cwd", "git_branch", "entrypoint", "parent_id"),
            command=("exit_code",),
            file=("operation",),
        )
        fields["source"] += ("path",)
    for name, keys in fields.items():
        for key in keys:
            value = event.get(name, {}).get(key)
            if not isinstance(value, (str, int, float, bool)):
                continue
            if isinstance(value, str):
                if capture.get("redact"):
                    value, reasons = redact_string(value)
                    if reasons:
                        result["evidence"]["gaps"].append("content_redacted")
                if len(value.encode()) > capture["max_text_bytes"]:
                    value = value.encode()[: capture["max_text_bytes"]].decode(
                        "utf-8", errors="ignore"
                    )
                    result["evidence"]["gaps"].append("content_truncated")
            result.setdefault(name, {})[key] = value
    result["evidence"]["gaps"] = sorted(set(result["evidence"]["gaps"]))
    return result


class CaptureCoordinator:
    def __init__(self, config):
        self.config = config
        self.directory = durable_directory(Path(config["data_dir"]) / "managed")
        _private(self.directory, directory=True)
        self.path = self.directory / "capture.sqlite3"
        marker = self.directory / "capture.initialized"
        if marker.exists() and not self.path.exists():
            raise CaptureDeferred("managed_capture_lost")
        descriptor = os.open(
            self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        os.close(descriptor)
        _private(self.path)
        with self._db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS launches(
                    id TEXT PRIMARY KEY, product TEXT NOT NULL, enrollment BLOB NOT NULL,
                    capture BLOB NOT NULL, epoch_id TEXT NOT NULL, registration_id TEXT,
                    state TEXT NOT NULL, native_id TEXT, journal TEXT, binding BLOB);
                CREATE UNIQUE INDEX IF NOT EXISTS managed_native_capture
                    ON launches(product,native_id) WHERE native_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS ordinary_sessions(
                    product TEXT NOT NULL,native_id TEXT NOT NULL,
                    PRIMARY KEY(product,native_id));
            """)
        descriptor = os.open(
            marker, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        os.close(descriptor)
        _private(marker)
        sync_directory(self.directory)

    def _enrollment(self):
        return canonical(
            {
                "server_url": self.config["server_url"].rstrip("/"),
                "sensor_id": self.config["sensor_id"],
            }
        )

    def _same_enrollment(self, row):
        if bytes(row["enrollment"]) != self._enrollment():
            return False
        tenant = self.config.get("tenant_id")
        bound_tenant = (
            json.loads(row["binding"])["tenant_id"] if row["binding"] else None
        )
        return not tenant or not bound_tenant or tenant == bound_tenant

    @contextmanager
    def _db(self):
        _private(self.path)
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA synchronous=FULL")
            with conn:
                yield conn
        finally:
            conn.close()

    def _lock(self, product, exclusive=False):
        path = self.directory / (product + ".startup.lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            _private(path)
            if os.name == "nt":
                import msvcrt

                os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(
                    fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
                )
            return fd
        except BaseException:
            os.close(fd)
            raise

    def begin(self, product, capture, epoch_id, registration_id=None):
        if product not in PRODUCTS:
            raise CaptureDeferred("unsupported_product")
        for key in (
            "prompt_text",
            "response_text",
            "tool_input",
            "tool_output",
            "raw",
            "redact",
        ):
            if type(capture.get(key)) is not bool:
                raise CaptureDeferred("invalid_capture_settings")
        if (
            type(capture.get("max_text_bytes")) is not int
            or capture["max_text_bytes"] < 1
        ):
            raise CaptureDeferred("invalid_capture_settings")
        epoch_id = str(uuid.UUID(epoch_id))
        registration_id = str(uuid.UUID(registration_id)) if registration_id else None
        try:
            fd = self._lock(product, exclusive=True)
        except BlockingIOError:
            raise CaptureDeferred("managed_start_in_progress") from None
        try:
            ident = str(uuid.uuid4())
            with self._db() as conn:
                # A dead launcher cannot let its unidentified history become ordinary.
                conn.execute(
                    "UPDATE launches SET state='interrupted' WHERE product=? AND state='starting'",
                    (product,),
                )
                conn.execute(
                    "INSERT INTO launches(id,product,enrollment,capture,epoch_id,registration_id,state) VALUES(?,?,?,?,?,?,'starting')",
                    (
                        ident,
                        product,
                        self._enrollment(),
                        canonical(capture),
                        epoch_id,
                        registration_id,
                    ),
                )
            return LaunchCapture(self, ident, fd)
        except BaseException:
            os.close(fd)
            raise

    def _route(self, conn, product, native_id, launch_id=None):
        if launch_id:
            try:
                launch_id = str(uuid.UUID(launch_id))
            except (ValueError, TypeError, AttributeError):
                raise CaptureDeferred("invalid_managed_launch") from None
            row = conn.execute(
                "SELECT * FROM launches WHERE id=?", (launch_id,)
            ).fetchone()
            if row is None or product not in (row["product"], "unknown"):
                raise CaptureDeferred("managed_launch_unavailable")
            if row["native_id"] and native_id and row["native_id"] != native_id:
                # Inherited native telemetry can identify a nested session. Keep
                # its captured record locally without claiming the main tuple.
                return dict(row, registration_id=None, state="local_only")
            return dict(row)
        row = conn.execute(
            "SELECT * FROM launches WHERE product=? AND native_id=?",
            (product, native_id),
        ).fetchone()
        if row is not None:
            return dict(row)
        if product not in PRODUCTS:
            return None
        known = (
            native_id
            and conn.execute(
                "SELECT 1 FROM ordinary_sessions WHERE product=? AND native_id=?",
                (product, native_id),
            ).fetchone()
        )
        if (
            not known
            and conn.execute(
                "SELECT 1 FROM launches WHERE product=? AND state IN ('starting','interrupted') LIMIT 1",
                (product,),
            ).fetchone()
        ):
            raise CaptureDeferred()
        if native_id:
            conn.execute(
                "INSERT OR IGNORE INTO ordinary_sessions VALUES(?,?)",
                (product, native_id),
            )
        return None

    def route(self, product, native_id, launch_id=None):
        with self._db() as conn:
            return self._route(conn, product, native_id, launch_id)

    def project_metadata_allowed(self, product, native_id, parent_id=None):
        # Recovery has no registration envelope. Never export a managed session
        # or its child through the ordinary heartbeat path.
        with self._db() as conn:
            return not conn.execute(
                """SELECT 1 FROM launches WHERE product=? AND (
                       native_id IN (?,?) OR (state IN ('starting','interrupted')
                       AND NOT EXISTS (SELECT 1 FROM ordinary_sessions
                                       WHERE product=? AND native_id=?))) LIMIT 1""",
                (product, native_id, parent_id, product, native_id),
            ).fetchone()

    def export_allowed(self, launch_id, native_id=None):
        if not launch_id:
            return True
        with self._db() as conn:
            row = conn.execute(
                "SELECT * FROM launches WHERE id=?", (launch_id,)
            ).fetchone()
            return bool(
                row
                and row["state"] == "verified"
                and self._same_enrollment(row)
                and (native_id is None or row["native_id"] == native_id)
            )

    def export_registration(self, launch_id, native_id):
        if not launch_id or not native_id:
            return None
        with self._db() as conn:
            row = conn.execute(
                "SELECT * FROM launches WHERE id=?", (launch_id,)
            ).fetchone()
            if (
                row
                and row["state"] == "verified"
                and row["native_id"] == native_id
                and self._same_enrollment(row)
            ):
                return row["registration_id"]
        return None

    def _child(self, conn, event):
        session = event.get("session", {})
        parent_id = session.get("parent_id")
        if (
            event.get("agent", {}).get("product") != "codex-cli"
            or not isinstance(parent_id, str)
            or not parent_id
        ):
            return None
        parent = conn.execute(
            "SELECT * FROM launches WHERE product='codex-cli' AND native_id=?",
            (parent_id,),
        ).fetchone()
        if parent is None or not parent["binding"]:
            return None
        parent_binding = json.loads(parent["binding"])
        epoch = str(
            uuid.uuid5(
                uuid.UUID(parent_binding["epoch_id"]), "native-child:" + session["id"]
            )
        )
        binding = dict(
            parent_binding,
            session_id=session["id"],
            registration_id=None,
            epoch_id=epoch,
        )
        directory = self.directory / epoch
        journal = Journal(directory, binding)
        try:
            with journal.transaction() as child:
                if not child.execute(
                    "SELECT 1 FROM metadata WHERE key='capture_parent'"
                ).fetchone():
                    child.execute(
                        "INSERT INTO metadata VALUES('capture_parent',?)",
                        (canonical(parent["id"]),),
                    )
                    Journal._enqueue(
                        child,
                        None,
                        {
                            "kind": "gap",
                            "gaps": ["unverified_history", "unsupported_boundary"],
                        },
                    )
        finally:
            journal.close()
        conn.execute(
            "INSERT INTO launches(id,product,enrollment,capture,epoch_id,state,native_id,journal,binding) VALUES(?,'codex-cli',?,?,?,'local_only',?,?,?)",
            (
                epoch,
                parent["enrollment"],
                parent["capture"],
                epoch,
                session["id"],
                str(directory),
                canonical(binding),
            ),
        )
        return dict(
            conn.execute("SELECT * FROM launches WHERE id=?", (epoch,)).fetchone()
        )

    def upload_allowed(self, binding):
        if not binding.get("registration_id"):
            return False
        with self._db() as conn:
            row = conn.execute(
                "SELECT * FROM launches WHERE product=? AND native_id=?",
                (binding["product"], binding["session_id"]),
            ).fetchone()
            return bool(
                row
                and row["state"] == "verified"
                and bytes(row["binding"]) == canonical(binding)
                and self._same_enrollment(row)
            )

    @staticmethod
    def _observe(row, event):
        directory = Path(row["journal"])
        _private(directory, directory=True)
        path = directory / "journal.sqlite3"
        _private(path)
        conn = sqlite3.connect(
            path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA temp_store=MEMORY")
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                binding = conn.execute(
                    "SELECT value FROM metadata WHERE key='binding'"
                ).fetchone()
                if binding is None or bytes(binding[0]) != bytes(row["binding"]):
                    raise CaptureDeferred("managed_identity_changed")
                # Collectors retry their stable source observation ID after a
                # checkpoint restart; observation time and parser gap metadata
                # can differ. Keep the first body, like ordinary event ingestion.
                # This writer never updates held actions or their payload binding.
                if conn.execute(
                    "SELECT 1 FROM observations WHERE id=?", (event["id"],)
                ).fetchone():
                    return
                # Local-only evidence remains durable after the foreground ends.
                # A late receipt never silently extends an earlier closing watermark.
                if conn.execute("SELECT 1 FROM metadata WHERE key='close'").fetchone():
                    marker = conn.execute(
                        "INSERT OR IGNORE INTO metadata VALUES('late_capture',?)",
                        (b"true",),
                    )
                    if marker.rowcount:
                        Journal._enqueue(
                            conn,
                            None,
                            {"kind": "gap", "gaps": ["unsupported_boundary"]},
                        )
                Journal._observe(conn, None, event)
        finally:
            conn.close()

    def emit(self, event, capture, append):
        """Persist before the collector advances; return whether normal upload woke."""
        product = event.get("agent", {}).get("product", "unknown")
        native_id = event.get("session", {}).get("id")
        try:
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM launches WHERE product=? AND native_id=?",
                    (product, native_id),
                ).fetchone()
                row = dict(row) if row else self._child(conn, event)
                if row is None:
                    row = self._route(conn, product, native_id)
                if row:
                    if not row["binding"]:
                        raise CaptureDeferred()
                    binding = json.loads(row["binding"])
                    event.setdefault("session", {})["registration_id"] = binding[
                        "registration_id"
                    ]
                    if binding["registration_id"] is None:
                        event["session"].pop("registration_id", None)
                    if "evidence" not in event:
                        ident = event["id"]
                        event["evidence"] = dict(
                            version=1,
                            logical_id=ident,
                            observation_id=ident,
                            stream_id="managed-capture-" + row["epoch_id"],
                            sequence=0,
                            part=0,
                            gaps=[],
                        )
                    event = _captured_observation(
                        event,
                        effective_capture(capture, json.loads(row["capture"])),
                        binding,
                    )
                    if row["state"] != "verified" or not self._same_enrollment(row):
                        self._observe(row, event)
                        return False
                else:
                    if event.get("source", {}).get("collector") == "hook" and not capture.get("tool_input"):
                        for key in ("cwd", "parent_id"):
                            event.get("session", {}).pop(key, None)
                    redact_event(event, capture)
                reason = validate_event(event)
                if reason:
                    if row:
                        raise CaptureDeferred("invalid_captured_event")
                    return False
                append(event)
                return True
        except (sqlite3.Error, JournalError) as exc:
            raise CaptureDeferred("managed_capture_unavailable") from exc


class LaunchCapture:
    def __init__(self, coordinator, ident, fd):
        self.coordinator, self.id, self.fd = coordinator, ident, fd

    def environment(self, environment):
        result = dict(environment)
        attrs = result.get("OTEL_RESOURCE_ATTRIBUTES", "")
        parts = [
            part
            for part in attrs.split(",")
            if part.split("=", 1)[0].strip() != LAUNCH_ATTRIBUTE
        ]
        result["OTEL_RESOURCE_ATTRIBUTES"] = ",".join(
            [part for part in parts if part] + [LAUNCH_ATTRIBUTE + "=" + self.id]
        )
        result["OPENAIDR_MANAGED_LAUNCH_ID"] = self.id
        return result

    def publish(self, journal):
        binding = journal.binding
        with self.coordinator._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM launches WHERE id=?", (self.id,)
            ).fetchone()
            if (
                row["state"] != "starting"
                or row["product"] != binding["product"]
                or row["epoch_id"] != binding["epoch_id"]
                or row["registration_id"] != binding["registration_id"]
                or (
                    self.coordinator.config.get("tenant_id")
                    and binding["tenant_id"] != self.coordinator.config["tenant_id"]
                )
                or bytes(row["enrollment"])
                != canonical({key: binding[key] for key in ("server_url", "sensor_id")})
            ):
                raise CaptureDeferred("managed_identity_changed")
            if conn.execute(
                "SELECT 1 FROM ordinary_sessions WHERE product=? AND native_id=?",
                (binding["product"], binding["session_id"]),
            ).fetchone():
                raise CaptureDeferred("native_session_already_observed")
            conn.execute(
                "UPDATE launches SET native_id=?,journal=?,binding=?,state=? WHERE id=?",
                (
                    binding["session_id"],
                    str(journal.directory),
                    canonical(binding),
                    "pending" if binding["registration_id"] else "local_only",
                    self.id,
                ),
            )
        self._unlock()

    def verify(self, status):
        with self.coordinator._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM launches WHERE id=?", (self.id,)
            ).fetchone()
            if (
                row["state"] not in ("pending", "verified")
                or status.get("status") != "verified"
                or status.get("id") != row["registration_id"]
                or status.get("external_id") != row["native_id"]
                or status.get("product") != row["product"]
                or status.get("delivery_epoch") != row["epoch_id"]
            ):
                raise CaptureDeferred("managed_registration_unavailable")
            conn.execute("UPDATE launches SET state='verified' WHERE id=?", (self.id,))

    def abandon(self):
        with self.coordinator._db() as conn:
            conn.execute(
                "UPDATE launches SET state='local_only' WHERE id=? AND state='pending'",
                (self.id,),
            )

    def _unlock(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def end(self, started=True):
        try:
            with self.coordinator._db() as conn:
                if not started:
                    # Preflight failed before a native producer could exist.
                    # No unknown session remains to justify a collection hold.
                    conn.execute(
                        "DELETE FROM launches WHERE id=? AND state='starting' AND native_id IS NULL",
                        (self.id,),
                    )
                    return ()
                result = conn.execute(
                    "UPDATE launches SET state='interrupted' WHERE id=? AND state='starting'",
                    (self.id,),
                )
                return ("unsupported_boundary",) if result.rowcount else ()
        finally:
            self._unlock()
