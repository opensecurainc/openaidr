"""Loopback OTLP receiver and crash-safe, bounded export delivery."""

import copy
import ipaddress
import json
import logging
import os
import random
import hashlib
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import httpx

from .config import TELEMETRY_PORT, default_listen
from .tls import client_options
from .local_http import LoopbackHTTPServer, loopback_host
from . import usage
from .capture import (
    CaptureCoordinator,
    CaptureDeferred,
    LAUNCH_ATTRIBUTE,
    REGISTRATION_ATTRIBUTE,
    effective_capture,
)

from openaidr.core.telemetry import (
    MAX_BODY_BYTES,
    CAPTURE_GAPS_ATTRIBUTE,
    SIGNALS as OTLP_SIGNALS,
    TelemetryError,
    error_bytes,
    media_type,
    count_records,
    decode_export,
    encode_export,
    response_bytes,
    scrub_export,
    attributes,
    records as export_records,
)

SIGNALS = ("logs", "metrics", "traces")
MAX_REQUEST_BYTES = MAX_BODY_BYTES


def token_fingerprint(token):
    """Non-secret identifier of the control token, so a rotation shows in status."""
    return hashlib.sha256(str(token or "").encode()).hexdigest()[:16]


def settings(config, persist_token=False):
    options = dict(config.get("telemetry") or {})
    options.setdefault("enabled", True)
    options.setdefault("listen", default_listen(TELEMETRY_PORT))
    options.setdefault("max_queue_bytes", 512 << 20)
    # These gates affect native OTLP exports only. Hook and transcript events
    # use the separate capture.* settings in runtime.py. Native prompt content
    # defaults off; tool details (commands, paths, URLs) default on for detection.
    # Secret-looking keys are still redacted and raw API bodies never forwarded.
    options.setdefault("capture_prompts", False)
    options.setdefault("capture_tool_details", True)
    saved = dict(config.get("telemetry") or {})
    if persist_token and not options.get("local_token"):
        # Persist the generated token. Defaults stay implicit in the YAML
        # so upgraded sensors pick up new defaults instead of a frozen copy.
        options["local_token"] = saved["local_token"] = secrets.token_urlsafe(32)
    if persist_token and os.name == "nt" and "listen" not in saved:
        # Except the per-account Windows port: it derives from the account's
        # environment, which a Scheduled Task's process need not share, and
        # the receiver and the agents' settings must use one port.
        saved["listen"] = options["listen"]
    if saved != (config.get("telemetry") or {}):
        config["telemetry"] = saved
        config.save()
    return options


class QueueFull(Exception):
    pass


class ExportQueue:
    """Retained exports survive restarts; capacity exhaustion rejects new input."""

    def __init__(self, path, max_bytes=512 << 20, *, usage_scope=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_bytes = max(4096, int(max_bytes))
        self.usage_scope = usage_scope
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        if os.name != "nt":
            self.path.chmod(0o600)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        # Bound database allocation as well as queued payloads. The allowance
        # covers indexes, metadata, and the currently committing request.
        allowance = usage.STORAGE_ALLOWANCE if usage_scope else 0
        pages = max(64, (self.max_bytes + MAX_REQUEST_BYTES + allowance) // 4096)
        self.db.execute(f"PRAGMA max_page_count={pages}")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS exports (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              batch_id TEXT NOT NULL UNIQUE,
              signal TEXT NOT NULL,
              content_type TEXT NOT NULL,
              body BLOB NOT NULL,
              records INTEGER NOT NULL,
              created_at REAL NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,
              next_attempt REAL NOT NULL DEFAULT 0,
              last_error TEXT NOT NULL DEFAULT ''
            );
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(exports)")}
        for name in ("managed_launch", "managed_session"):
            if name not in columns:
                self.db.execute(f"ALTER TABLE exports ADD COLUMN {name} TEXT")
        # Older sensors queued traces, including delayed and managed exports.
        # Discard them before delivery or usage recovery can read the backlog.
        self.db.execute("DELETE FROM exports WHERE signal='traces'")
        if usage_scope:
            usage.initialize(self.db, usage_scope)
            usage.prune(self.db)
        self.db.commit()
        self.db.row_factory = sqlite3.Row

    def append(self, signal, body, content_type, records):
        return self.append_many(
            [dict(signal=signal, body=body, content_type=content_type, records=records)]
        )[0]

    def append_many(self, exports):
        batch_ids = [str(uuid.uuid4()) for _ in exports]
        with self.lock:
            try:
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    used = self.db.execute(
                        "SELECT COALESCE(SUM(length(body)),0) FROM exports"
                    ).fetchone()[0]
                    if (
                        used + sum(len(item["body"]) for item in exports)
                        > self.max_bytes
                    ):
                        raise QueueFull("telemetry queue is full; retry later")
                    self.db.executemany(
                        "INSERT INTO exports(batch_id,signal,content_type,body,records,created_at,managed_launch,managed_session) VALUES(?,?,?,?,?,?,?,?)",
                        [
                            (
                                ident,
                                item["signal"],
                                item["content_type"],
                                item["body"],
                                item["records"],
                                time.time(),
                                item.get("managed_launch"),
                                item.get("managed_session"),
                            )
                            for ident, item in zip(batch_ids, exports)
                        ],
                    )
                    if self.usage_scope:
                        for batch_id in batch_ids:
                            usage.record(self.db, self.usage_scope, self.db.execute(
                                "SELECT * FROM exports WHERE batch_id=?", (batch_id,),
                            ).fetchone())
                        usage.prune(self.db)
            except sqlite3.OperationalError as exc:
                if "full" in str(exc).lower():
                    raise QueueFull("telemetry queue storage is full") from exc
                raise
        return batch_ids

    def next(self, eligible=lambda launch_id, native_id: launch_id is None):
        with self.lock:
            after = 0
            while rows := self.db.execute(
                "SELECT seq,managed_launch,managed_session FROM exports WHERE next_attempt<=? AND seq>? ORDER BY seq LIMIT 100",
                (time.time(), after),
            ).fetchall():
                for row in rows:
                    if eligible(row["managed_launch"], row["managed_session"]):
                        export = dict(
                            self.db.execute(
                                "SELECT * FROM exports WHERE seq=?", (row["seq"],)
                            ).fetchone()
                        )
                        if self.usage_scope and export["usage_projected"] < usage.PROJECTION_VERSION:
                            with self.db:
                                usage.record(self.db, self.usage_scope, export)
                                usage.prune(self.db)
                        return export
                after = rows[-1]["seq"]
            return None

    def confirm(self, batch_id):
        with self.lock, self.db:
            self.db.execute("DELETE FROM exports WHERE batch_id=?", (batch_id,))

    def retry(self, batch_id, error, delay=None):
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT attempts FROM exports WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if row is None:
                return
            attempts = row[0] + 1
            if delay is None:
                base = min(300, 2 ** min(attempts - 1, 9))
                delay = base + random.random() * base / 5
            self.db.execute(
                "UPDATE exports SET attempts=?, next_attempt=?, last_error=? WHERE batch_id=?",
                (attempts, time.time() + delay, str(error)[:1000], batch_id),
            )

    def status(self):
        # Usage import and ingestion share the writer lock. Status must not
        # wait for that work or make the desktop restart a healthy sensor.
        try:
            with closing(sqlite3.connect(
                self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.1,
            )) as db, db:
                db.execute("BEGIN")
                row = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(body)),0),COALESCE(SUM(records),0) FROM exports"
                ).fetchone()
                error = db.execute(
                    "SELECT last_error FROM exports WHERE last_error<>'' ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                return {
                    "queue_depth": row[0],
                    "queue_bytes": row[1],
                    "queued_records": row[2],
                    "max_queue_bytes": self.max_bytes,
                    "last_error": error[0] if error else "",
                }
        except sqlite3.OperationalError as exc:
            if (exc.sqlite_errorcode & 0xff) not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise
            return dict(queue_depth=None, queue_bytes=None, queued_records=None,
                        max_queue_bytes=self.max_bytes, last_error=None)

    def close(self):
        with self.lock:
            self.db.close()


def partial_rejection(signal, response):
    """OTLP partial-success means some records were rejected, so retain export."""
    if response.status_code != 200:
        raise ValueError("remote OTLP endpoint did not return HTTP 200")
    content_type = (
        response.headers.get("content-type", "").split(";")[0].strip().lower()
    )
    if content_type not in ("application/json", "application/x-protobuf"):
        raise ValueError("remote endpoint returned a non-OTLP content type")
    if content_type == "application/json":
        payload = response.json()
        if not isinstance(payload, dict) or set(payload) - {
            "partialSuccess",
            "partial_success",
        }:
            raise ValueError("remote endpoint returned an invalid OTLP response")
        partial = payload.get("partialSuccess", payload.get("partial_success", {}))
        return any(
            int(partial.get(key, 0) or 0) > 0
            for key in (
                "rejectedLogRecords",
                "rejectedSpans",
                "rejectedDataPoints",
                "rejected_log_records",
                "rejected_spans",
                "rejected_data_points",
            )
        )
    if content_type in ("application/x-protobuf", "application/protobuf"):
        from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
            ExportLogsServiceResponse,
        )
        from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
            ExportMetricsServiceResponse,
        )
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceResponse,
        )

        message = {
            "logs": ExportLogsServiceResponse,
            "metrics": ExportMetricsServiceResponse,
            "traces": ExportTraceServiceResponse,
        }[signal]()
        message.ParseFromString(response.content)
        partial = message.partial_success
        return bool(
            getattr(
                partial,
                {
                    "logs": "rejected_log_records",
                    "metrics": "rejected_data_points",
                    "traces": "rejected_spans",
                }[signal],
            )
        )
    return False


def _partition(signal, payload, coordinator):
    """Keep native records whole while separating independently held sessions."""
    resources, scopes, items = OTLP_SIGNALS[signal][2:]
    groups = {}

    def remove_registration(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "attributes" and isinstance(child, list):
                    value[key] = [
                        item
                        for item in child
                        if item.get("key")
                        not in (REGISTRATION_ATTRIBUTE, CAPTURE_GAPS_ATTRIBUTE)
                    ]
                else:
                    remove_registration(child)
        elif isinstance(value, list):
            for child in value:
                remove_registration(child)

    for resource_index, resource in enumerate(payload.get(resources, [])):
        resource_attrs = attributes(resource.get("resource", {}).get("attributes"))
        service = str(resource_attrs.get("service.name", "")).lower()
        product = (
            "codex-cli"
            if "codex" in service
            else "claude-code"
            if "claude" in service
            else "unknown"
        )
        if not any(scope.get(items) for scope in resource.get(scopes, [])):
            # Even an empty native batch can carry content-bearing resource
            # attributes. It still belongs to its managed capture permission.
            native_id = next(
                (
                    resource_attrs.get(key)
                    for key in ("session.id", "conversation.id", "thread.id")
                    if resource_attrs.get(key)
                ),
                None,
            )
            native_id = str(native_id) if native_id else None
            row = coordinator.route(
                product, native_id, resource_attrs.get(LAUNCH_ATTRIBUTE)
            )
            key = (row["id"] if row else None, native_id if row else None)
            if key not in groups:
                groups[key] = (row, native_id if row else None, {resources: []}, {})
            header = copy.deepcopy(resource)
            remove_registration(header)
            groups[key][2][resources].append(header)
            continue
        for scope_index, scope in enumerate(resource.get(scopes, [])):
            for item in scope.get(items, []):
                units = [(item, item)]
                if signal == "metrics":
                    units = []
                    for kind in (
                        "gauge",
                        "sum",
                        "histogram",
                        "exponentialHistogram",
                        "summary",
                    ):
                        for point in item.get(kind, {}).get("dataPoints", []):
                            unit = copy.deepcopy(item)
                            unit[kind]["dataPoints"] = [copy.deepcopy(point)]
                            units.append((unit, unit[kind]["dataPoints"][0]))
                    if not units:
                        units = [(item, {})]
                for unit, attributed in units:
                    attrs = attributes(attributed.get("attributes"))
                    native_id = next(
                        (
                            attrs.get(key) or resource_attrs.get(key)
                            for key in ("session.id", "conversation.id", "thread.id")
                            if attrs.get(key) or resource_attrs.get(key)
                        ),
                        None,
                    )
                    native_id = str(native_id) if native_id else None
                    launch_id = attrs.get(LAUNCH_ATTRIBUTE) or resource_attrs.get(
                        LAUNCH_ATTRIBUTE
                    )
                    row = coordinator.route(product, native_id, launch_id)
                    key = (row["id"] if row else None, native_id if row else None)
                    if key not in groups:
                        groups[key] = (
                            row,
                            native_id if row else None,
                            {resources: []},
                            {},
                        )
                    _, _, grouped, indexes = groups[key]
                    location = (resource_index, scope_index)
                    if location not in indexes:
                        header = copy.deepcopy(resource)
                        header[scopes] = [copy.deepcopy(scope)]
                        header[scopes][0][items] = []
                        remove_registration(header)
                        grouped[resources].append(header)
                        indexes[location] = header[scopes][0][items]
                    captured = copy.deepcopy(unit)
                    remove_registration(captured)
                    if row and row["registration_id"] and row["native_id"] == native_id:
                        tagged = captured
                        if signal == "metrics":
                            tagged = next(
                                (
                                    captured[kind]["dataPoints"][0]
                                    for kind in (
                                        "gauge",
                                        "sum",
                                        "histogram",
                                        "exponentialHistogram",
                                        "summary",
                                    )
                                    if captured.get(kind, {}).get("dataPoints")
                                ),
                                None,
                            )
                        if tagged is not None:
                            tagged.setdefault("attributes", []).append(
                                {
                                    "key": REGISTRATION_ATTRIBUTE,
                                    "value": {"stringValue": row["registration_id"]},
                                }
                            )
                    indexes[location].append(captured)
    return [value[:3] for value in groups.values()] or [
        (None, None, copy.deepcopy(payload))
    ]


class Telemetry:
    def __init__(
        self,
        config,
        *,
        on_auth_failure=None,
        paused=lambda: False,
        capture=None,
        coordinator=None,
    ):
        self.config = config
        self.http_lock = threading.RLock()
        self.on_auth_failure, self.paused = on_auth_failure, paused
        self.auth_denied = False
        self.credential_generation = config.get("credential_generation")
        transport = client_options(config)
        self.headers = transport.pop("headers")
        self.options = settings(config, persist_token=True)
        self.coordinator = coordinator or CaptureCoordinator(config)
        self.capture = capture
        self.queue = ExportQueue(
            Path(config["data_dir"]) / "telemetry.sqlite3",
            self.options["max_queue_bytes"],
            usage_scope=usage.local_identity(config),
        )
        self.http = httpx.Client(timeout=30, **transport)
        self.received = 0
        self.forwarded = 0
        self.processed_locally = 0
        self.last_forwarded_at = None
        self.wake = threading.Event()
        self.bound_address = None

    def status(self):
        return dict(
            self.queue.status(),
            enabled=self.options["enabled"],
            listen=self.options["listen"],
            listening=self.bound_address is not None,
            received=self.received,
            forwarded=self.forwarded,
            processed_locally=self.processed_locally,
            last_forwarded_at=self.last_forwarded_at,
            capture_prompts=self.options["capture_prompts"],
            capture_tool_details=self.options["capture_tool_details"],
            token_fingerprint=token_fingerprint(self.options.get("local_token")),
        )

    def estimate_hooks(self, events):
        try:
            from .hook_estimates import collect
            collect(self, events)
        except Exception:
            # Accounting must not delay action delivery or affect hook decisions.
            return

    def accept(self, signal, body, content_type, content_encoding=""):
        payload = decode_export(signal, body, content_type, content_encoding)
        # Keep supported per-request accounting as logs, then discard raw
        # traces, including content and parent totals that repeat usage.
        if signal == "traces":
            from openaidr.core.copilot_telemetry import request_logs as copilot_requests
            from openaidr.core.hermes_telemetry import request_logs as hermes_requests
            from openaidr.core.workbuddy_telemetry import request_logs as workbuddy_requests

            payload = {"resourceLogs": [*copilot_requests(payload)["resourceLogs"],
                                        *hermes_requests(payload)["resourceLogs"],
                                        *workbuddy_requests(payload)["resourceLogs"]]}
            if not payload["resourceLogs"]:
                return None
            signal = "logs"
        try:
            groups = _partition(signal, payload, self.coordinator)
        except CaptureDeferred:
            raise TelemetryError(
                "managed capture is not yet available; retry later", 503
            ) from None
        exports = []
        for row, native_id, group in groups:
            capture = None
            if row:
                capture = json.loads(row["capture"])
                if self.capture is not None:
                    capture = effective_capture(self.capture(), capture)
            clean = scrub_export(
                signal,
                group,
                capture_prompts=self.options["capture_prompts"],
                capture_tool_details=self.options["capture_tool_details"],
                capture=capture,
            )
            exports.append(
                dict(
                    signal=signal,
                    body=encode_export(signal, clean, content_type),
                    content_type=content_type,
                    records=count_records(signal, clean),
                    managed_launch=row["id"] if row else None,
                    managed_session=native_id,
                )
            )
        if sum(len(item["body"]) for item in exports) > MAX_REQUEST_BYTES:
            raise TelemetryError("normalized export exceeds the size limit", 413)
        batch_ids = self.queue.append_many(exports)
        self.received += sum(item["records"] for item in exports)
        self.wake.set()
        return batch_ids[0]

    def forward_once(self):
        if self.config.get("auth_mode") == "mtls" and (
            self.auth_denied or self.paused()
        ):
            return False
        export = self.queue.next(self.coordinator.export_allowed)
        if export is None:
            return False
        if self.config.get("connection_mode") in ("free", "api_key"):
            # next() projects retained exports into local usage before release.
            self.queue.confirm(export["batch_id"])
            self.processed_locally += export["records"]
            return True
        try:
            body = export["body"]
            registration = self.coordinator.export_registration(
                export["managed_launch"], export["managed_session"]
            )
            if registration:
                # Early startup exports were captured before native identity was
                # published. This immutable binding supplies the same tag on
                # every delivery retry, without rewriting retained native bytes.
                payload = decode_export(export["signal"], body, export["content_type"])
                for _, _, item in export_records(export["signal"], payload):
                    targets = [item]
                    if export["signal"] == "metrics":
                        targets = [
                            point
                            for kind in (
                                "gauge",
                                "sum",
                                "histogram",
                                "exponentialHistogram",
                                "summary",
                            )
                            for point in item.get(kind, {}).get("dataPoints", [])
                        ]
                    for target in targets:
                        target["attributes"] = [
                            value
                            for value in target.get("attributes", [])
                            if value.get("key") != REGISTRATION_ATTRIBUTE
                        ]
                        target["attributes"].append(
                            {
                                "key": REGISTRATION_ATTRIBUTE,
                                "value": {"stringValue": registration},
                            }
                        )
                body = encode_export(export["signal"], payload, export["content_type"])
            with self.http_lock:
                from .uploads import post

                response = post(
                    self.http,
                    self.config["server_url"].rstrip("/")
                    + "/otlp/v1/"
                    + export["signal"],
                    content=body,
                    chunk_url=self.config["server_url"].rstrip("/") + "/ingest/v1/uploads/otlp/" + export["signal"],
                    headers={
                        **self.headers,
                        "Content-Type": export["content_type"],
                        "X-OpenAIDR-Batch-Id": export["batch_id"],
                    },
                )
            if self.config.get("auth_mode") == "mtls" and response.status_code in (
                401,
                403,
            ):
                self.auth_denied = True
                if self.on_auth_failure:
                    self.on_auth_failure()
            response.raise_for_status()
            response_type = (
                response.headers.get("content-type", "").split(";")[0].strip().lower()
            )
            if response_type != export["content_type"]:
                raise ValueError(
                    "remote OTLP response content type does not match export"
                )
            if partial_rejection(export["signal"], response):
                raise ValueError("remote OTLP endpoint rejected part of the export")
            self.queue.confirm(export["batch_id"])
            self.forwarded += export["records"]
            self.last_forwarded_at = time.time()
        except Exception as exc:
            self.queue.retry(export["batch_id"], exc)
            logging.warning("telemetry export retained for retry: %s", exc)
        return True

    def refresh(self):
        transport = client_options(self.config)
        headers = transport.pop("headers")
        replacement = httpx.Client(timeout=30, **transport)
        with self.http_lock:
            previous = self.http
            self.http, self.headers = replacement, headers
            self.credential_generation = self.config.get("credential_generation")
            previous.close()

    def import_usage(self, stop, *, watch=False):
        from .usage_import import run
        run(self.config, self.queue, stop, self.paused, watch=watch)

    def forward(self, stop):
        while not stop.is_set():
            if not self.forward_once():
                self.wake.wait(0.5)
                self.wake.clear()

    def receive(self, stop):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def do_POST(self):
                if "Origin" in self.headers or not loopback_host(
                    self.headers.get("Host"), self.server.server_port
                ):
                    return self.reply(403, b"forbidden", "text/plain")
                signal = self.path.removeprefix("/v1/")
                if self.path != "/v1/" + signal or signal not in SIGNALS:
                    return self.reply(404, b"not found", "text/plain")
                requested_type = self.headers.get(
                    "Content-Type", "application/x-protobuf"
                )
                try:
                    content_type = media_type(requested_type)
                except TelemetryError:
                    return self.reply(
                        415,
                        error_bytes(3, "unsupported content type", "application/json"),
                        "application/json",
                    )
                try:
                    if self.headers.get("Transfer-Encoding"):
                        return self.reply(
                            400,
                            error_bytes(3, "Content-Length is required", content_type),
                            content_type,
                        )
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > MAX_REQUEST_BYTES:
                        return self.reply(
                            413,
                            error_bytes(8, "request too large", content_type),
                            content_type,
                        )
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete request body")
                    owner.accept(
                        signal,
                        body,
                        content_type,
                        self.headers.get("Content-Encoding", ""),
                    )
                    self.reply(200, response_bytes(signal, content_type), content_type)
                except QueueFull as exc:
                    self.reply(
                        503, error_bytes(8, str(exc), content_type), content_type
                    )
                except TelemetryError as exc:
                    self.reply(
                        exc.status, error_bytes(3, str(exc), content_type), content_type
                    )
                except (ValueError, TypeError, KeyError) as exc:
                    self.reply(
                        400, error_bytes(3, str(exc), content_type), content_type
                    )
                except Exception:
                    logging.exception("telemetry receiver failed to persist export")
                    self.reply(
                        503,
                        error_bytes(
                            14, "export not accepted; retry later", content_type
                        ),
                        content_type,
                    )

            def reply(self, code, body, content_type):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                if code == 503:
                    self.send_header("Retry-After", "5")
                self.end_headers()
                self.wfile.write(body)

        host, port = self.options["listen"].rsplit(":", 1)
        host = host.strip("[]")

        class Server(LoopbackHTTPServer):
            daemon_threads = False

        server = Server((host, int(port)), Handler)
        self.bound_address = server.server_address
        server.timeout = 0.25
        try:
            while not stop.is_set():
                server.handle_request()
        finally:
            self.bound_address = None
            server.server_close()

    def close(self):
        self.http.close()
        self.queue.close()
