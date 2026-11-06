"""Temporary worker bridge; tenant intelligence credentials stay outside the scanner."""

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import secrets
import threading

from openaidr_api_client.validation import osv
from .config import from_env
from openaidr_api_client.client import Connection
from openaidr_api_client.clients.threat_intel import ThreatIntelClient


def configuration():
    return Connection.from_config(from_env())


@contextmanager
def provider(cfg, *, transport=None, request_id_for=None):
    connection = Connection.from_config(cfg)
    token = secrets.token_urlsafe(32)

    class Bridge:
        expires_at = None

        def retain_expiry(self, stamp):
            self.expires_at = min(self.expires_at, stamp) if self.expires_at else stamp

        async def assess(self, queries, timeout):
            options = {} if request_id_for is None else {"request_id": request_id_for(queries)}
            client = ThreatIntelClient.from_connection(connection, transport=transport)
            try:
                async with asyncio.timeout(timeout):
                    return await client.packages(queries, **options)
            finally:
                await client.aclose()

    bridge = Bridge()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *_args):
            pass

        def do_POST(self):
            status, value = 400, {"error": "Invalid intelligence request"}
            try:
                authorized = secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token)
                size = int(self.headers.get("Content-Length", "0"))
                if not authorized or self.path != "/v1/packages/check":
                    status = 403
                elif not self.headers.get("Transfer-Encoding") and 0 < size <= 64 << 10:
                    request = json.loads(self.rfile.read(size))
                    packages, timeout = request["packages"], request["timeout"]
                    if (set(request) != {"packages", "timeout"} or not isinstance(packages, list)
                            or not 1 <= len(packages) <= 25 or type(timeout) not in (int, float)
                            or not math.isfinite(timeout) or not 0 < timeout <= 30):
                        raise ValueError("Invalid request")
                    queries, indices, results = [], [], []
                    for index, item in enumerate(packages):
                        if (not isinstance(item, dict) or set(item) != {"ecosystem", "name", "version"}
                                or any(not isinstance(value, str) for value in item.values())):
                            raise ValueError("Invalid package")
                        query, _ = osv.package_query({"ecosystem": item["ecosystem"].lower(),
                                                      "identifier": item["name"], "version": item["version"]})
                        results.append({"status": "unsupported", "findings": []})
                        if query is not None:
                            queries.append(query)
                            indices.append(index)
                    if queries:
                        try:
                            assessed = asyncio.run(bridge.assess(queries, timeout))
                        except Exception:
                            assessed = [{"status": "unavailable", "findings": []} for _ in queries]
                        for index, result in zip(indices, assessed, strict=True):
                            results[index] = result
                            if result["status"] == "complete":
                                bridge.retain_expiry(result["expires_at"])
                            else:
                                bridge.retain_expiry(datetime.now(timezone.utc) + timedelta(minutes=5))
                    value, status = {"results": results}, 200
            except Exception:
                bridge.retain_expiry(datetime.now(timezone.utc) + timedelta(minutes=5))
                status, value = 502, {"error": "Intelligence assessment unavailable"}
            body = json.dumps(value, default=lambda value: value.isoformat(), allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    bridge.environment = {"OPENAIDR_SKILL_INTEL_ORIGIN": f"http://127.0.0.1:{server.server_port}",
                          "OPENAIDR_SKILL_INTEL_TOKEN": token}
    try:
        yield bridge
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
