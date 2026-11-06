"""A temporary loopback bridge that accounts for each SkillSpector model call."""

import json
import logging
import secrets
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_REQUEST_BYTES = 1 << 20

log = logging.getLogger(__name__)


@contextmanager
def provider(client, job, *, profile=None, revision=None):
    if profile is None and revision is None:
        from .skill_llm import MODEL
        from openaidr_api_client.contracts.skills import REVISION

        profile, revision = MODEL, REVISION
    elif not isinstance(profile, str) or not isinstance(revision, str):
        raise ValueError("Incomplete scanner service profile")
    token = secrets.token_urlsafe(32)
    slots = threading.BoundedSemaphore(2)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            status, result = 400, {"error": {"message": "Invalid scan request"}}
            try:
                authorized = secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token)
                size = int(self.headers.get("Content-Length", "0"))
                path = "/v1/skills/assess"
                if not authorized or self.path != path:
                    status = 403
                elif 0 < size <= MAX_REQUEST_BYTES:
                    request = json.loads(self.rfile.read(size))
                    if not isinstance(request, dict) or set(request) != {"task", "timeout_ms"}:
                        raise ValueError("unsupported scanner task")
                    timeout_ms = request["timeout_ms"]
                    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 120000:
                        raise ValueError("unsupported scanner timeout")
                    task = {**request["task"], "revision": revision, "bundle_sha256": job["sha256"]}
                    deadline = time.monotonic() + timeout_ms / 1000
                    if not slots.acquire(timeout=timeout_ms / 1000):
                        raise TimeoutError("Scanner model queue deadline exceeded")
                    try:
                        remaining = int((deadline - time.monotonic()) * 1000)
                        if remaining <= 0:
                            raise TimeoutError("Scanner model queue deadline exceeded")
                        reply = client.post("/internal/v1/skill-scans/inference", json={
                            "sha256": job["sha256"], "lease_id": job["lease_id"], "task": task,
                            "timeout_ms": remaining}, timeout=remaining / 1000 + 5)
                        status, result = reply.status_code, reply.json()
                    finally:
                        slots.release()
            except Exception:
                status, result = 502, {"error": {"message": "Skill model analysis unavailable"}}
            payload = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        settings = {"SKILLSPECTOR_MODEL": profile, "SKILLSPECTOR_REASONING_EFFORT": "none",
                    "SKILLSPECTOR_MAX_LLM_CONCURRENCY": "2", "OPENAIDR_SKILL_MODEL_ORIGIN": origin}
        yield {"SKILLSPECTOR_PROVIDER": "openai", **settings, "OPENAI_API_KEY": token, "OPENAI_BASE_URL": origin + "/v1"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
