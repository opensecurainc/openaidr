"""Authenticated request fragments, retained only until complete or expired."""

import asyncio
import hashlib
import re
import threading
import time

from starlette.responses import Response

from .httpx import require, uuid_param


class UploadBuffer:
    CHUNK_BYTES = 768 << 10
    MAX_BYTES = 64 << 20
    MAX_UPLOADS = 64
    MAX_PER_OWNER = 4
    TTL = 300

    def __init__(self):
        self.lock = threading.Lock()
        self.items = {}

    def prune(self):
        with self.lock:
            self._prune()

    def _prune(self):
        for key, item in list(self.items.items()):
            if item[0] <= time.monotonic():
                del self.items[key]

    def receive(self, request, owner, limit):
        """Call only after authentication and authorization for the target route."""
        values = []
        for name in ("id", "offset", "length", "sha256"):
            headers = request.headers.getlist("x-openaidr-upload-" + name)
            require(len(headers) == 1, "missing or duplicate upload header")
            values.append(headers[0])
        ident, offset, length, digest = values
        uuid_param(ident, "upload id")
        require(bool(re.fullmatch(r"[0-9]{1,8}", offset))
                and bool(re.fullmatch(r"[0-9]{1,8}", length)), "invalid upload length or offset")
        offset, length = int(offset), int(length)
        require(0 < length <= limit, "upload exceeds request size limit", 413)
        require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)), "invalid upload hash")
        chunk = request.state.body
        require(0 < len(chunk) <= self.CHUNK_BYTES, "invalid upload fragment size", 413)
        require(offset + len(chunk) <= length, "upload fragment exceeds declared length")
        metadata = (request.method, request.url.path, request.url.query, length, digest,
                    *(tuple(request.headers.getlist(name)) for name in
                      ("content-type", "content-encoding", "x-openaidr-batch-id")))
        key = (owner, ident)
        with self.lock:
            self._prune()
            item = self.items.get(key)
            if item is None:
                require(offset == 0, "upload expired or interrupted; restart upload", 409)
                require(len(self.items) < self.MAX_UPLOADS
                        and sum(value[1] for value in self.items.values()) + length <= self.MAX_BYTES
                        and sum(existing[0] == owner for existing in self.items) < self.MAX_PER_OWNER,
                        "upload capacity exhausted; retry later", 429)
                item = (time.monotonic() + self.TTL, length, metadata, bytearray())
                self.items[key] = item
            require(item[2] == metadata, "upload metadata changed; restart upload", 409)
            content = item[3]
            require(offset == len(content), "upload offset mismatch; restart upload", 409)
            content.extend(chunk)
            if len(content) < length:
                return Response(status_code=202, headers={
                    "X-OpenAIDR-Upload-Offset": str(len(content)), "Cache-Control": "no-store",
                })
            del self.items[key]
            require(hashlib.sha256(content).hexdigest() == digest, "upload hash mismatch")
            request.state.body = bytes(content)
        return None

    async def run(self, stop):
        try:
            while not stop.is_set():
                self.prune()
                try:
                    await asyncio.wait_for(stop.wait(), timeout=15)
                except TimeoutError:
                    pass
        finally:
            with self.lock:
                self.items.clear()
