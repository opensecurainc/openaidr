"""Bounded, process-local skill contents. Never write payloads to storage."""

import asyncio
import threading
import time

from .httpx import require


class ContentBuffer:
    MAX_BYTES = 64 << 20
    MAX_BUNDLES = 256
    TTL = 15 * 60

    def __init__(self):
        self.lock = threading.RLock()
        self.items = {}
        self.profile = None

    def prune(self):
        with self.lock:
            expired = [key for key, value in self.items.items() if value[0] <= time.monotonic()]
            for key in expired:
                del self.items[key]

    def check_capacity(self, files):
        size = sum(len(path) + len(content) for path, content in files.items())
        used = sum(item[1] for item in self.items.values())
        require(len(self.items) < self.MAX_BUNDLES and used + size <= self.MAX_BYTES,
                "skill scan buffer is full; retry upload", 429)
        return size

    async def run(self, stop):
        try:
            while not stop.is_set():
                await asyncio.to_thread(self.prune)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=15)
                except TimeoutError:
                    pass
        finally:
            with self.lock:
                self.items.clear()
