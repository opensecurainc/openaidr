"""Bounded, opt-in purge diagnostics; stdout remains the bridge response."""

import hashlib
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path


class Progress:
    def __init__(self, root):
        self.root = root
        self.operation = "validate"
        self.path = root

    def emit(self, **record):
        if os.environ.get("OPENAIDR_REMOVAL_PROGRESS") == "1":
            try:
                print("OPENAIDR_REMOVAL " + json.dumps(record), file=sys.stderr, flush=True)
            except OSError:
                pass  # Diagnostics must not prevent safe cleanup.

    def relative_path(self):
        # Arbitrary filenames can contain identities or secrets. Retain only
        # known top-level names, and hash all other components without resolving
        # symlinks or reading any file content.
        path = Path(self.path)
        if path.is_absolute():
            try:
                path = path.relative_to(self.root)
            except ValueError:
                return "outside-root"
        if ".." in path.parts:
            return "outside-root"
        known = {"data", "bin", "logs", "credentials", "sensor.yaml", "desktop-removal.json"}
        parts = [part if index == 0 and part in known else
                 "entry-" + hashlib.sha256(os.fsencode(part)).hexdigest()[:12]
                 for index, part in enumerate(path.parts[:8])]
        return "/".join(parts) or "."

    @contextmanager
    def phase(self, stage):
        started = time.monotonic()
        self.operation, self.path = "validate", self.root
        self._rmtree_failed = False
        counts = {}
        self.emit(stage=stage, event="start")
        try:
            yield counts
        except Exception as exc:
            details = {}
            if isinstance(exc, OSError):
                details = {"operation": self.operation, "path": self.relative_path(),
                           "error_type": type(exc).__name__, "errno": exc.errno}
            self.emit(stage=stage, event="failed", ms=round((time.monotonic() - started) * 1000), **details)
            if isinstance(exc, OSError):
                raise ValueError(
                    f"Local data deletion is incomplete ({stage}: {self.operation}, errno {exc.errno}). "
                    "Retry deletion. Details are in the desktop diagnostic log."
                ) from exc
            raise
        else:
            self.emit(stage=stage, event="complete", ms=round((time.monotonic() - started) * 1000), **counts)

    def rmtree_error(self, function, path, exc_info):
        # Some Python versions report a re-raised unlink error again as a
        # scandir error. Preserve the original operation and nested path.
        if not self._rmtree_failed:
            self.operation = function.__name__
            self.path = path
            self._rmtree_failed = True
        raise exc_info[1]
