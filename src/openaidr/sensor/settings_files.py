"""Cooperating settings writers serialize, and detect edits by other programs."""

from contextlib import ExitStack
import hashlib
from pathlib import Path

from openaidr.core.files import ConcurrentFileChange, atomic_write, file_content, sync_directory
from .config import configuration_lock


class PartialSettingsUpdate(OSError):
    """An input changed after an earlier file was already published."""


def content_hash(content):
    return hashlib.sha256(content).hexdigest() if content is not None else None


def publication_state(before, after, current, *, unpublished=False):
    """Classify a recorded write without inferring ownership from a single field."""
    if unpublished or current == before:
        return "before"
    if current == after:
        return "after"
    return None


class SettingsFiles:
    def __init__(self, paths):
        self.original = {path: file_content(path) for path in paths}
        self.pending = {}

    def text(self, path):
        return (self.content(path) or b"").decode("utf-8")

    def content(self, path):
        return self.original[Path(path).expanduser().resolve()]

    def write(self, path, text):
        path = Path(path).expanduser().resolve()
        if path not in self.original:
            raise ValueError(f"Settings target was not locked: {path}")
        self.pending[path] = text

    def delete(self, path):
        self.write(path, None)

    def commit(self):
        # Check every input before the first publication, including read-only
        # inputs. External editors do not take our advisory locks.
        for path, original in self.original.items():
            if file_content(path) != original:
                raise ConcurrentFileChange(f"{path} changed during setup; retry the operation")
        published = False
        for path, text in self.pending.items():
            try:
                if text is None:
                    if file_content(path) != self.original[path]:
                        raise ConcurrentFileChange(f"{path} changed during setup; retry the operation")
                    path.unlink(missing_ok=True)
                    sync_directory(path.parent)
                else:
                    atomic_write(path, text, expected=self.original[path])
            except ConcurrentFileChange as exc:
                if published:
                    # Replaying positional Codex trust changes after a partial
                    # write can move the user's trust twice. Stop visibly.
                    raise PartialSettingsUpdate(f"Settings changed after a partial update; inspect {path} and retry") from exc
                raise
            published = True


def _edit_locked(paths, update):
    for attempt in range(3):
        files = SettingsFiles(paths)
        result = update(files)
        try:
            files.commit()
            return result
        except ConcurrentFileChange:
            if attempt == 2:
                raise


def edit_settings(paths, update, *, recover=None, complete=None):
    """Apply a fresh read/modify/write under each canonical target's lock.

    Locks fail on contention instead of waiting while a caller may hold the
    sensor config lock. Keep the lock files: deleting one can split its inode
    between two writers. Changes seen before publication are recomputed.
    """
    paths = sorted({Path(path).expanduser().resolve() for path in paths})
    with ExitStack() as stack:
        for path in paths:
            try:
                stack.enter_context(configuration_lock(path))
            except BlockingIOError as exc:
                raise OSError(f"{path} is being updated by another OpenAIDR process; retry the operation") from exc
        if recover:
            _edit_locked(paths, recover)
        result = _edit_locked(paths, update)
        if complete:
            _edit_locked(paths, lambda files: complete(files, result))
        return result
