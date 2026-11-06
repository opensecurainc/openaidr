"""Bound stdlib regex execution without sharing its GIL with the caller."""

import atexit
import multiprocessing
import os
import pickle
import queue
import signal
import socket
import struct
import threading
import time
import uuid


EVALUATION_SECONDS = 0.05
STARTUP_SECONDS = 1.0
WORKERS = 2


class EvaluationUnavailable(Exception):
    pass


def _remaining(deadline):
    seconds = deadline - time.monotonic() if deadline is not None else None
    if seconds is not None and seconds <= 0:
        raise TimeoutError
    return seconds


def _read(stream, size, deadline):
    chunks = []
    while size:
        stream.settimeout(_remaining(deadline))
        chunk = stream.recv(min(size, 65536))
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def _receive(stream, deadline=None, *, arm_timer=False):
    size = struct.unpack("!I", _read(stream, 4, deadline))[0]
    if arm_timer:
        signal.setitimer(signal.ITIMER_REAL, EVALUATION_SECONDS)
    return pickle.loads(_read(stream, size, deadline))


def _send(stream, value, deadline=None):
    payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
    stream.settimeout(_remaining(deadline))
    stream.sendall(struct.pack("!I", len(payload)) + payload)


def _expired(*_):
    raise TimeoutError


def _serve(stream):
    # Import before the startup handshake, outside the matching budget.
    from openaidr.core.policy import _evaluate_rules

    timer = os.name != "nt"
    if timer:
        # The worker also stops matching if its controller exits abruptly.
        signal.signal(signal.SIGALRM, _expired)
    try:
        _send(stream, "started")
        while True:
            try:
                rules, events = _receive(stream, arm_timer=timer)
                results = []
                for index, event in enumerate(events):
                    rule_index, error = _evaluate_rules(rules, event)
                    results.append((index, rule_index, error))
                    if error or rule_index is not None and rules[rule_index][0].get("action") == "deny":
                        break
            except TimeoutError:
                results = "timed out"
            finally:
                if timer:
                    signal.setitimer(signal.ITIMER_REAL, 0)
            _send(stream, results)
    except (EOFError, OSError):
        pass
    finally:
        stream.close()


class _Worker:
    def __init__(self):
        self.lock = threading.RLock()
        self.process = None
        self.stream = None
        self.job = None

    def stop(self):
        with self.lock:
            self._stop()

    def _stop(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if self.process is not None:
            if self.process.pid is not None:
                if self.process.is_alive():
                    try:
                        self.process.kill()
                    except ProcessLookupError:
                        pass
                self.process.join(timeout=0.05)
            if self.process.pid is None or not self.process.is_alive():
                self.process.close()
                self.process = None
        if self.job is not None:
            self.job.Close()
            self.job = None

    def start(self):
        if self.process is not None:
            if self.stream is not None and self.process.is_alive():
                return
            self.stop()
            if self.process is not None:
                raise EvaluationUnavailable("worker stopping")
        parent, child = socket.socketpair()
        self.stream = parent
        self.process = multiprocessing.get_context("spawn").Process(
            target=_serve, args=(child,), daemon=True,
        )
        deadline = time.monotonic() + STARTUP_SECONDS
        try:
            self.process.start()
        finally:
            child.close()
        if os.name == "nt":
            import win32api
            import win32con
            import win32job

            # Windows closes this handle even after abrupt controller death.
            # Never submit work until the child is assigned to the job.
            # pywin32 requires a string name; keep each worker's job distinct.
            self.job = win32job.CreateJobObject(None, f"openaidr-policy-{uuid.uuid4().hex}")
            limits = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
            limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, limits)
            process = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, self.process.pid)
            try:
                win32job.AssignProcessToJobObject(self.job, process)
            finally:
                process.Close()
        if _receive(parent, deadline) != "started":
            raise EvaluationUnavailable("worker unavailable")

    def run(self, rules, events):
        with self.lock:
            return self._run(rules, events)

    def _run(self, rules, events):
        try:
            self.start()
            deadline = time.monotonic() + EVALUATION_SECONDS
            _send(self.stream, (rules, events), deadline)
            result = _receive(self.stream, deadline)
            _remaining(deadline)
            if result == "timed out":
                raise TimeoutError
            return result
        except BaseException:
            self.stop()
            raise


class WorkerPool:
    def __init__(self):
        self.pid = os.getpid()
        self.workers = [_Worker() for _ in range(WORKERS)]
        self.available = queue.Queue()
        for worker in self.workers:
            self.available.put(worker)
        atexit.register(self.close)

    def close(self):
        if self.pid == os.getpid():
            for worker in self.workers:
                worker.stop()

    def evaluate(self, rules, events):
        try:
            worker = self.available.get(timeout=EVALUATION_SECONDS)
        except queue.Empty:
            raise EvaluationUnavailable("workers busy") from None
        try:
            return worker.run(rules, events)
        except TimeoutError:
            raise EvaluationUnavailable("evaluation or worker startup timed out") from None
        except Exception:
            raise EvaluationUnavailable("worker unavailable") from None
        finally:
            self.available.put(worker)


_pool = None
_lock = threading.Lock()


def evaluate(rules, events):
    global _pool
    with _lock:
        if _pool is None or _pool.pid != os.getpid():
            _pool = WorkerPool()
        pool = _pool
    return pool.evaluate(rules, events)
