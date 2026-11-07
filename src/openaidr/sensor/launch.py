"""Recovery for retained managed-session records; new sessions use installed hooks."""

import asyncio
import json
from pathlib import Path
import re
import sqlite3
import sys
import unicodedata
import uuid

from openaidr.sensor.config import Config, IDENTITY_FIELDS, configuration_lock
from openaidr.core.files import atomic_write
from openaidr.sensor.tls import client_options
from openaidr.sensor.runtime import NOT_ENROLLED
from openaidr.guardrail.backend import Backend, BackendDenied, BackendUnavailable
from openaidr.guardrail.gate import JournalDelivery
from openaidr.guardrail.journal import Journal, JournalError, _private
from .capture import CaptureCoordinator


class LaunchError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _text(value):
    """Display untrusted native text without terminal control sequences."""
    return "".join(
        char if char in "\n\t" or (
            ord(char) >= 32 and ord(char) != 127
            and unicodedata.category(char) not in ("Cf", "Cs")
        ) else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


class Console:
    def notice(self, message):
        print(_text(message), file=sys.stderr, flush=True)


def _identity(config):
    return {"server_url": config["server_url"].rstrip("/"),
            "sensor_id": config.get("sensor_id"), "tenant_id": config.get("tenant_id")}


def _authorization(config, deny=False, recover=None):
    """Fence known denial across native sessions, separately from owner grants."""
    with configuration_lock(config.path):
        current = Config.load(config.path)
        if any(current.get(key) != config.get(key) for key in IDENTITY_FIELDS):
            raise LaunchError("enrollment_changed")
        path = Path(config["data_dir"]) / "managed-authorization.json"
        identity = _identity(config)
        value = {"identity": identity, "generation": 0, "denied": False}
        try:
            _private(path)
            previous = json.loads(path.read_bytes())
            scoped = previous["identity"]
            if (scoped["server_url"] == identity["server_url"]
                and scoped["sensor_id"] == identity["sensor_id"]
                and (not scoped["tenant_id"] or not identity["tenant_id"]
                     or scoped["tenant_id"] == identity["tenant_id"])):
                if (type(previous["generation"]) is not int or previous["generation"] < 0
                    or type(previous["denied"]) is not bool):
                    raise ValueError
                value.update(generation=previous["generation"], denied=previous["denied"])
        except FileNotFoundError:
            pass
        except (OSError, KeyError, ValueError, TypeError, JournalError):
            raise LaunchError("authorization_cache_unavailable") from None
        if deny:
            value.update(generation=value["generation"] + 1, denied=True)
        elif recover is not None and value["generation"] == recover:
            value["denied"] = False
        if deny or recover is not None:
            atomic_write(path, json.dumps(value))
        return value


async def bootstrap(config):
    """Authenticate record recovery without loading or persisting policy rules."""
    authorization = await _durable_call(_authorization, config)
    backend = Backend(config, client_options=client_options(config, asynchronous=True))
    try:
        value = await backend.bootstrap()
        # Do not overwrite concurrent credential renewal or re-enrollment.
        with configuration_lock(config.path):
            current = Config.load(config.path)
            if any(current.get(key) != config.get(key) for key in IDENTITY_FIELDS):
                raise LaunchError("enrollment_changed")
            config["tenant_id"] = value["tenant_id"]
            config.save()
        recovered = await _durable_call(_authorization, config, False, authorization["generation"])
        if recovered["denied"]:
            raise BackendDenied("backend_denied")
        return backend
    except BackendDenied:
        try:
            await _durable_call(_authorization, config, True)
        finally:
            await backend.aclose()
        raise
    except BackendUnavailable:
        await backend.aclose()
        if (await _durable_call(_authorization, config))["denied"]:
            raise BackendDenied("backend_denied") from None
        raise
    except BaseException:
        await backend.aclose()
        raise


async def _durable_call(method, *args):
    # Join a cancelled durable write before recovery shuts down.
    task = asyncio.create_task(asyncio.to_thread(method, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


async def reconcile(config, product, console):
    backend = await bootstrap(config)
    delivered = retained = 0
    try:
        root = Path(config["data_dir"]) / "managed"
        coordinator = CaptureCoordinator(config)
        for directory in sorted(root.glob("*")):
            try:
                uuid.UUID(directory.name)
            except ValueError:
                continue
            _private(directory, directory=True)
            path = directory / "journal.sqlite3"
            if not path.exists():
                continue
            _private(path)
            with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as read:
                row = read.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
                if row is None:
                    raise JournalError("journal_key_unavailable")
                binding = json.loads(row[0])
            if (not binding.get("registration_id") or binding.get("product") != product
                or any(binding.get(key) != backend.identity[key] for key in ("server_url", "tenant_id", "sensor_id"))
                or not coordinator.upload_allowed(binding)):
                continue
            try:
                journal = Journal(directory, binding)
            except BlockingIOError:
                retained += 1
                continue
            try:
                async def denied():
                    await _durable_call(_authorization, config, True)

                delivery = JournalDelivery(journal, backend, on_denied=denied)
                journal.settle()
                if journal.closing() is None:
                    await delivery.close_session(reason="process_exit", boundaries=(),
                                                 gaps=("unsupported_boundary", "outcome_unreported"))
                okay = await delivery.flush()
                delivered += int(okay)
                retained += int(not okay)
            finally:
                journal.close()
    finally:
        await backend.aclose()
    console.notice(f"Reconciliation: {delivered} delivered, {retained} retained. No native action was restarted.")
    return 0 if not retained else 1


async def run(args, native_args):
    if not args.reconcile:
        print(
            "New managed sessions have been retired. Run openaidr setup with your "
            "sensor configuration, then start codex or claude normally to use installed "
            "hooks. Existing records can still be delivered with --reconcile.",
            file=sys.stderr,
        )
        return 1
    if native_args:
        raise LaunchError("native_options_not_used_by_reconciliation")
    config = Config.load(args.config)
    config.validate()
    if not config.enrolled():
        raise ValueError(NOT_ENROLLED)
    product = "codex-cli" if args.client == "codex" else "claude-code"
    return await reconcile(config, product, Console())


def main(args, native_args):
    try:
        return asyncio.run(run(args, native_args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Recovery stopped. Pending records are retained.", file=sys.stderr)
        return 130
    except Exception as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            code = "launch_failed"
        print(f"Recovery stopped: {code}. No held action will be replayed.", file=sys.stderr)
        return 1
