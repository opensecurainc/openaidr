"""Private, per-session durable state. Raw held bytes never enter SQLite."""

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
import uuid

from openaidr.core.event import EVIDENCE_GAPS, new_id
from openaidr.core.files import durable_directory, sync_directory
from openaidr.core.enrollment import validate_server_url


class JournalError(Exception):
    pass


_DELIVERY_GAPS = EVIDENCE_GAPS | {
    "backend_unavailable",
    "journal_lost",
    "unsupported_boundary",
    "unverified_history",
    "outcome_unreported",
}
_BOUNDARIES = {"prompt", "tool_call", "tool_output", "assistant_response"}
_CLOSE_REASONS = {
    "session_end",
    "process_exit",
    "user_stop",
    "client_error",
    "journal_lost",
}


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _binding(value):
    keys = {
        "server_url",
        "tenant_id",
        "sensor_id",
        "product",
        "session_id",
        "registration_id",
        "epoch_id",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise JournalError("invalid_session_binding")
    result = dict(value)
    validate_server_url(result["server_url"])
    result["server_url"] = result["server_url"].rstrip("/")
    for key in ("sensor_id", "epoch_id"):
        result[key] = str(uuid.UUID(result[key]))
    if result["tenant_id"] is None:
        if result["registration_id"] is not None:
            raise JournalError("invalid_session_binding")
    else:
        result["tenant_id"] = str(uuid.UUID(result["tenant_id"]))
    if result["registration_id"] is not None:
        result["registration_id"] = str(uuid.UUID(result["registration_id"]))
    if result["product"] not in ("codex-cli", "claude-code"):
        raise JournalError("unsupported_product")
    if (
        not isinstance(result["session_id"], str)
        or not 1 <= len(result["session_id"]) <= 256
    ):
        raise JournalError("invalid_session_binding")
    return result


def _private(path, directory=False):
    info = path.lstat()
    if os.name == "nt":
        # Windows reports every file as group- and world-accessible in
        # st_mode, so the mode test failed always and the sensor could not
        # start. These files live in the user's own %LOCALAPPDATA% profile,
        # which grants only that user and administrators; links are refused.
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
        ):
            raise JournalError("journal_not_private")
        if directory and not stat.S_ISDIR(info.st_mode):
            raise JournalError("invalid_journal_directory")
        return
    if stat.S_ISLNK(info.st_mode) or bool(info.st_mode & 0o077):
        raise JournalError("journal_not_private")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise JournalError("journal_owner_changed")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise JournalError("invalid_journal_directory")


class Journal:
    def __init__(self, directory, binding):
        self.binding = _binding(binding)
        self.directory = durable_directory(Path(directory))
        _private(self.directory, directory=True)
        self.connection = None
        self.lock_fd = None
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_path = self.directory / "journal.lock"
            previous_lock = lock_path.exists()
            self.lock_fd = os.open(lock_path, flags, 0o600)
            _private(lock_path)
            if os.name == "nt":
                import msvcrt

                os.write(self.lock_fd, b"0")
                os.lseek(self.lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(self.lock_fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.directory / "journal.sqlite3"
            existing = path.exists()
            if previous_lock and not existing:
                raise JournalError("journal_lost")
            descriptor = os.open(path, flags, 0o600)
            os.close(descriptor)
            _private(path)
            self.connection = sqlite3.connect(path, isolation_level=None)
            self.connection.row_factory = sqlite3.Row
            self.connection.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                PRAGMA secure_delete=ON;
                PRAGMA temp_store=MEMORY;
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS actions(
                    logical_id TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,commitment TEXT NOT NULL,
                    target TEXT NOT NULL,context TEXT NOT NULL,request_id TEXT NOT NULL UNIQUE,
                    local_action TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',
                    restriction TEXT NOT NULL DEFAULT '',
                    warned INTEGER NOT NULL DEFAULT 0,
                    check_id TEXT,approval_id TEXT,consume_id TEXT,release_id TEXT,
                    settings_version INTEGER,policy_version INTEGER,consume_uncertain INTEGER NOT NULL DEFAULT 0,
                    deliveries TEXT NOT NULL,
                    outcome TEXT,exit_code INTEGER,created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS deliveries(
                    logical_id TEXT NOT NULL,delivery_id TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'waiting',
                    outcome TEXT,exit_code INTEGER,reason TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(logical_id,delivery_id));
                CREATE TABLE IF NOT EXISTS outbox(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,record_id TEXT NOT NULL UNIQUE,
                    logical_id TEXT,receipt TEXT NOT NULL,event TEXT,operation TEXT,
                    acknowledged INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,payload_hash BLOB NOT NULL);
            """)
            with self.transaction() as conn:
                row = conn.execute(
                    "SELECT value FROM metadata WHERE key='binding'"
                ).fetchone()
                if row is None:
                    if existing:
                        raise JournalError("journal_key_unavailable")
                    conn.executemany(
                        "INSERT INTO metadata VALUES(?,?)",
                        (
                            ("binding", canonical(self.binding)),
                            ("hmac_key", secrets.token_bytes(32)),
                        ),
                    )
                elif bytes(row["value"]) != canonical(self.binding):
                    raise JournalError("journal_identity_changed")
            key = self.connection.execute(
                "SELECT value FROM metadata WHERE key='hmac_key'"
            ).fetchone()
            if key is None or not isinstance(key[0], bytes):
                raise JournalError("journal_key_unavailable")
            self.key = key[0]
            if len(self.key) != 32:
                raise JournalError("journal_key_unavailable")
            # The reopened file cannot recreate a lost callback. Neither a
            # previous consume nor dispatch intent is permission to retry it.
            with self.transaction() as conn:
                conn.execute("""UPDATE deliveries SET outcome='uncertain',state='uncertain',reason='restart'
                    WHERE state='dispatching' OR (state='waiting' AND logical_id IN
                        (SELECT logical_id FROM actions WHERE consume_uncertain))""")
                conn.execute("""UPDATE deliveries SET outcome='not_executed',state='not_executed',reason='cancelled'
                    WHERE state='waiting'""")
            for row in self.connection.execute(
                "SELECT logical_id FROM actions WHERE outcome IS NULL"
            ).fetchall():
                self._finish_deliveries(row["logical_id"])
            sync_directory(self.directory)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    @contextmanager
    def transaction(self):
        if self.connection is None:
            raise JournalError("journal_closed")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def authorization(self):
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key='authorization'"
        ).fetchone()
        return json.loads(row[0]) if row else {"generation": 0, "denied": False}

    def deny_authorization(self):
        with self.transaction() as conn:
            state = self.authorization()
            state = {"generation": state["generation"] + 1, "denied": True}
            conn.execute(
                "INSERT OR REPLACE INTO metadata VALUES('authorization',?)",
                (canonical(state),),
            )

    def recover_authorization(self, generation):
        with self.transaction() as conn:
            state = self.authorization()
            # A response started before a newer denial cannot clear that fence.
            if state["generation"] != generation:
                return False
            if state["denied"]:
                state["denied"] = False
                conn.execute(
                    "INSERT OR REPLACE INTO metadata VALUES('authorization',?)",
                    (canonical(state),),
                )
            return True

    def learned_policy(self):
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key='policy'"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def learn_policy(self, snapshot):
        with self.transaction() as conn:
            previous = self.learned_policy()
            if previous is None or snapshot["version"] > previous["version"]:
                conn.execute(
                    "INSERT OR REPLACE INTO metadata VALUES('policy',?)",
                    (canonical(snapshot),),
                )

    def context_policy(self):
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key='context_policy'"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def learn_context_policy(self, snapshot):
        with self.transaction() as conn:
            previous = self.context_policy()
            if previous is None or snapshot["version"] > previous["version"]:
                conn.execute(
                    "INSERT OR REPLACE INTO metadata VALUES('context_policy',?)",
                    (canonical(snapshot),),
                )
            elif snapshot["version"] == previous["version"] and snapshot != previous:
                raise JournalError("context_policy_changed")

    def commitment(
        self, logical_id, boundary, raw, deliveries=("primary",), evidence=None
    ):
        if not isinstance(raw, bytes):
            raise JournalError("invalid_held_bytes")
        prefix = canonical(
            {
                "version": 1,
                "binding": self.binding,
                "logical_id": logical_id,
                "boundary": boundary,
                "deliveries": sorted(deliveries),
            }
        )
        digest = hmac.new(self.key, digestmod=hashlib.sha256)
        for part in (prefix, raw, canonical(evidence)):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
        return "hmac-sha256-v1:" + digest.hexdigest()

    def action(self, logical_id):
        row = self.connection.execute(
            "SELECT * FROM actions WHERE logical_id=?", (logical_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        for name in ("target", "context", "deliveries"):
            result[name] = json.loads(result[name])
        return result

    @staticmethod
    def _enqueue(conn, logical_id, receipt, event=None, operation=None):
        ident = new_id()
        cursor = conn.execute(
            "INSERT INTO outbox(record_id,logical_id,receipt,event,operation) VALUES(?,?,?,?,?)",
            (
                ident,
                logical_id,
                "{}",
                canonical(event).decode() if event is not None else None,
                canonical(operation).decode() if operation is not None else None,
            ),
        )
        sequence = cursor.lastrowid
        body = {**receipt, "record_id": ident, "sequence": sequence}
        conn.execute(
            "UPDATE outbox SET receipt=? WHERE sequence=?",
            (canonical(body).decode(), sequence),
        )
        return sequence

    def prepare(
        self,
        logical_id,
        commitment,
        target,
        context,
        local_action,
        deliveries=("primary",),
        observations=(),
    ):
        with self.transaction() as conn:
            current = self.action(logical_id)
            if current is not None:
                if (
                    current["commitment"] != commitment
                    or current["target"] != target
                    or current["context"] != context
                    or current["deliveries"] != sorted(deliveries)
                ):
                    raise JournalError("payload_changed")
                return current
            if conn.execute("SELECT 1 FROM metadata WHERE key IN ('close','settled')").fetchone():
                raise JournalError("session_closed")
            conn.execute(
                """INSERT INTO actions(logical_id,event_id,commitment,target,context,request_id,
                         local_action,state,deliveries,created_at) VALUES(?,?,?,?,?,?,?,'prepared',?,?)""",
                (
                    logical_id,
                    target["id"],
                    commitment,
                    canonical(target).decode(),
                    canonical(context).decode(),
                    new_id(),
                    local_action,
                    canonical(sorted(deliveries)).decode(),
                    time.time(),
                ),
            )
            self._enqueue(
                conn,
                logical_id,
                {
                    "kind": "target",
                    "event_id": target["id"],
                    "logical_id": logical_id,
                    "action_commitment": commitment,
                    "gaps": [],
                },
                event=target,
            )
            conn.executemany(
                "INSERT INTO deliveries(logical_id,delivery_id) VALUES(?,?)",
                ((logical_id, value) for value in deliveries),
            )
            if local_action == "warn":
                conn.execute(
                    "UPDATE actions SET warned=1 WHERE logical_id=?", (logical_id,)
                )
            for event in observations:
                self._observe(conn, logical_id, event)
        return self.action(logical_id)

    @staticmethod
    def _observe(conn, logical_id, event):
        digest = hashlib.sha256(canonical(event)).digest()
        previous = conn.execute(
            "SELECT payload_hash FROM observations WHERE id=?", (event["id"],)
        ).fetchone()
        if previous:
            if previous["payload_hash"] != digest:
                raise JournalError("payload_changed")
            return
        conn.execute("INSERT INTO observations VALUES(?,?)", (event["id"], digest))
        Journal._enqueue(
            conn, logical_id,
            {"kind": "observation", "event_id": event["id"], "gaps": []},
            event=event,
        )

    def observe(self, event, gaps=()):
        if any(code not in _DELIVERY_GAPS for code in gaps):
            raise JournalError("invalid_delivery_gap")
        with self.transaction() as conn:
            if conn.execute("SELECT 1 FROM metadata WHERE key IN ('close','settled')").fetchone():
                raise JournalError("session_closed")
            self._observe(conn, None, event)
            for gap in sorted(set(gaps)):
                self._enqueue(conn, None, {"kind": "gap", "gaps": [gap]})

    def update(self, logical_id, **values):
        allowed = {
            "state",
            "reason",
            "request_id",
            "check_id",
            "approval_id",
            "consume_id",
            "release_id",
            "outcome",
            "exit_code",
            "settings_version",
            "policy_version",
            "consume_uncertain",
            "restriction",
            "warned",
            "local_action",
        }
        if not values or not set(values) <= allowed:
            raise JournalError("invalid_journal_update")
        with self.transaction() as conn:
            # Names come only from the fixed set above, never request content.
            conn.execute(
                "UPDATE actions SET "
                + ",".join(key + "=?" for key in values)
                + " WHERE logical_id=?",
                (*values.values(), logical_id),
            )
        return self.action(logical_id)

    def pending(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise JournalError("invalid_outbox_limit")
        result = []
        for row in self.connection.execute(
            "SELECT * FROM outbox WHERE NOT acknowledged ORDER BY sequence LIMIT ?",
            (limit,),
        ):
            item = dict(row)
            for name in ("receipt", "event", "operation"):
                item[name] = json.loads(item[name]) if item[name] is not None else None
            result.append(item)
        return result

    def acknowledge(self, sequences):
        with self.transaction() as conn:
            conn.executemany(
                "UPDATE outbox SET acknowledged=1 WHERE sequence=?",
                ((seq,) for seq in sequences),
            )

    def add_gap(self, logical_id, gap):
        with self.transaction() as conn:
            self._enqueue(conn, logical_id, {"kind": "gap", "gaps": [gap]})

    def finish(self, logical_id, outcome, exit_code, reason):
        from openaidr.core.event import now

        with self.transaction() as conn:
            action = self.action(logical_id)
            if action["outcome"] is not None:
                return action
            conn.execute(
                "UPDATE actions SET outcome=?,exit_code=?,state=?,reason=? WHERE logical_id=?",
                (outcome, exit_code, outcome, reason, logical_id),
            )
            if action["release_id"]:
                operation = {
                    "kind": "outcome",
                    "release_id": action["release_id"],
                    "outcome": outcome,
                    "exit_code": exit_code,
                }
                self._enqueue(
                    conn,
                    logical_id,
                    {
                        "kind": "outcome",
                        "logical_id": logical_id,
                        "release_id": action["release_id"],
                        "gaps": [],
                    },
                    operation=operation,
                )
            elif action["consume_id"] and action["consume_uncertain"]:
                operation = {
                    "kind": "reconcile_consume",
                    "check_id": action["check_id"],
                    "request_id": action["consume_id"],
                    "commitment": action["commitment"],
                    "outcome": outcome,
                    "exit_code": exit_code,
                }
                self._enqueue(
                    conn,
                    logical_id,
                    {"kind": "outcome", "logical_id": logical_id, "gaps": []},
                    operation=operation,
                )
            else:
                event_id = new_id()
                event = {
                    "id": event_id,
                    "time": now(),
                    "kind": "sensor",
                    "agent": {"product": self.binding["product"]},
                    "host": action["target"].get("host", {}),
                    "session": action["target"]["session"],
                    "evidence": {
                        "version": 1,
                        "logical_id": hashlib.sha256(event_id.encode()).hexdigest(),
                        "observation_id": hashlib.sha256(
                            (event_id + ":outcome").encode()
                        ).hexdigest(),
                        "stream_id": hashlib.sha256(
                            self.binding["epoch_id"].encode()
                        ).hexdigest(),
                        "sequence": 0,
                        "part": 0,
                        "gaps": [],
                    },
                    "managed_outcome": {
                        "logical_id": logical_id,
                        "outcome": outcome,
                        "reason": reason,
                    },
                }
                if exit_code is not None:
                    event["managed_outcome"]["exit_code"] = exit_code
                gaps = (
                    ["backend_unavailable"] if reason == "backend_unavailable" else []
                )
                self._enqueue(
                    conn,
                    logical_id,
                    {
                        "kind": "outcome",
                        "logical_id": logical_id,
                        "event_id": event_id,
                        "gaps": gaps,
                    },
                    event=event,
                )
        return self.action(logical_id)

    def delivery(self, logical_id, delivery_id):
        row = self.connection.execute(
            "SELECT * FROM deliveries WHERE logical_id=? AND delivery_id=?",
            (logical_id, delivery_id),
        ).fetchone()
        if row is None:
            raise JournalError("unknown_delivery")
        return dict(row)

    def settle(self):
        """Seal a stopped producer without turning unstarted consumers into success."""
        with self.transaction() as conn:
            conn.execute("INSERT OR IGNORE INTO metadata VALUES('settled', '1')")
            conn.execute("""UPDATE deliveries SET outcome='uncertain',state='uncertain',reason='cancelled'
                WHERE outcome IS NULL AND (state='dispatching' OR logical_id IN
                    (SELECT logical_id FROM actions WHERE consume_uncertain))""")
            conn.execute("""UPDATE deliveries SET outcome='not_executed',state='not_executed',reason='cancelled'
                WHERE outcome IS NULL""")
        for row in self.connection.execute(
            "SELECT logical_id FROM actions WHERE outcome IS NULL"
        ).fetchall():
            self._finish_deliveries(row["logical_id"])

    def dispatch_intent(self, logical_id, delivery_id):
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE deliveries SET state='dispatching' WHERE logical_id=? AND delivery_id=? AND state='waiting'",
                (logical_id, delivery_id),
            ).rowcount
            if changed != 1:
                raise JournalError("delivery_already_started")

    def finish_delivery(self, logical_id, delivery_id, outcome, exit_code, reason):
        with self.transaction() as conn:
            conn.execute(
                "UPDATE deliveries SET outcome=?,exit_code=?,state=?,reason=? WHERE logical_id=? AND delivery_id=? AND outcome IS NULL",
                (outcome, exit_code, outcome, reason, logical_id, delivery_id),
            )
        self._finish_deliveries(logical_id)
        return self.delivery(logical_id, delivery_id)

    def _finish_deliveries(self, logical_id):
        rows = self.connection.execute(
            "SELECT * FROM deliveries WHERE logical_id=?", (logical_id,)
        ).fetchall()
        if not rows or any(row["outcome"] is None for row in rows):
            return
        outcomes = {row["outcome"] for row in rows}
        result = (
            "uncertain"
            if "uncertain" in outcomes
            else "succeeded"
            if outcomes == {"succeeded"}
            else "not_executed"
            if outcomes == {"not_executed"}
            else "failed"
        )
        action = self.action(logical_id)
        reason = (
            "backend_unavailable"
            if action["reason"] == "backend_unavailable"
            else (
                "blocked"
                if any(row["reason"] == "blocked" for row in rows)
                else "cancelled"
            )
        )
        self.finish(
            logical_id,
            result,
            next(
                (row["exit_code"] for row in rows if row["exit_code"] is not None), None
            ),
            reason,
        )

    def resolve_operation(self, sequence, receipt):
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT record_id,receipt FROM outbox WHERE sequence=?", (sequence,)
            ).fetchone()
            previous = json.loads(row["receipt"])
            receipt = {
                **previous,
                **receipt,
                "record_id": row["record_id"],
                "sequence": sequence,
            }
            conn.execute(
                "UPDATE outbox SET receipt=?,operation=NULL WHERE sequence=?",
                (canonical(receipt).decode(), sequence),
            )

    def closing(self, manifest=None):
        if manifest is not None:
            if (
                not isinstance(manifest, dict)
                or set(manifest) != {"reason", "boundaries", "gaps"}
                or not isinstance(manifest["reason"], str)
                or manifest["reason"] not in _CLOSE_REASONS
                or any(
                    not isinstance(manifest[key], (list, tuple, set, frozenset))
                    or len(manifest[key]) > maximum
                    or any(
                        not isinstance(value, str) or value not in allowed
                        for value in manifest[key]
                    )
                    for key, maximum, allowed in (
                        ("boundaries", 4, _BOUNDARIES),
                        ("gaps", 32, _DELIVERY_GAPS),
                    )
                )
            ):
                raise JournalError("invalid_close_manifest")
            manifest = {
                "reason": manifest["reason"],
                "boundaries": sorted(set(manifest["boundaries"])),
                "gaps": sorted(set(manifest["gaps"])),
            }
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key='close'"
            ).fetchone()
            existing = json.loads(row["value"]) if row else None
            if manifest is None:
                return existing
            if conn.execute(
                "SELECT 1 FROM actions WHERE outcome IS NULL LIMIT 1"
            ).fetchone():
                raise JournalError("actions_pending")
            sequence = conn.execute(
                "SELECT COALESCE(max(sequence),0) FROM outbox"
            ).fetchone()[0]
            payload = {
                "epoch_id": self.binding["epoch_id"],
                "final_sequence": sequence,
                "capabilities_version": 1,
                **manifest,
            }
            if existing:
                if {
                    key: value for key, value in existing.items() if key != "request_id"
                } != payload:
                    raise JournalError("close_changed")
                return existing
            payload["request_id"] = new_id()
            conn.execute(
                "INSERT INTO metadata VALUES('close',?)", (canonical(payload),)
            )
            return payload
