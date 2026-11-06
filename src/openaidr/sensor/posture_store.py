"""Private assessment results and durable, enrollment-bound request identities."""

from contextlib import closing, contextmanager
from datetime import datetime
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
from uuid import uuid4

from openaidr_api_client.contracts.credits import BillingReceipt, amount, microcredits

from openaidr.core.files import durable_directory, sync_directory
from .usage import identity

MAX_BYTES = 512 << 20
MAX_REPORT_BYTES = 1 << 20
APPLICATION_ID = 0x4F415053
SERVICES = frozenset(("package_vulnerabilities", "skill_assessment"))


def _timestamp(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            raise ValueError("Assessment timestamps require a timezone")
        value = value.timestamp()
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Invalid assessment timestamp")
    return value


def _keys(values, *, limit=None):
    if isinstance(values, (str, bytes)):
        raise ValueError("Assessment keys must be a sequence")
    values = list(values)
    if (limit is not None and not 1 <= len(values) <= limit
            or any(not isinstance(key, str) or not 1 <= len(key) <= 192 or "\x00" in key for key in values)
            or len(set(values)) != len(values)):
        raise ValueError("Invalid assessment keys")
    return values


class Store:
    def __init__(self, config):
        self.path = Path(config["data_dir"]).absolute() / "posture-assessments.sqlite3"
        self.scope = identity(config)
        durable_directory(self.path.parent)
        if self.path.is_symlink():
            raise ValueError("Assessment database must be a regular file")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Assessment database must be a regular file")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_directory(self.path.parent)
        with self._db(write=True) as db:
            application = db.execute("PRAGMA application_id").fetchone()[0]
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if application == 0 and not db.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone():
                db.execute("""CREATE TABLE attempts (
                    scope TEXT NOT NULL, id TEXT NOT NULL, service TEXT NOT NULL,
                    keys TEXT NOT NULL, state TEXT NOT NULL, retry_at REAL, receipt TEXT,
                    created REAL NOT NULL, PRIMARY KEY(scope,id))""")
                db.execute("""CREATE TABLE assets (
                    scope TEXT NOT NULL, key TEXT NOT NULL, request_id TEXT NOT NULL,
                    report TEXT, expires_at REAL, PRIMARY KEY(scope,key),
                    FOREIGN KEY(scope,request_id) REFERENCES attempts(scope,id))""")
                db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                db.execute("PRAGMA user_version=1")
            elif application != APPLICATION_ID or version != 1:
                raise ValueError("Unsupported assessment database")

    @contextmanager
    def _db(self, *, write=False):
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            pages = MAX_BYTES // db.execute("PRAGMA page_size").fetchone()[0]
            if db.execute("PRAGMA page_count").fetchone()[0] > pages:
                raise ValueError("Assessment database exceeds its storage allowance")
            db.execute(f"PRAGMA max_page_count={pages}")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _attempt(self, db, request_id):
        row = db.execute("SELECT * FROM attempts WHERE scope=? AND id=?", (self.scope, request_id)).fetchone()
        if row is None:
            raise ValueError("Unknown assessment request")
        return row

    def claim(self, service, keys, now=None):
        """Claim the complete batch, or nothing; unknown attempts never expire."""
        if service not in SERVICES:
            raise ValueError("Unsupported assessment service")
        keys = _keys(keys, limit=25)
        now = _timestamp(time.time() if now is None else now)
        with self._db(write=True) as db:
            for key in keys:
                row = db.execute("""SELECT a.expires_at,t.service,t.state,t.retry_at,t.receipt
                    FROM assets a JOIN attempts t ON t.scope=a.scope AND t.id=a.request_id
                    WHERE a.scope=? AND a.key=?""", (self.scope, key)).fetchone()
                if row is not None:
                    if row["service"] != service:
                        raise ValueError("Assessment key belongs to another service")
                    settled = row["receipt"] and json.loads(row["receipt"])["state"] in ("settled", "released", "disabled")
                    if not (row["state"] == "complete" and settled and row["expires_at"] is not None and row["expires_at"] <= now
                            or row["state"] == "retry" and row["retry_at"] <= now):
                        return None
            request_id = str(uuid4())
            db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,NULL,NULL,?)",
                       (self.scope, request_id, service, json.dumps(keys), "pending", now))
            db.executemany("""INSERT INTO assets(scope,key,request_id) VALUES(?,?,?)
                ON CONFLICT(scope,key) DO UPDATE SET request_id=excluded.request_id""",
                [(self.scope, key, request_id) for key in keys])
        return request_id

    def complete(self, request_id, reports):
        if not isinstance(reports, dict):
            raise ValueError("Assessment reports must be a mapping")
        encoded = {}
        for key, report in reports.items():
            if not isinstance(report, dict):
                raise ValueError("Invalid assessment report")
            expiry = _timestamp(report["expires_at"]) if report.get("expires_at") is not None else None
            checked = _timestamp(report.get("checked_at"))
            value = json.dumps(report, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
            if expiry is not None and expiry < checked or len(value.encode()) > MAX_REPORT_BYTES:
                raise ValueError("Invalid assessment report bounds")
            encoded[key] = (value, expiry)
        with self._db(write=True) as db:
            attempt = self._attempt(db, request_id)
            if attempt["service"] != "skill_assessment" and any(expiry is None for _, expiry in encoded.values()):
                raise ValueError("Package assessments require an expiry")
            keys = json.loads(attempt["keys"])
            current = db.execute("SELECT key,report FROM assets WHERE scope=? AND request_id=?",
                                 (self.scope, request_id)).fetchall()
            if set(reports) != set(keys) or {row["key"] for row in current} != set(keys):
                raise ValueError("Assessment reports do not match the claimed batch")
            if attempt["state"] == "complete":
                if any(row["report"] != encoded[row["key"]][0] for row in current):
                    raise ValueError("Completed assessment reports are immutable")
                return
            if attempt["state"] not in ("pending", "unknown"):
                raise ValueError("Assessment request is no longer active")
            db.executemany("UPDATE assets SET report=?,expires_at=? WHERE scope=? AND key=?",
                           [(value, expiry, self.scope, key) for key, (value, expiry) in encoded.items()])
            db.execute("UPDATE attempts SET state='complete' WHERE scope=? AND id=?", (self.scope, request_id))

    def receipt(self, request_id, value):
        value = BillingReceipt.model_validate(value).model_dump()
        for key in ("credits_reserved", "credits_charged"):
            if value[key] is not None:
                value[key] = amount(microcredits(value[key]))
        with self._db(write=True) as db:
            attempt = self._attempt(db, request_id)
            if value["request_id"] != request_id or value["service"] != attempt["service"]:
                raise ValueError("Assessment receipt identity differs")
            if attempt["state"] == "retry" and value["state"] not in ("disabled", "released"):
                raise ValueError("A retriable request cannot have a charge or reservation")
            old = json.loads(attempt["receipt"]) if attempt["receipt"] else None
            if old and old != value:
                if (old["state"] in ("disabled", "settled", "released")
                        or any(old[key] != value[key] for key in ("credits_reserved", "rate_version"))
                        or value["state"] not in ("pending", "settled", "released")):
                    raise ValueError("Assessment receipt cannot change its recorded outcome or price")
            db.execute("UPDATE attempts SET receipt=? WHERE scope=? AND id=?",
                       (json.dumps(value, separators=(",", ":")), self.scope, request_id))

    def fail(self, request_id, retry_at=None):
        """Only confirmed pre-admission failures or releases may be retried."""
        if retry_at is not None:
            retry_at = _timestamp(retry_at)
        with self._db(write=True) as db:
            attempt = self._attempt(db, request_id)
            if attempt["state"] == "complete":
                raise ValueError("Completed assessment cannot become a failure")
            receipt = json.loads(attempt["receipt"]) if attempt["receipt"] else None
            if retry_at is not None and receipt and receipt["state"] not in ("released", "disabled"):
                raise ValueError("Unresolved or charged assessment cannot be retried")
            db.execute("UPDATE attempts SET state=?,retry_at=? WHERE scope=? AND id=?",
                       ("unknown" if retry_at is None else "retry", retry_at, self.scope, request_id))

    def records(self, keys=None):
        selected = None if keys is None else _keys(keys)
        if selected == []:
            return {}
        result = {}
        with self._db() as db:
            batches = [None] if selected is None else [selected[i:i + 400] for i in range(0, len(selected), 400)]
            for batch in batches:
                where = "" if batch is None else " AND a.key IN (" + ",".join("?" for _ in batch) + ")"
                rows = db.execute("""SELECT a.key,a.report,a.expires_at,t.id,t.service,t.state,t.retry_at,t.receipt
                    FROM assets a JOIN attempts t ON t.scope=a.scope AND t.id=a.request_id WHERE a.scope=?"""
                    + where, [self.scope, *(batch or [])])
                for row in rows:
                    result[row["key"]] = dict(state=row["state"], request_id=row["id"], service=row["service"],
                        report=json.loads(row["report"]) if row["report"] else None,
                        billing_state=json.loads(row["receipt"])["state"] if row["receipt"] else None,
                        expires_at=row["expires_at"], retry_at=row["retry_at"])
        return result

    def summary(self):
        charged = reserved = unknown = 0
        with self._db() as db:
            for row in db.execute("SELECT state,receipt FROM attempts WHERE scope=?", (self.scope,)):
                receipt = json.loads(row["receipt"]) if row["receipt"] else None
                unknown += (row["state"] in ("pending", "unknown") or row["state"] == "complete"
                            and (receipt is None or receipt["state"] in ("reserved", "pending")))
                if receipt:
                    if receipt["credits_charged"] is not None:
                        charged += microcredits(receipt["credits_charged"])
                    if receipt["state"] in ("reserved", "pending"):
                        reserved += microcredits(receipt["credits_reserved"])
        return dict(credits_charged=amount(charged), credits_reserved=amount(reserved), unknown_attempts=unknown)
