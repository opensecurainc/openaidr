"""Dormant complete-job orchestration; no scheduler or worker factory registration."""

import asyncio
from datetime import timedelta
from functools import partial
import math
import threading
import time

import anyio
from openaidr_api_client.contracts.errors import APIError

from . import intelligence, investigation_admission as admission, investigation_evidence as evidence
from . import investigation_recovery as recovery, investigation_submissions as submissions
from . import session_investigator as inv
from .store import NotFound


class Investigator:
    """Process one due identity per tick, independently of selected-service readiness."""

    def __init__(self, st, cfg, *, db_concurrency=1, poll_seconds=1, reconciliation_seconds=60, transport=None):
        if (not 1 <= db_concurrency <= 8 or not all(math.isfinite(value) and 0 < value <= 3600
                for value in (poll_seconds, reconciliation_seconds))):
            raise ValueError("Invalid investigation polling bounds")
        self.st, self.cfg, self.tenant, self.transport = st, cfg, inv._uuid(cfg.tenant_id), transport
        self.poll_seconds, self.reconciliation_seconds = poll_seconds, reconciliation_seconds
        self._limiter, self._close_limiter = anyio.CapacityLimiter(db_concurrency), anyio.CapacityLimiter(1)
        self._lock, self._closed, self._workers = threading.Lock(), threading.Event(), {}
        self._next_kind = 0

    def _attempt(self, claim):
        return self.st.one("""SELECT a.id AS attempt_id,a.tenant_id,a.job_id,a.claim_token,a.deadline_at,a.admission_origin
            FROM session_investigation_attempts a JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
            WHERE a.tenant_id=$1 AND a.id=$2 AND a.job_id=$3 AND a.claim_token=$4 AND j.protocol_version=4""",
            self.tenant, claim["attempt_id"], claim["job_id"], claim["claim_token"])

    def _due(self, *, capture=False):
        with self._lock:
            active = [row["attempt_id"] for row in self._workers.values() if row]
        with self.st.transaction() as conn:
            self.st.execute("SET LOCAL statement_timeout='5s'", conn=conn)
            self.st.execute("SET LOCAL lock_timeout='3s'", conn=conn)
            if capture:
                rows = self.st.many("""SELECT a.id AS attempt_id,a.tenant_id,a.job_id,a.claim_token,a.deadline_at,a.admission_origin
                    FROM session_investigation_attempts a JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
                    WHERE a.tenant_id=$1 AND j.protocol_version=4 AND j.state='running' AND a.state='reserved'
                      AND j.claim_token=a.claim_token AND a.admission_origin IS NOT NULL AND NOT (a.id=ANY($2::uuid[]))
                      AND j.next_attempt_at<=clock_timestamp()
                      AND NOT EXISTS(SELECT 1 FROM session_investigation_submissions b WHERE b.attempt_id=a.id)
                    ORDER BY j.next_attempt_at,a.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED""", self.tenant, active, conn=conn)
                if rows:
                    self.st.execute("UPDATE session_investigation_jobs SET next_attempt_at=clock_timestamp()+$2*interval '1 second' WHERE id=$1",
                                    rows[0]["job_id"], self.poll_seconds, conn=conn)
            else:
                rows = self.st.many("""SELECT b.attempt_id,b.tenant_id,a.job_id,a.claim_token,a.deadline_at
                    FROM session_investigation_submissions b
                    JOIN session_investigation_attempts a ON a.id=b.attempt_id AND a.tenant_id=b.tenant_id
                    JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
                    LEFT JOIN service_credit_receipts r ON r.tenant_id=b.tenant_id AND r.request_id=b.attempt_id
                    WHERE b.tenant_id=$1 AND j.protocol_version=4 AND NOT (b.attempt_id=ANY($2::uuid[]))
                      AND (b.closed_at IS NULL OR r.state IS NULL OR r.state IN ('pending','reserved')
                           OR b.remote_status IS NULL OR b.remote_status NOT IN ('completed','failed','cancelled'))
                      AND (b.checked_at IS NULL OR b.checked_at<=clock_timestamp()-
                           CASE WHEN b.closed_at IS NULL THEN $3 ELSE $4 END*interval '1 second')
                    ORDER BY b.checked_at NULLS FIRST,b.attempt_id LIMIT 1 FOR UPDATE OF b SKIP LOCKED""",
                    self.tenant, active, self.poll_seconds, self.reconciliation_seconds, conn=conn)
                if rows:
                    # Scheduling cannot depend on diagnostic writes: a published
                    # result may still have pending accounting to reconcile.
                    self.st.execute("UPDATE session_investigation_submissions SET checked_at=clock_timestamp() WHERE attempt_id=$1",
                                    rows[0]["attempt_id"], conn=conn)
        return rows[0] if rows else None

    def _recover(self, row):
        if self._closed.is_set():
            return True
        try:
            recovery.reconcile(self.st, self.cfg, self.tenant, row["attempt_id"], transport=self.transport)
            if self.st.scalar("SELECT clock_timestamp()") >= row["deadline_at"] + timedelta(hours=1):
                # The original grant plus the service's retention window is a
                # finite local retrieval horizon, never proof of zero charge.
                with self.st.transaction() as conn:
                    self.st.one("SELECT id FROM session_investigation_jobs WHERE id=$1 FOR UPDATE", row["job_id"], conn=conn)
                    current = self.st.one("SELECT remote_status,closed_at,publication FROM session_investigation_submissions WHERE attempt_id=$1 FOR UPDATE",
                                          row["attempt_id"], conn=conn)
                    if current["closed_at"] is not None or current["publication"] is not None:
                        return True
                    code = "result_unavailable" if current["remote_status"] == "completed" else "service_unavailable"
                    inv.stop_attempt(self.st, recovery._claim(row), code, conn=conn)
                    self.st.execute("""UPDATE session_investigation_submissions SET closed_at=clock_timestamp(),
                        cancel_requested=true,last_error=$3 WHERE tenant_id=$1 AND attempt_id=$2
                        AND publication IS NULL AND closed_at IS NULL""", self.tenant, row["attempt_id"], code, conn=conn)
        finally:
            self.st.execute("UPDATE session_investigation_submissions SET checked_at=clock_timestamp() WHERE tenant_id=$1 AND attempt_id=$2",
                            self.tenant, row["attempt_id"])
        return True

    def _close_unsent(self, row, code):
        # Capture commits its submission and dispatch intent under this same
        # job lock. An earlier no-submission read cannot authorize cleanup.
        with self.st.transaction() as conn:
            self.st.execute("SET LOCAL statement_timeout='5s'", conn=conn)
            self.st.execute("SET LOCAL lock_timeout='3s'", conn=conn)
            self.st.one("""SELECT id FROM session_investigation_jobs
                WHERE id=$1 AND tenant_id=$2 AND protocol_version=4 FOR UPDATE""", row["job_id"], self.tenant, conn=conn)
            submitted = self.st.scalar("""SELECT EXISTS(SELECT 1 FROM session_investigation_submissions
                WHERE attempt_id=$1 AND tenant_id=$2)""", row["attempt_id"], self.tenant, conn=conn)
            if not submitted:
                inv.stop_attempt(self.st, recovery._claim(row), code, conn=conn)
        return self._recover(row) if submitted else True

    def _capture(self, row):
        claim = recovery._claim(row)
        if self.st.scalar("SELECT EXISTS(SELECT 1 FROM session_investigation_submissions WHERE attempt_id=$1)", row["attempt_id"]):
            return self._recover(row)
        if self.st.scalar("SELECT clock_timestamp()") >= row["deadline_at"]:
            return self._close_unsent(row, "claim_expired")
        try:
            connection = intelligence.connection_for_origin(self.cfg, self.st, row["admission_origin"])
        except (APIError, ValueError):
            return True
        if connection is None or self._closed.is_set():
            return True
        try:
            evidence.prepare(self.st, claim, connection)
        except (APIError, ValueError, NotFound, inv.InvestigationStopped) as error:
            if self.st.scalar("SELECT EXISTS(SELECT 1 FROM session_investigation_submissions WHERE attempt_id=$1)", row["attempt_id"]):
                return self._recover(row)
            code = getattr(error, "code", "scope_unavailable" if isinstance(error, NotFound) else "invalid_request")
            if code not in ("internal_error", "capture_conflict") and not isinstance(error, APIError):
                return self._close_unsent(row, code)
            elif isinstance(error, APIError) and error.status in (403, 404):
                return self._close_unsent(row, "scope_unavailable")
            return True
        return self._recover(row)

    def _admit(self, worker_id):
        try:
            connection = intelligence.selected_connection(self.cfg, self.st)
        except (APIError, ValueError):
            return None
        if connection is None:
            return None
        candidates = self.st.many("""SELECT id FROM session_investigation_jobs WHERE tenant_id=$1
            AND protocol_version=4 AND state='queued' AND next_attempt_at<=clock_timestamp()
            ORDER BY next_attempt_at,id LIMIT 100""", self.tenant)
        for candidate in candidates:
            if self._closed.is_set():
                return None
            try:
                with self.st.transaction() as conn:
                    claim = admission.claim(self.st, candidate["id"], connection, worker_id, conn=conn)
            except (APIError, NotFound):
                claim = None
            if claim:
                return self._attempt(claim)
            self.st.execute("""UPDATE session_investigation_jobs SET next_attempt_at=clock_timestamp()+interval '60 seconds'
                WHERE id=$1 AND tenant_id=$2 AND state='queued'""", candidate["id"], self.tenant)
        return None

    def _execute(self, worker_id, tenant_id, worker_ready, claim=None):
        submissions._contracts()
        if self.cfg.tenant_id != self.tenant or tenant_id not in (None, self.tenant):
            return False
        finished = threading.Event()
        with self._lock:
            if self._closed.is_set():
                return False
            self._workers[finished] = None
            first = self._next_kind
            self._next_kind = (first + 1) % 3
        try:
            row = self._attempt(claim) if claim else None
            capture = claim is not None
            if not claim:
                for kind in ((first + offset) % 3 for offset in range(3)):
                    capture = kind != 0
                    if kind == 2:
                        row = self._admit(worker_id) if worker_ready and not self._closed.is_set() else None
                    else:
                        row = self._due(capture=capture)
                    if row:
                        break
            if row is None or self._closed.is_set():
                return False
            with self._lock:
                self._workers[finished] = row
            return self._capture(row) if capture else self._recover(row)
        finally:
            with self._lock:
                self._workers.pop(finished)
                finished.set()

    async def _run(self, worker_id, tenant_id, worker_ready, claim=None):
        try:
            return await anyio.to_thread.run_sync(partial(self._execute, worker_id, tenant_id, worker_ready, claim), limiter=self._limiter)
        except asyncio.CancelledError:
            await self.aclose()
            raise

    async def run_once(self, worker_id, tenant_id=None, *, worker_ready=False):
        return await self._run(worker_id, tenant_id, worker_ready)

    async def run_claim(self, claim):
        return await self._run("submitted-job", claim["tenant_id"], False, claim)

    async def cancel(self, attempt_id):
        def request():
            submissions._contracts()
            row = self.st.one("""SELECT a.id AS attempt_id,a.tenant_id,a.job_id,a.claim_token,a.deadline_at
                FROM session_investigation_attempts a JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
                WHERE a.id=$1 AND a.tenant_id=$2 AND j.protocol_version=4""", attempt_id, self.tenant)
            with self.st.transaction() as conn:
                self.st.one("SELECT id FROM session_investigation_jobs WHERE id=$1 FOR UPDATE", row["job_id"], conn=conn)
                updated = self.st.many("""UPDATE session_investigation_submissions SET cancel_requested=true
                    WHERE attempt_id=$1 AND tenant_id=$2 AND publication IS NULL RETURNING attempt_id""", attempt_id, self.tenant, conn=conn)
                exists = self.st.scalar("SELECT EXISTS(SELECT 1 FROM session_investigation_submissions WHERE attempt_id=$1)", attempt_id, conn=conn)
                if not exists:
                    inv.stop_attempt(self.st, recovery._claim(row), "cancelled", conn=conn)
            if updated:
                recovery.reconcile(self.st, self.cfg, self.tenant, attempt_id, transport=self.transport)
            return bool(updated) or not exists
        return await anyio.to_thread.run_sync(request, limiter=self._close_limiter)

    async def aclose(self):
        # Disconnecting a tenant must leave accepted work running remotely.
        self._closed.set()
        with self._lock:
            workers = list(self._workers)
        def drain():
            deadline = time.monotonic() + 60
            for worker in workers:
                if not worker.wait(max(0, deadline - time.monotonic())):
                    raise TimeoutError("Investigation work is still draining; its identity remains recoverable")
        await anyio.to_thread.run_sync(drain, limiter=self._close_limiter)
