"""Assessment requests survive restarts without duplicating uncertain paid work."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import sqlite3
from threading import Barrier
from uuid import uuid4

import pytest

from openaidr.sensor import posture_store


def config(tmp_path, **changes):
    return dict(data_dir=str(tmp_path / "private"), server_url="https://api-test.example",
                sensor_id="device", tenant_id="tenant", **changes)


def report(expires=20, title="Retained finding"):
    stamp = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat()
    return dict(status="complete", findings=[{"title": title, "detail": "Literal <script> evidence"}],
                checked_at=stamp(10), expires_at=stamp(expires))


def receipt(request_id, state="settled", service="package_vulnerabilities", amount="0.01"):
    return dict(request_id=request_id, service=service, state=state, rate_version="test-1",
                credits_reserved=amount, credits_charged=amount if state == "settled" else "0" if state == "released" else None)


def test_private_durable_cache_and_enrollment_isolation(tmp_path):
    cfg = config(tmp_path)
    store = posture_store.Store(cfg)
    if os.name != "nt":
        assert store.path.stat().st_mode & 0o777 == 0o600
        assert store.path.parent.stat().st_mode & 0o777 == 0o700
    ident = store.claim("package_vulnerabilities", ["package:a"], now=10)
    store.complete(ident, {"package:a": report()})
    store.receipt(ident, receipt(ident))
    restarted = posture_store.Store(cfg)
    assert restarted.records(["package:a"])["package:a"]["report"] == report()
    assert restarted.claim("package_vulnerabilities", ["package:a"], now=19) is None
    for field, value in (("server_url", "https://other.example"), ("sensor_id", "other"), ("tenant_id", "other")):
        other = posture_store.Store({**cfg, field: value})
        assert other.scope != store.scope and other.records() == {}
        assert other.summary() == dict(credits_charged="0", credits_reserved="0", unknown_attempts=0)
        with pytest.raises(ValueError, match="Unknown"):
            other.receipt(ident, receipt(ident))
    refreshed = restarted.claim("package_vulnerabilities", ["package:a"], now=20)
    assert refreshed != ident
    assert restarted.records()["package:a"]["report"] == report()
    assert restarted.summary() == dict(credits_charged="0.01", credits_reserved="0", unknown_attempts=1)


def test_concurrent_claims_are_atomic_and_unknown_requests_never_expire(tmp_path):
    cfg = config(tmp_path)
    stores = [posture_store.Store(cfg) for _ in range(4)]
    barrier = Barrier(4)

    def claim(store):
        barrier.wait()
        return store.claim("package_vulnerabilities", ["package:a", "package:b"], now=10)

    with ThreadPoolExecutor(max_workers=4) as executor:
        identifiers = list(executor.map(claim, stores))
    assert sum(value is not None for value in identifiers) == 1
    ident = next(value for value in identifiers if value)
    store = stores[0]
    assert store.claim("package_vulnerabilities", ["package:c", "package:a"], now=30) is None
    assert "package:c" not in store.records()
    store.fail(ident)
    restarted = posture_store.Store(cfg)
    assert restarted.claim("package_vulnerabilities", ["package:a"], now=10**10) is None
    assert restarted.records(["package:a"])["package:a"]["state"] == "unknown"
    assert restarted.records([]) == {} and restarted.records(["missing"]) == {}
    assert restarted.summary()["unknown_attempts"] == 1
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM attempts").fetchone()[0] == 1


def test_receipts_bind_identity_and_preserve_monotonic_billing_independently(tmp_path):
    store = posture_store.Store(config(tmp_path))
    ident = store.claim("package_vulnerabilities", ["package:a"], now=10)
    for wrong in (receipt(str(uuid4())), receipt(ident, service="skill_assessment"),
                  {**receipt(ident), "credits_charged": "2"}):
        with pytest.raises(ValueError):
            store.receipt(ident, wrong)
    store.receipt(ident, receipt(ident, "reserved"))
    assert store.summary() == dict(credits_charged="0", credits_reserved="0.01", unknown_attempts=1)
    store.receipt(ident, receipt(ident, "pending"))
    for wrong in (receipt(ident, "reserved"), receipt(ident, "settled", amount="0.02"),
                  {**receipt(ident), "rate_version": "test-2"}):
        with pytest.raises(ValueError, match="recorded outcome or price"):
            store.receipt(ident, wrong)
    store.receipt(ident, receipt(ident))
    store.receipt(ident, receipt(ident, amount="0.010"))
    store.fail(ident)
    assert store.summary() == dict(credits_charged="0.01", credits_reserved="0", unknown_attempts=1)
    with pytest.raises(ValueError):
        store.complete(ident, {"package:a": {**report(), "expires_at": "invalid"}})
    assert store.summary()["credits_charged"] == "0.01"
    with pytest.raises(ValueError, match="cannot be retried"):
        store.fail(ident, retry_at=30)
    with pytest.raises(ValueError):
        store.receipt(ident, receipt(ident, "released"))
    store.complete(ident, {"package:a": report()})
    assert store.summary()["unknown_attempts"] == 0


def test_completion_requires_the_whole_batch_and_retry_retains_findings(tmp_path):
    store = posture_store.Store(config(tmp_path))
    keys = ["package:a", "package:b"]
    ident = store.claim("package_vulnerabilities", keys, now=10)
    for invalid in ({keys[0]: report()}, {keys[0]: report(), "unclaimed": report()}):
        with pytest.raises(ValueError, match="claimed batch"):
            store.complete(ident, invalid)
        assert all(row["report"] is None for row in store.records().values())
    reports = {key: report() for key in keys}
    store.complete(ident, reports)
    store.complete(ident, {key: dict(reversed(list(value.items()))) for key, value in reports.items()})
    assert store.summary()["unknown_attempts"] == 1  # A result alone does not confirm billing.
    assert store.claim("package_vulnerabilities", keys, now=21) is None
    store.receipt(ident, receipt(ident, "pending"))
    assert store.claim("package_vulnerabilities", keys, now=21) is None
    store.receipt(ident, receipt(ident))
    with pytest.raises(ValueError, match="immutable"):
        store.complete(ident, {key: report(title="different") for key in keys})
    refresh = store.claim("package_vulnerabilities", keys, now=21)
    store.receipt(refresh, receipt(refresh, "released"))
    store.fail(refresh, retry_at=30)
    assert store.claim("package_vulnerabilities", keys, now=29) is None
    assert all(row["report"] == report() for row in store.records().values())
    next_id = store.claim("package_vulnerabilities", keys, now=30)
    with pytest.raises(ValueError, match="claimed batch"):
        store.complete(refresh, reports)
    store.fail(next_id, retry_at=40)  # A confirmed rejection before admission has no receipt.
    with pytest.raises(ValueError, match="retriable"):
        store.receipt(next_id, receipt(next_id))
    assert len(store.records()) == 2
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM attempts").fetchone()[0] == 3


def test_storage_and_batch_bounds_fail_closed(tmp_path, monkeypatch):
    store = posture_store.Store(config(tmp_path))
    for keys in ([], ["duplicate", "duplicate"], [str(index) for index in range(26)], ["x" * 193]):
        with pytest.raises(ValueError):
            store.claim("package_vulnerabilities", keys)
    with pytest.raises(ValueError):
        store.claim("unpriced_service", ["a"])
    assert store.records() == {}
    ident = store.claim("skill_assessment", ["skill:a:profile-1"], now=10)
    with pytest.raises(ValueError):
        store.claim("package_vulnerabilities", ["skill:a:profile-1"], now=20)
    monkeypatch.setattr(posture_store, "MAX_BYTES", 64 << 10)
    oversized = {**report(), "detail": "x" * (128 << 10)}
    with pytest.raises(sqlite3.DatabaseError, match="full"):
        store.complete(ident, {"skill:a:profile-1": oversized})
    assert store.records()["skill:a:profile-1"]["state"] == "pending"
    assert store.records()["skill:a:profile-1"]["report"] is None
    assert store.path.stat().st_size <= 64 << 10
    assert "x" * 1024 not in store.path.read_bytes().decode("latin-1")
    assert json.loads(json.dumps(store.summary()))["unknown_attempts"] == 1
