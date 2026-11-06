import json
import sqlite3
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from openaidr.server import host_metrics as metrics

NOW = datetime(2026, 9, 30, 12, tzinfo=timezone.utc)


def sample(when=NOW):
    return dict(
        time=when.isoformat(),
        cpu_percent=25.5,
        memory_percent=40,
        disk_percent=60,
        disk_read_bytes_per_second=1024,
        disk_write_bytes_per_second=2048,
    )


def capacity():
    return dict(
        cpu_count=8,
        memory_used_bytes=40 * 1024,
        memory_total_bytes=100 * 1024,
        disk_used_bytes=600,
        disk_total_bytes=1000,
    )


@pytest.fixture
def sysstat_report():
    # Shape and units from sadf -j with sysstat 12.7.5.
    return {
        "sysstat": {
            "hosts": [
                {
                    "nodename": "host",
                    "number-of-cpus": 8,
                    "statistics": [
                        {
                            "timestamp": {
                                "date": "2026-09-30",
                                "time": "12:00:00",
                                "tz": "UTC",
                            },
                            "cpu-load": [
                                {"cpu": "0", "idle": 0},
                                {"cpu": "all", "idle": 74.5},
                            ],
                            "memory": {"memused-percent": 40, "memused": 40},
                            "io": {"io-reads": {"bread": 2}, "io-writes": {"bwrtn": 4}},
                        }
                    ],
                }
            ]
        }
    }


def test_sysstat_units_and_aggregate_cpu(sysstat_report):
    report = sysstat_report
    disk = namedtuple("Disk", "total used free")(1000, 600, 400)
    assert metrics.normalize(report, disk, 100 * 1024, disk, True) == (
        "host",
        {**sample(), **capacity(), "disk_available_bytes": 400, "disk_is_root": True,
         "root_disk_percent": 60, "root_disk_used_bytes": 600,
         "root_disk_total_bytes": 1000, "root_disk_available_bytes": 400},
    )
    # Boot exhaustion must remain visible when the configured data disk is free.
    root = disk._replace(total=100, used=97, free=2)
    _, normalized = metrics.normalize(report, disk, 100 * 1024, root, False)
    assert normalized["disk_percent"] == 60
    assert normalized["disk_available_bytes"] == 400
    assert normalized["root_disk_percent"] == 97
    assert normalized["root_disk_available_bytes"] == 2
    assert normalized["root_disk_total_bytes"] == 100
    assert normalized["disk_is_root"] is False
    report["sysstat"]["hosts"][0]["statistics"][0]["timestamp"]["tz"] = "LOCAL"
    with pytest.raises(ValueError):
        metrics.normalize(report, disk, 100 * 1024, disk, True)


@pytest.mark.parametrize("disk_path, same", [("/", True), ("/srv/openaidr", True), ("/srv/openaidr", False)])
def test_collector_reads_host_boot_and_data_filesystems(tmp_path, monkeypatch, sysstat_report, disk_path, same):
    data = tmp_path / disk_path.lstrip("/")
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("OPENAIDR_HOST_DISK_PATH", disk_path)
    real_stat, real_read = metrics.Path.stat, metrics.Path.read_text

    def host_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path in (tmp_path, data):
            values = list(result)
            values[2] = 2 if path == data and not same else 1
            return metrics.os.stat_result(values)
        return result

    monkeypatch.setattr(metrics.Path, "stat", host_stat)
    monkeypatch.setattr(metrics.Path, "read_text", lambda path, *a, **kw:
                        "MemTotal: 100 kB\n" if str(path) == "/proc/meminfo" else real_read(path, *a, **kw))
    monkeypatch.setattr(metrics.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=json.dumps(sysstat_report)))
    monkeypatch.setattr(metrics.service_cpu, "snapshot", lambda root: None)
    Disk = namedtuple("Disk", "total used free")
    reads = []

    def disk_usage(path):
        reads.append(path)
        return Disk(1000, 600, 350) if path == data else Disk(1000, 970, 20)

    monkeypatch.setattr(metrics.shutil, "disk_usage", disk_usage)
    host, row, measured = metrics.collect_sample(host_root=tmp_path)
    assert (host, measured) == ("host", disk_path)
    assert row["disk_is_root"] is same
    assert row["disk_percent"] == 60
    assert row["root_disk_percent"] == (60 if same else 97)
    assert row["root_disk_available_bytes"] == (350 if same else 20)
    assert reads == ([data] if same else [data, tmp_path])


@pytest.mark.parametrize(
    "release, expected",
    [
        (None, "/"),
        ('PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\n', "/"),
        ('PRETTY_NAME="Docker Desktop"\n', "/var/lib"),
        ("# Docker host\nPRETTY_NAME='Docker Desktop'\n", "/var/lib"),
    ],
)
def test_disk_filesystem_selection_uses_host_os_release(tmp_path, release, expected):
    (tmp_path / "var/lib").mkdir(parents=True)
    if release is not None:
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc/os-release").write_text(release)
    assert metrics.host_disk_path(tmp_path) == expected


def test_configured_disk_path_must_be_a_host_directory(tmp_path):
    (tmp_path / "srv/openaidr").mkdir(parents=True)
    assert metrics.host_disk_path(tmp_path, "/srv/openaidr") == "/srv/openaidr"
    assert metrics.host_disk_path(tmp_path, "/") == "/"
    for configured in ("srv/openaidr", "/srv/openaidr/", "/srv/../srv/openaidr", "/data"):
        with pytest.raises(ValueError, match="host directory"):
            metrics.host_disk_path(tmp_path, configured)
    # The configured path survives the collector's history round trip.
    path = tmp_path / "history.json"
    first = {**sample(NOW - timedelta(minutes=1)), **capacity()}
    second = {**sample(), **capacity()}
    metrics.save_sample(path, "host", first, disk_path="/srv/openaidr")
    metrics.save_sample(path, "host", second, disk_path="/srv/openaidr")
    current = metrics.read_metrics(path, now=NOW)
    assert current["status"] == "ok"
    assert current["disk_path"] == "/srv/openaidr"
    assert current["samples"] == [first, second]
    history = json.loads(path.read_text())
    for invalid in ("srv", "/srv/../etc", "/srv/", "/a b"):
        path.write_text(json.dumps({**history, "disk_path": invalid}))
        assert metrics.read_metrics(path, now=NOW)["status"] == "unavailable"


def test_disk_source_changes_restart_history_without_relabeling_old_samples(tmp_path):
    path = tmp_path / "history.json"
    metrics.save_sample(path, "host", sample(NOW - timedelta(minutes=1)))
    assert metrics.read_metrics(path, now=NOW)["disk_path"] == "/"

    docker = {**sample(), **capacity(), "disk_percent": 88.7, "disk_used_bytes": 887}
    metrics.save_sample(path, "host", docker, disk_path="/var/lib")
    current = metrics.read_metrics(path, now=NOW)
    assert current["status"] == "ok"
    assert current["disk_path"] == "/var/lib"
    assert current["samples"] == [docker]

    next_time = NOW + timedelta(minutes=1)
    next_row = {**docker, "time": next_time.isoformat()}
    metrics.save_sample(path, "host", next_row, disk_path="/var/lib")
    assert metrics.read_metrics(path, now=next_time)["samples"] == [docker, next_row]

    # Returning to root measurements must also start a separate history.
    root = {**sample(next_time), **capacity()}
    metrics.save_sample(path, "host", root)
    current = metrics.read_metrics(path, now=next_time)
    assert current["disk_path"] == "/"
    assert current["samples"] == [root]


def test_history_survives_restart_is_bounded_and_reports_staleness(tmp_path):
    path = tmp_path / "history.json"
    rows = [sample(NOW - timedelta(minutes=1440 - i)) for i in range(1440)]
    path.write_text(
        json.dumps(
            dict(
                version=1,
                hostname="host",
                disk_path="/",
                interval_seconds=60,
                samples=rows,
            )
        )
    )
    latest = {**sample(), **capacity()}
    metrics.save_sample(path, "host", latest)
    stored = metrics.load_history(path)
    assert len(stored["samples"]) == 1440
    assert stored["samples"][0]["time"] == (NOW - timedelta(minutes=1439)).isoformat()
    assert stored["samples"][-1] == latest
    assert "cpu_count" not in stored["samples"][0]
    assert path.stat().st_mode & 0o777 == 0o644
    assert not path.with_suffix(".tmp").exists()
    assert metrics.read_metrics(path, "1h", NOW)["samples"] == stored["samples"][-61:]
    stale = metrics.read_metrics(path, "1h", NOW + timedelta(minutes=4))
    assert stale["status"] == "stale" and stale["samples"]
    assert stale["last_sample_at"] == NOW.isoformat()
    expired = metrics.read_metrics(path, "24h", NOW + timedelta(days=2))
    assert expired["status"] == "stale" and expired["samples"] == []
    # Repeated timestamps replace the sample; switching hosts drops old history.
    metrics.save_sample(path, "host", latest)
    assert len(metrics.load_history(path)["samples"]) == 1440
    assert metrics.read_metrics(path, now=NOW)["samples"][-1] == latest
    metrics.save_sample(path, "other-host", sample())
    assert metrics.load_history(path)["samples"] == [sample()]


@pytest.mark.parametrize(
    "invalid",
    [
        {"cpu_count": True},
        {"cpu_count": 0},
        {"cpu_count": 1.5},
        {"memory_used_bytes": -1},
        {"memory_used_bytes": 101 * 1024},
        {"memory_total_bytes": 0},
        {"disk_used_bytes": 1001},
        {"disk_total_bytes": None},
        {"disk_total_bytes": 2**53},
    ],
)
def test_invalid_capacity_is_unavailable(tmp_path, invalid):
    path = tmp_path / "history.json"
    metrics.save_sample(path, "host", {**sample(), **capacity(), **invalid})
    assert metrics.read_metrics(path, now=NOW)["status"] == "unavailable"


def test_missing_capacity_is_not_invented_and_zero_usage_is_preserved(tmp_path):
    path = tmp_path / "history.json"
    metrics.save_sample(path, "host", sample())
    assert metrics.read_metrics(path, now=NOW)["samples"] == [sample()]
    partial = {**sample(), "cpu_count": 8}
    metrics.save_sample(path, "host", partial)
    assert metrics.read_metrics(path, now=NOW)["status"] == "unavailable"
    zero = {**sample(), **capacity(), "memory_used_bytes": 0, "disk_used_bytes": 0}
    metrics.save_sample(path, "host", zero)
    assert metrics.read_metrics(path, now=NOW)["samples"] == [zero]


def test_root_disk_history_upgrade_preserves_unknown_readings_and_available_space(tmp_path):
    path = tmp_path / "history.json"
    old = {**sample(NOW - timedelta(minutes=2)), **capacity()}
    current = {**sample(NOW - timedelta(minutes=1)), **capacity(),
               "disk_available_bytes": 350, "disk_is_root": False,
               "root_disk_percent": 97, "root_disk_used_bytes": 970,
               "root_disk_total_bytes": 1000, "root_disk_available_bytes": 20}
    latest = {**current, "time": NOW.isoformat()}
    for row in (old, current, latest):
        metrics.save_sample(path, "host", row, "/srv/openaidr")
    assert metrics.read_metrics(path, now=NOW)["samples"] == [old, current, latest]
    for range_name in ("7d", "30d"):
        result = metrics.read_metrics(path, range_name, NOW)
        assert result["status"] == "ok"
        # A mixed old/new bucket is unknown, never a diluted or zero reading.
        assert [point["root_disk_percent"] for point in result["samples"]] == [None, 97]
        assert result["latest_sample"] == latest
    # Downgrading the collector does not relabel stale root readings as current.
    metrics.save_sample(path, "host", {**old, "time": NOW.isoformat()}, "/srv/openaidr")
    assert "root_disk_percent" not in metrics.read_metrics(path, now=NOW)["samples"][-1]


@pytest.mark.parametrize("invalid", [
    {"disk_is_root": 1}, {"disk_available_bytes": 401},
    {"root_disk_percent": None}, {"root_disk_percent": 101},
    {"root_disk_available_bytes": -1}, {"root_disk_available_bytes": 31},
    {"root_disk_total_bytes": 0}, {"root_disk_used_bytes": True},
])
def test_invalid_filesystem_measurements_are_unavailable(tmp_path, invalid):
    path = tmp_path / "history.json"
    row = {**sample(), **capacity(), "disk_available_bytes": 350, "disk_is_root": False,
           "root_disk_percent": 97, "root_disk_used_bytes": 970,
           "root_disk_total_bytes": 1000, "root_disk_available_bytes": 20}
    metrics.save_sample(path, "host", {**row, **invalid}, "/srv/openaidr")
    assert metrics.read_metrics(path, now=NOW)["status"] == "unavailable"


@pytest.mark.parametrize(
    "invalid", [True, -1, 101, float("nan"), float("inf"), "25", None]
)
def test_invalid_metrics_are_unavailable_without_inventing_zeros(tmp_path, invalid):
    path = tmp_path / "history.json"
    metrics.save_sample(path, "host", sample())
    data = json.loads(path.read_text())
    data["samples"][0]["cpu_percent"] = invalid
    path.write_text(json.dumps(data))
    result = metrics.read_metrics(path, now=NOW)
    assert result["status"] == "unavailable" and result["samples"] == []


def test_missing_corrupt_and_future_history(tmp_path):
    path = tmp_path / "history.json"
    assert metrics.read_metrics("")["status"] == "disabled"
    assert metrics.read_metrics(path)["status"] == "waiting"
    for invalid in ("{", "null", "[]", "{}", "x" * (metrics.MAX_BYTES + 1)):
        path.write_text(invalid)
        assert metrics.read_metrics(path)["status"] == "unavailable"
    metrics.save_sample(path, "host", sample(NOW + timedelta(hours=1)))
    assert metrics.read_metrics(path, now=NOW)["status"] == "unavailable"


def test_service_cpu_history_preserves_gaps_zeroes_and_five_minute_range(tmp_path):
    path = tmp_path / "history.json"
    latest = {**sample(), **capacity(), "service_cpu_percent": {
        "postgres": 48.2, "server": 0, "dashboard": None,
    }}
    metrics.save_sample(path, "host", sample(NOW - timedelta(minutes=6)))
    metrics.save_sample(path, "host", latest)
    assert metrics.read_metrics(path, "5m", NOW)["samples"] == [latest]
    assert "service_cpu_percent" not in metrics.read_metrics(path, "1h", NOW)["samples"][0]
    for values in ({"postgres": 1}, {"postgres": True, "server": 0, "dashboard": None},
                   {"postgres": 101, "server": 0, "dashboard": None}):
        metrics.save_sample(path, "host", {**latest, "service_cpu_percent": values})
        assert metrics.read_metrics(path, now=NOW)["status"] == "unavailable"


def test_month_archive_retains_history_across_restarts_and_bounds_responses(tmp_path):
    path = tmp_path / "history.json"
    rows = [{**sample(NOW - timedelta(minutes=43200 - i)), **capacity(),
             "service_cpu_percent": {"postgres": 10, "server": 0, "dashboard": None},
             **({"root_disk_percent": 97, "root_disk_used_bytes": 970,
                 "root_disk_total_bytes": 1000, "root_disk_available_bytes": 20}
                if i >= 40000 else {})}
            for i in range(43201)]
    history = dict(version=1, hostname="host", disk_path="/", interval_seconds=60, samples=rows)
    metrics.host_metrics_history.record(path, history)
    path.write_text(json.dumps({**history, "samples": rows[-1440:]}))
    metrics.save_sample(path, "host", rows[-1])
    with sqlite3.connect(path.with_suffix(".sqlite3")) as db:
        assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 43200
        assert db.execute("SELECT MIN(at) FROM samples").fetchone()[0] > (NOW - timedelta(days=30)).timestamp()
    assert path.with_suffix(".sqlite3").stat().st_mode & 0o777 == 0o644
    for range_name, interval, limit, count in (("7d", 600, 1009, 10081), ("30d", 1800, 1441, 43200)):
        result = metrics.read_metrics(path, range_name, NOW)
        assert result["status"] == "ok"
        assert result["interval_seconds"] == interval
        assert len(result["samples"]) <= limit
        assert result["latest_sample"] == rows[-1]
        assert result["samples"][0]["root_disk_percent"] is None
        assert result["samples"][-1]["root_disk_percent"] == 97
        assert any(point["root_disk_percent"] == 97
                   and metrics.timestamp(point["time"]) < NOW - timedelta(days=1)
                   for point in result["samples"])
        summary = result["service_cpu_summary"]
        assert summary["total_samples"] == count
        assert summary["services"]["postgres"]["percent"] == 10
        assert summary["services"]["postgres"]["cores"] == pytest.approx(0.8)
        assert summary["services"]["server"]["percent"] == 0
        assert summary["services"]["dashboard"]["percent"] is None
    assert len(metrics.read_metrics(path, "24h", NOW)["samples"]) == 1440
    # Old deployments need no migration and keep their existing recent history.
    path.with_suffix(".sqlite3").unlink()
    assert metrics.read_metrics(path, "30d", NOW)["service_cpu_summary"]["total_samples"] == 1440


def test_long_ranges_preserve_gaps_latest_values_and_weighted_service_averages(tmp_path):
    path = tmp_path / "history.json"
    rows = []
    for minutes, cpu, postgres in ((20, 90, 60), (19, 30, 0), (1, 0, None), (0, 20, 30)):
        row = {**sample(NOW - timedelta(minutes=minutes)), **capacity(), "cpu_percent": cpu,
               "service_cpu_percent": {"postgres": postgres, "server": 0, "dashboard": None}}
        rows.append(row)
        metrics.save_sample(path, "host", row)
    result = metrics.read_metrics(path, "7d", NOW)
    assert [point["cpu_percent"] for point in result["samples"]] == [60, 0, 20]
    assert result["samples"][1]["gap_before"] is True
    assert result["samples"][1]["service_cpu_percent"]["postgres"] is None
    assert result["latest_sample"] == rows[-1]
    assert result["service_cpu_summary"]["services"]["postgres"] == dict(count=3, percent=30, cores=2.4)
    assert metrics.read_metrics(path, "30d", NOW + timedelta(days=31))["samples"] == []
    assert metrics.read_metrics(path, "30d", NOW + timedelta(minutes=4))["status"] == "stale"
    # Changing sources must never relabel the previous month's measurements.
    metrics.save_sample(path, "other", rows[-1], disk_path="/srv/openaidr")
    assert metrics.read_metrics(path, "30d", NOW)["service_cpu_summary"]["total_samples"] == 1


def test_archive_failure_keeps_recent_collection_and_reports_long_range_failure(tmp_path):
    path = tmp_path / "history.json"
    archive = path.with_suffix(".sqlite3")
    archive.write_text("corrupt")
    metrics.save_sample(path, "host", sample())
    assert metrics.read_metrics(path, "24h", NOW)["samples"] == [sample()]
    result = metrics.read_metrics(path, "30d", NOW)
    assert result["status"] == "unavailable"
    assert result["message"] == "Host metrics archive could not be read."
