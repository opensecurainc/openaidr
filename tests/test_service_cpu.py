from openaidr.server import service_cpu as cpu


def process(root, pid, name, group):
    directory = root / "proc" / str(pid)
    directory.mkdir(parents=True)
    (directory / "comm").write_text(name + "\n")
    (directory / "cgroup").write_text("0::" + group + "\n")


def counter(root, group, value):
    directory = root / "sys/fs/cgroup" / group.lstrip("/")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cpu.stat").write_text(f"usage_usec {value}\nuser_usec 0\nsystem_usec 0\n")


def test_host_cgroups_are_deduplicated_and_changes_leave_gaps(tmp_path):
    pg = "/system.slice/docker-" + "a" * 64 + ".scope"
    api = "/docker/" + "b" * 64
    dashboard = "/docker/" + "c" * 64
    for pid, name, group in ((1, "postgres", pg), (2, "postgres", pg),
                             (3, "openaidr-server", api), (4, "next-server (v1", dashboard)):
        process(tmp_path, pid, name, group)
        counter(tmp_path, group, 1_000_000)
    (tmp_path / "sys/fs/cgroup/cgroup.controllers").write_text("cpu memory")
    first = cpu.snapshot(tmp_path)
    assert len(first["postgres"]) == 1
    counter(tmp_path, pg, 61_000_000)
    counter(tmp_path, api, 16_000_000)
    second = cpu.snapshot(tmp_path)
    assert cpu.percentages(first, second, 60, 2) == {
        "postgres": 50, "server": 12.5, "dashboard": 0,
    }
    second["postgres"][pg] = 121_240_000
    assert cpu.percentages(first, second, 60, 2)["postgres"] == 100
    second["postgres"][pg] = 241_000_000
    assert cpu.percentages(first, second, 60, 2)["postgres"] is None
    second["postgres"] = {"replacement": 61_000_000}
    second["server"][api] = 0
    second["dashboard"] = {}
    assert cpu.percentages(first, second, 60, 2) == dict.fromkeys(cpu.SERVICES)
    # Two services sharing a container cannot be attributed independently.
    process(tmp_path, 5, "openaidr-server", pg)
    assert cpu.snapshot(tmp_path) is None


def test_unsupported_inaccessible_and_private_namespace_are_unavailable(tmp_path):
    assert cpu.snapshot(tmp_path) is None
    process(tmp_path, 1, "postgres", "/../docker/" + "a" * 64)
    counter(tmp_path, "/", 123)
    (tmp_path / "sys/fs/cgroup/cgroup.controllers").write_text("cpu")
    assert cpu.snapshot(tmp_path) is None
    (tmp_path / "proc/1/cgroup").write_text("0::/\n")
    assert cpu.percentages(cpu.snapshot(tmp_path), cpu.snapshot(tmp_path), 60, 2) == dict.fromkeys(cpu.SERVICES)
    assert cpu.percentages(None, None, 60, 2) == dict.fromkeys(cpu.SERVICES)
