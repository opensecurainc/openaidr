"""Cross-platform detection boundaries and engine failure recovery."""

from datetime import datetime, timezone
import pytest
from openaidr.server.detect_paths import (
    glob_match,
    host_match,
    is_secret_path,
    is_rootish,
    outside_cwd,
    is_temp_path,
    secret_refs,
)
from openaidr.server.detect_commands import split, host_of
from openaidr.server.detect import Allowlist, Engine, SessionContext, evaluate_session


@pytest.mark.parametrize(
    "value",
    [
        "/Users/me/repo/.env",
        ".env.production",
        "/home/u/.aws/credentials",
        "/home/u/.ssh/id_ed25519",
        r"C:\Users\u\.kube\config",
        "certs/server.pem",
        "/srv/app/service-account.json",
        "~/.npmrc",
        "/Users/me/.claude/.credentials.json",
        "/home/u/.git-credentials",
    ],
)
def test_secret_paths(value):
    assert is_secret_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "/Users/me/repo/.env.example",
        "/home/u/.ssh/id_ed25519.pub",
        "/home/u/.ssh/known_hosts",
        "src/main.py",
        "README.md",
        "/home/u/.config/nvim/init.lua",
        "credentials.yml.enc",
    ],
)
def test_public_paths(value):
    assert not is_secret_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "/",
        "/*",
        "~",
        "~/",
        "$HOME",
        "${HOME}",
        "/Users/me",
        "/home/me/",
        "C:\\",
        "/etc",
        "/usr",
        "/Users/me/*",
        "C:/Windows",
        "C:/Program Files",
        "%USERPROFILE%",
        "/System",
        "/Applications",
    ],
)
def test_rootish(value):
    assert is_rootish(value)


@pytest.mark.parametrize(
    "value",
    ["/Users/me/repo", "build", "./dist", "/tmp/x", "/home/me/proj/node_modules"],
)
def test_nonrootish(value):
    assert not is_rootish(value)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("src/a.py", False),
        ("/Users/me/repo/x", False),
        ("../other/x", True),
        ("/Users/me/other", True),
        ("~/x", True),
        ("$HOME/.zshrc", True),
        ("/tmp/x", True),
        ("./build", False),
        ("/Users/me/repo", False),
        ("C:/Users/me/repo/x", True),
        ("/Users/me/repository/a", True),
    ],
)
def test_workspace_boundary(value, expected):
    assert outside_cwd(value, "/Users/me/repo") == expected
    assert not outside_cwd(value, "")


@pytest.mark.parametrize(
    "pattern,value,expected",
    [
        ("**/.ssh/id_*", "/home/u/.ssh/id_rsa", True),
        ("~/.aws/credentials", "/Users/me/.aws/credentials", True),
        ("/srv/app/**", "/srv/app/logs/x.log", True),
        ("/srv/app/*", "/srv/app/logs/x.log", False),
        ("*.example.com", "api.example.com", True),
        ("*.example.com", "example.com", False),
        (r"C:\Users\**", "C:/Users/me/x", True),
        ("file?.txt", "file1.txt", True),
        ("file?.txt", "file12.txt", False),
        ("", "anything", False),
    ],
)
def test_glob_boundaries(pattern, value, expected):
    assert glob_match(pattern, value) == expected


def test_allowlist_private_hosts_and_domain_boundaries():
    allow = Allowlist(hosts=["*.github.com", "github.com", "pypi.org"])
    assert host_match("example.com", "sub.example.com")
    assert not host_match("example.com", "notexample.com")
    for host in [
        "api.github.com",
        "github.com",
        "pypi.org",
        "localhost",
        "10.0.0.5",
        "172.20.1.1",
    ]:
        assert allow.host_allowed(host)
    for host in ["files.pythonhosted.org", "172.40.1.1"]:
        assert not allow.host_allowed(host)
    # An allowed path suppresses findings only for the kinds its rule
    # allows, so a read-only allow does not hide writes.
    rules = [
        {"enabled": True, "action": "allow", "match": {"path_glob": "**/.aws/**", "kinds": ["file.read"]}},
        {"enabled": True, "action": "allow", "match": {"path_glob": "/srv/**", "kinds": ["file.write"] * 1000}},
        {"enabled": True, "action": "allow", "match": {"path_glob": "/srv/**", "kinds": ["file.write"]}},
        {"enabled": True, "action": "allow", "match": {"path_glob": "/cache/**", "kinds": ["command"]}},
        {"enabled": True, "action": "allow", "match": {"path_glob": "/opt/**"}},
        {"enabled": True, "action": "allow", "match": {"path_glob": "/var/both/**", "kinds": "command,file.write"}},
        # Scoped by a condition the allowlist cannot check.
        {"enabled": True, "action": "allow", "match": {"path_glob": "/home/a/.aws/**", "kinds": ["file.write"], "products": ["claude-code"]}},
        # Stored before kinds were validated; they must not break detection
        # or suppress findings.
        *[
            {"enabled": True, "action": "allow", "match": {"path_glob": "/tmp/odd/**", "kinds": bad}}
            for bad in (1, 0, False, {})
        ],
    ]
    allow = Allowlist.from_policy({"rules": rules})
    assert not allow.path_allowed("/home/a/.aws/credentials", "file.write")
    assert not allow.path_allowed("/home/a/.aws/config", "command")
    assert allow.path_allowed("/srv/x", "file.write") and not allow.path_allowed("/srv/x", "command")
    assert allow.path_allowed("/cache/x", "command") and not allow.path_allowed("/cache/x", "file.write")
    assert allow.path_allowed("/opt/x", "file.write") and allow.path_allowed("/opt/x", "command")
    assert not allow.path_allowed("/tmp/odd/x", "file.write")
    assert not allow.path_allowed("/tmp/odd/x", "command")
    # A string of kinds is read as the sensor reads it.
    assert allow.path_allowed("/var/both/x", "command") and allow.path_allowed("/var/both/x", "file.write")
    # A glob is kept once per kind, however often a rule repeats the kind.
    assert allow.kind_paths["file.write"].count("/srv/**") == 1
    # Kinds no path finding checks are not indexed.
    assert set(allow.kind_paths) == {"command", "file.write"}
    assert host_of("https://user:pw@Example.COM:8443/path?x=1") == "example.com"
    assert is_temp_path(r"C:\Users\Alice\AppData\Local\Temp\scratch")
    assert secret_refs(
        split("cat ~/.aws/credentials; echo $API_KEY"),
        "cat ~/.aws/credentials; echo $API_KEY",
    ) == ["~/.aws/credentials", "$API_KEY"]


def test_system_directory_deletion_is_critical():
    event = dict(
        id="event",
        time=datetime.now(timezone.utc).isoformat(),
        kind="command",
        command={"text": "rm -rf /etc"},
        agent={},
        host={},
        session={"cwd": "/work"},
    )
    found = [
        hit
        for hit in evaluate_session([event])
        if hit["rule"]["id"] == "destructive-command"
    ]
    assert found[0]["candidate"]["severity"] == "critical"


class MemoryStore:
    """Persistence double with failures at the two durable batch boundaries."""

    def __init__(self, fail):
        self.fail = fail
        self.cursor = None
        self.findings = []
        at = datetime.now(timezone.utc)
        self.row = dict(
            id="event",
            received_at=at,
            time=at,
            kind="file.read",
            session_id="session",
            sensor_id="sensor",
            product="claude-code",
            body={
                "id": "event",
                "time": at.isoformat(),
                "kind": "file.read",
                "file": {"path": "/work/.env"},
                "session": {"id": "session", "cwd": "/work"},
            },
        )

    def active_tenant_ids(self):
        return ["tenant"]

    def get_detect_cursor(self, tenant):
        return self.cursor

    def events_after(self, tenant, cursor, limit):
        return [] if cursor else [self.row]

    def get_policy(self, tenant):
        return {"rules": []}

    def disabled_rules(self, tenant):
        return {}

    def insert_finding(self, finding):
        if self.fail == "insert":
            self.fail = None
            raise RuntimeError("database unavailable")
        if finding in self.findings:
            return False
        self.findings.append(finding)
        return True

    def set_detect_cursor(self, tenant, cursor):
        if self.fail == "cursor":
            self.fail = None
            raise RuntimeError("cursor unavailable")
        self.cursor = cursor


@pytest.mark.parametrize("failure", ["insert", "cursor"])
@pytest.mark.parametrize("existing_session", [False, True])
def test_engine_retries_failed_persistence_without_losing_finding(failure, existing_session):
    store = MemoryStore(failure)
    engine = Engine(store)
    untouched = SessionContext("tenant", "untouched")
    foreign = SessionContext("foreign", "session")
    engine.sessions.update({("tenant", "untouched"): untouched, ("foreign", "session"): foreign})
    if existing_session:
        previous = SessionContext("tenant", "session")
        previous.observe({**store.row["body"], "kind": "response", "text": "Earlier activity"})
        engine.sessions[("tenant", "session")] = previous
    with pytest.raises(RuntimeError):
        engine.tick()
    assert not store.cursor
    assert engine.sessions[("tenant", "untouched")] is untouched
    assert engine.sessions[("foreign", "session")] is foreign
    if existing_session:
        restored = engine.sessions[("tenant", "session")]
        assert restored.sequence == 1 and restored.data == {}
        assert len(restored.recent) == 1 and restored.recent[0]["kind"] == "response"
    else:
        assert ("tenant", "session") not in engine.sessions
    engine.tick()
    assert store.cursor and len(store.findings) == 1
    assert engine.tick() == 0


def test_triager_error_skips_candidate_and_advances_cursor(caplog):
    store = MemoryStore(None)
    engine = Engine(store)

    def broken_triager(*args):
        raise RuntimeError("triage failed")

    engine.triager = broken_triager
    assert engine.tick() == 0
    assert store.cursor and not store.findings
    assert "triage failed" in caplog.text


def test_engine_restores_each_session_to_before_the_failed_batch():
    class BatchStore(MemoryStore):
        def events_after(self, tenant, cursor, limit):
            return [] if cursor else [
                {**self.row, "id": str(i), "kind": "response", "session_id": session,
                 "body": {**self.row["body"], "id": str(i), "kind": "response"}}
                for i, session in enumerate(("existing", "new", "existing"))
            ]

    store = BatchStore("cursor")
    engine = Engine(store)
    existing = SessionContext("tenant", "existing")
    existing.observe({**store.row["body"], "kind": "response"})
    engine.sessions[("tenant", "existing")] = existing
    with pytest.raises(RuntimeError):
        engine.tick()
    assert set(engine.sessions) == {("tenant", "existing")}
    restored = engine.sessions[("tenant", "existing")]
    assert restored.sequence == 1 and len(restored.recent) == 1 and restored.data == {}
    engine.tick()
    assert engine.sessions[("tenant", "existing")].sequence == 3
    assert engine.sessions[("tenant", "new")].sequence == 1


def test_engine_failure_preserves_previously_committed_batch_state():
    class TwoBatchStore(MemoryStore):
        def __init__(self):
            super().__init__(None)
            self.rows = [
                self.row,
                {
                    **self.row,
                    "id": "event2",
                    "body": {
                        **self.row["body"],
                        "id": "event2",
                        "file": {"path": "/work/.npmrc"},
                    },
                },
            ]
            self.failed = False

        def events_after(self, tenant, cursor, limit):
            position = next(
                (
                    i + 1
                    for i, row in enumerate(self.rows)
                    if cursor and row["id"] == cursor["id"]
                ),
                0,
            )
            return self.rows[position : position + limit]

        def insert_finding(self, finding):
            if finding["primary_event_id"] == "event2" and not self.failed:
                self.failed = True
                raise RuntimeError("second batch failed")
            return super().insert_finding(finding)

    store = TwoBatchStore()
    engine = Engine(store)
    engine.batch_size = 1
    with pytest.raises(RuntimeError):
        engine.tick()
    assert store.cursor["id"] == "event"
    assert engine.sessions[("tenant", "session")].sequence == 1
    assert engine.tick() == 1
    assert store.cursor["id"] == "event2"
    assert len(store.findings) == 2
