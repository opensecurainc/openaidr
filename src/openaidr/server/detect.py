"""Stateful built-in detection rules and PostgreSQL polling engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import logging
import copy
import posixpath as path
import re
from .detect_commands import split, egresses, host_of, non_flag_args
from .detect_paths import (
    glob_match,
    host_match,
    norm_path,
    is_secret_path,
    secret_refs,
    is_temp_path,
    is_agent_dir,
    is_rootish,
    outside_cwd,
    has_production_marker,
)
from .detect_constants import RULES, AGENT_CONFIG_PATHS

RULE_INDEX = {rule["id"]: rule for rule in RULES}


def rule_by_id(rule_id):
    return RULE_INDEX.get(rule_id)


def rule_name(rule_id):
    return RULE_INDEX.get(rule_id, {}).get("name", rule_id)


def rule_list(disabled=None, counts=None):
    disabled, counts = disabled or {}, counts or {}
    return [
        dict(
            r,
            enabled=not disabled.get(r["id"], False),
            builtin=True,
            findings_30d=counts.get(r["id"], 0),
        )
        for r in sorted(RULES, key=lambda r: r["id"])
    ]


def timestamp(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc)
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value
        else datetime.now(timezone.utc)
    )


def truncate(s, n):
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


# Event kinds whose findings an allowed path suppresses: recursive deletes
# (command) and out-of-scope writes (file.write).
PATH_FINDING_KINDS = ("command", "file.write")
# Rule conditions a path allowlist entry cannot check.
PATH_UNCHECKED_CONDITIONS = ("products", "tool_name", "command_regex", "host_glob")


@dataclass
class Allowlist:
    hosts: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    # Path globs that allow only some event kinds, keyed by kind.
    kind_paths: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_policy(cls, policy):
        rules = [
            r.get("match", {})
            for r in policy.get("rules", [])
            if r.get("enabled") and r.get("action") == "allow"
        ]
        paths, kind_paths = {}, {}
        for r in rules:
            glob, kinds = r.get("path_glob"), r.get("kinds")
            # The allowlist cannot check other conditions, such as products,
            # so a path allow scoped by them suppresses nothing.
            if (
                not glob
                or not isinstance(glob, str)
                or any(r.get(k) for k in PATH_UNCHECKED_CONDITIONS)
            ):
                continue
            # No kinds, or empty ones, match every kind, as in the sensor.
            if kinds is None or (isinstance(kinds, (str, list)) and not kinds):
                paths[glob] = True
                continue
            # A rule scoped to some kinds suppresses findings only for those
            # kinds, so a read-only allow does not hide writes. Only the
            # kinds path findings check are indexed, each once; malformed
            # kinds, including falsy ones such as 0 or false, suppress
            # nothing. Membership is tested as the sensor tests it, so a
            # string such as "command,file.write" covers both kinds.
            if isinstance(kinds, (str, list)):
                for kind in PATH_FINDING_KINDS:
                    if kind in kinds:
                        kind_paths.setdefault(kind, {})[glob] = True
        return cls(
            [r["host_glob"] for r in rules if r.get("host_glob")],
            list(paths),
            {kind: list(globs) for kind, globs in kind_paths.items()},
        )

    def host_allowed(self, host):
        host = host.lower()
        if (
            not host
            or host == "localhost"
            or host.endswith((".localhost", ".local"))
            or host.startswith(("127.", "10.", "192.168.", "0.0.0.0"))
            or host == "::1"
        ):
            return True
        parts = host.split(".")
        if (
            len(parts) == 4
            and parts[0] == "172"
            and parts[1].isdigit()
            and 16 <= int(parts[1]) <= 31
        ):
            return True
        return any(host_match(p, host) for p in self.hosts)

    def path_allowed(self, p, kind):
        p = norm_path(p)
        return any(
            glob_match(g, p) for g in (*self.paths, *self.kind_paths.get(kind, ()))
        )


@dataclass
class SessionContext:
    tenant_id: str = "t"
    session_id: str = "s"
    cwd: str = ""
    product: str = ""
    allow: Allowlist = field(default_factory=Allowlist)
    recent: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    last_seen: datetime | None = None
    sequence: int = 0

    def observe(self, e):
        self.cwd = (
            e.get("session", {}).get("cwd")
            or self.cwd
            or e.get("command", {}).get("cwd", "")
        )
        self.product = self.product or e.get("agent", {}).get("product", "")
        t = timestamp(e.get("time"))
        self.last_seen = max(self.last_seen, t) if self.last_seen else t
        # Sensors record every policy check; one no rule matched still
        # describes the session but is not activity, so it must not enter or
        # age correlation windows.
        hook = e.get("hook") or {}
        if (
            e.get("kind") == "hook.decision"
            and isinstance(e.get("source"), dict)
            and e["source"].get("collector") == "hook"
            and hook.get("decision") == "allow"
            and not hook.get("rule_id")
        ):
            return
        # Preserve event positions while retaining only tool-error correlation data.
        tool, file, command = (e.get(key) for key in ("tool", "file", "command"))
        recent = dict(
            kind=e["kind"],
            call_id=tool.get("call_id") if isinstance(tool, dict) else None,
            path=file.get("path", "") if isinstance(file, dict) else "",
            command=command.get("text", "") if isinstance(command, dict) else "",
        )
        self.recent = (self.recent + [recent])[-300:]
        self.sequence += 1


def _action(e):
    if e.get("command", {}).get("text"):
        return e["command"]["text"]
    if e.get("file"):
        return e["file"].get("op", "") + " " + e["file"]["path"]
    return e.get("network", {}).get("url") or e.get("tool", {}).get("name") or e["kind"]


def _where(sc, e):
    cwd = e.get("command", {}).get("cwd") or sc.cwd or "an unknown directory"
    who = e.get("agent", {}).get("product", "")
    host = e.get("host", {})
    if host.get("user"):
        who += " for " + host["user"]
    if host.get("hostname"):
        who += " on " + host["hostname"]
    return f"{cwd} ({who})"


SQL_DROP = re.compile(
    r'\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|USER|ROLE)|TRUNCATE(\s+TABLE)?\s+[a-z_"\[]|DELETE\s+FROM\s+\S+\s*(;|$))',
    re.I,
)
URL_SOURCE = re.compile(
    r"(https?://\S+|git\+\S+|git@[^\s:]+:\S+|github:\S+|gitlab:\S+|bitbucket:\S+|ssh://\S+)",
    re.I,
)


def _destructive(sc, e, segs):
    text = e["command"]["text"]
    cwd = e["command"].get("cwd") or sc.cwd
    reasons, levels = [], []

    def add(reason, severity="high"):
        reasons.append(reason)
        levels.append(severity)

    for s in segs:
        a, name = s.args, s.name
        aset, lower = set(a), {v.lower() for v in a}
        if name == "rm" or name in ("remove-item", "rmdir", "rd", "del", "erase"):
            recursive = (
                any(
                    x == "--recursive"
                    or x.startswith("-")
                    and not x.startswith("--")
                    and any(c in x for c in "rR")
                    for x in a
                )
                if name == "rm"
                else bool(
                    lower & ({"-recurse", "-r"} if name == "remove-item" else {"/s"})
                )
            )
            if not recursive:
                continue
            for target in non_flag_args(a):
                if name != "rm" and target.startswith("/") and len(target) <= 3:
                    continue
                if is_rootish(target):
                    add("recursive delete of " + target, "critical")
                elif name == "rm" and norm_path(target).strip() in (
                    ".",
                    "./",
                    "*",
                    "./*",
                    "..",
                    "../",
                    "../*",
                    ".*",
                ):
                    add("recursive delete wipes the working directory (" + target + ")")
                elif (
                    outside_cwd(target, cwd)
                    and not is_temp_path(target)
                    and not sc.allow.path_allowed(target, "command")
                ):
                    add("recursive delete outside the workspace: " + target)
        elif name == "git" and a:
            verb = a[0]
            if verb == "push":
                if any(
                    x in ("-f", "--force", "--mirror")
                    or x.startswith("-f")
                    and not x.startswith("--")
                    and len(x) <= 3
                    for x in a[1:]
                ):
                    add("force push")
                if aset & {"--delete", "-d"}:
                    add("remote branch delete", "medium")
            elif verb == "reset" and "--hard" in aset:
                add("git reset --hard discards uncommitted work", "medium")
            elif verb == "clean" and any(x.startswith("-") and "f" in x for x in a[1:]):
                add("git clean removes untracked files", "medium")
            elif verb == "branch" and "-D" in aset:
                add("git branch -D discards a branch", "medium")
            elif verb in ("filter-branch", "filter-repo"):
                add("history rewrite with " + verb)
        elif name in ("kubectl", "oc", "helm"):
            verbs = {"uninstall", "delete"} if name == "helm" else {"delete", "drain"}
            if set(a[:7]) & verbs:
                add(name + " " + " ".join(a))
        elif (
            name in ("terraform", "tofu", "pulumi")
            and a
            and (
                a[0] == "destroy"
                or a[0] == "apply"
                and aset & {"-destroy", "-auto-approve"}
            )
        ):
            add(name + " " + " ".join(a))
        elif (
            name in ("docker", "podman")
            and len(a) > 1
            and (
                a[:2] == ["system", "prune"]
                or a[0] == "volume"
                and a[1] in ("rm", "prune")
                or a[0] == "rm"
                and aset & {"-f", "--force"}
                and aset & {"-v", "--volumes"}
            )
        ):
            add(name + " " + " ".join(a[:2]))
        elif name in (
            "mkfs",
            "mkfs.ext4",
            "mkfs.xfs",
            "mkfs.btrfs",
            "diskutil",
            "wipefs",
            "shred",
            "format",
            "fdisk",
            "parted",
            "sgdisk",
        ):
            if name == "diskutil" and not aset & {
                "eraseDisk",
                "eraseVolume",
                "reformat",
                "zeroDisk",
                "randomDisk",
                "apfs",
            }:
                continue
            if name in ("fdisk", "parted", "sgdisk") and not aset & {
                "--zap-all",
                "-Z",
                "mklabel",
                "rm",
                "d",
            }:
                continue
            add("disk destruction with " + name, "critical")
        elif name == "dd" and any(x.startswith("of=/dev/") for x in a):
            add("dd writes to a raw device", "critical")
        elif name in ("chmod", "chown") and (
            "--recursive" in aset
            or any(x.startswith("-") and not x.startswith("--") and "R" in x for x in a)
        ):
            for target in non_flag_args(a):
                if is_rootish(target):
                    add(name + " -R on " + target, "critical")
        elif name == "find" and a and ("-delete" in aset or "-exec rm" in " ".join(a)):
            if is_rootish(a[0]):
                add("find -delete from " + a[0], "critical")
            elif outside_cwd(a[0], cwd) and not is_temp_path(a[0]):
                add("find -delete outside the workspace: " + a[0])
        elif name == "crontab" and "-r" in aset:
            add("crontab -r removes all cron jobs")
        elif name in ("iptables", "nft", "ufw") and aset & {
            "-F",
            "--flush",
            "flush",
            "reset",
            "disable",
        }:
            add("firewall rules flushed with " + name)
        elif name in ("psql", "mysql", "sqlite3", "mongosh", "mongo", "redis-cli") and (
            SQL_DROP.search(" ".join(a))
            or lower & {"flushall", "flushdb", "dropdatabase()"}
        ):
            add("destructive database statement via " + name)
        elif name in ("dropdb", "dropuser"):
            add(name + " " + " ".join(a))
        elif (
            name in ("launchctl", "systemctl")
            and aset & {"disable", "mask"}
            and has_production_marker(text)
        ):
            add(name + " " + " ".join(a))
    if not reasons and SQL_DROP.search(text):
        add("SQL statement drops or truncates data")
    if not reasons:
        return []
    if has_production_marker(text):
        add("the command mentions production", "critical")
    severity = max(
        levels, key=lambda x: ["info", "low", "medium", "high", "critical"].index(x)
    )
    return [
        dict(
            severity=severity,
            title="Destructive command: " + truncate(text, 80),
            summary=f"The agent ran `{truncate(text, 300)}` in {_where(sc, e)}. Signals: "
            + "; ".join(dict.fromkeys(reasons))
            + ".",
        )
    ]


def evaluate_rule(rule_id, sc, e):
    kind, cmd, file, tool = (
        e["kind"],
        e.get("command", {}),
        e.get("file", {}),
        e.get("tool", {}),
    )
    text = cmd.get("text", "")
    segs = split(text) if kind == "command" else []
    state = sc.data.setdefault(rule_id, {})
    if rule_id == "secret-file-access":
        refs = (
            [file["path"]]
            if kind == "file.read" and is_secret_path(file.get("path", ""))
            else secret_refs(segs, text)
            if kind == "command"
            else []
        )
        accesses, reported = (
            state.setdefault("accesses", []),
            state.setdefault("reported", set()),
        )
        accesses.extend((e["id"], ref, e.get("time")) for ref in refs)
        fresh = [ref for ref in refs if ref not in reported]
        reported.update(fresh)
        if fresh:
            what = "ran a command referencing" if kind == "command" else "read"
            return [
                dict(
                    title="Secret access: " + truncate(", ".join(fresh), 80),
                    summary=f"The agent {what} {', '.join(fresh)} in {_where(sc, e)}.",
                )
            ]
    elif rule_id == "secret-then-egress":
        accesses = sc.data.get("secret-file-access", {}).get("accesses", [])
        hosts = (
            [(e["network"].get("host", ""), tool.get("name", "network request"))]
            if kind == "network" and e.get("network")
            else [(eg.host, eg.tool) for eg in egresses(segs)]
        )
        out = []
        for host, via in hosts:
            if sc.allow.host_allowed(host):
                continue
            fresh = [
                (eid, ref, t) for eid, ref, t in accesses if (ref, host) not in state
            ]
            if not fresh:
                continue
            for _, ref, _ in fresh:
                state[(ref, host)] = True
            ids = list(dict.fromkeys([a[0] for a in fresh] + [e["id"]]))
            refs = ", ".join(dict.fromkeys(a[1] for a in fresh))
            out.append(
                dict(
                    title="Secret access then egress to " + host,
                    summary=f"The agent accessed {refs} and then contacted {host} via {via} in {_where(sc, e)}.",
                    event_ids=ids,
                    first_event_at=min(
                        [timestamp(a[2]) for a in fresh] + [timestamp(e.get("time"))]
                    ),
                )
            )
        return out
    elif rule_id == "data-egress-command":
        out, seen = [], set()
        for eg in egresses(segs):
            if not eg.upload or sc.allow.host_allowed(eg.host) or eg.host in seen:
                continue
            seen.add(eg.host)
            files = truncate(", ".join(eg.files), 120) if eg.files else "local content"
            out.append(
                dict(
                    title=f"Upload to {eg.host} via {eg.tool}",
                    summary=f"The agent uploaded {files} to {eg.host} with `{truncate(text, 200)}` in {_where(sc, e)}.",
                )
            )
        return out
    elif rule_id == "destructive-command" and kind == "command":
        return _destructive(sc, e, segs)
    elif rule_id == "out-of-scope-write" and kind == "file.write" and file and sc.cwd:
        p = file["path"]
        directory = path.dirname(norm_path(p))
        if (
            outside_cwd(p, sc.cwd)
            and not is_temp_path(p)
            and not is_agent_dir(p)
            and not sc.allow.path_allowed(p, "file.write")
            and directory not in state
        ):
            state[directory] = True
            severity = (
                "high"
                if is_rootish(directory)
                or norm_path(p).startswith("/etc/")
                or norm_path(p).lower().startswith("c:/windows/")
                else "medium"
            )
            op = file.get("op") or "write"
            return [
                dict(
                    severity=severity,
                    title=f"File {op} outside workspace: {truncate(p, 70)}",
                    summary=f"The agent performed a {op} on {p} while working in {sc.cwd}.",
                )
            ]
    elif rule_id == "unknown-tool-install":
        if kind == "file.write" and file:
            p = norm_path(file["path"])
            for suffix, sev, what in AGENT_CONFIG_PATHS:
                if (
                    p.lower().endswith(suffix)
                    or suffix.endswith("/")
                    and suffix in p.lower()
                ):
                    return [
                        dict(
                            severity=sev,
                            title="Agent configuration modified: " + truncate(p, 70),
                            summary=f"The agent changed {what} at {p}. Changes here alter what the agent can run or which servers it trusts.",
                        )
                    ]
        out = []
        for eg in egresses(segs):
            if eg.pipe_to_shell and not sc.allow.host_allowed(eg.host):
                out.append(
                    dict(
                        title="Remote script piped to a shell from " + eg.host,
                        summary=f"The agent ran `{truncate(text, 200)}`, which executes code downloaded from {eg.host} without inspection.",
                    )
                )
        for s in segs:
            joined, what = " ".join(s.args), ""
            aset = set(s.args)
            if s.name in ("claude", "codex", "gemini") and joined.startswith("mcp add"):
                what = (
                    "MCP server added to "
                    + {
                        "claude": "Claude Code",
                        "codex": "Codex",
                        "gemini": "Gemini CLI",
                    }[s.name]
                )
            elif s.name == "claude" and joined.startswith(
                ("plugin install", "plugin marketplace add")
            ):
                what = "Claude Code plugin installed"
            elif s.name == "gemini" and joined.startswith("extensions install"):
                what = "Gemini CLI extension installed"
            elif s.name == "cursor" and "mcp" in joined:
                what = "MCP server added to Cursor"
            elif (
                s.name in ("pip", "pip3", "uv", "pipx")
                and aset & {"install", "add"}
                and URL_SOURCE.search(joined)
            ):
                what = "Python package installed from a URL or git source"
            elif (
                s.name in ("npm", "pnpm", "yarn", "bun")
                and aset & {"install", "i", "add"}
                and URL_SOURCE.search(joined)
            ):
                what = "Node package installed from a URL or git source"
            elif s.name == "cargo" and {"install", "--git"} <= aset:
                what = "Rust crate installed from git"
            elif (
                s.name == "go"
                and s.args[:1] == ["install"]
                and "@" in joined
                and not any(
                    h in joined
                    for h in (
                        "golang.org/",
                        "google.golang.org/",
                        "github.com/golang/",
                        "github.com/golangci/",
                        "honnef.co/",
                        "mvdan.cc/",
                        "gotest.tools/",
                        "sigs.k8s.io/",
                        "k8s.io/",
                    )
                )
            ):
                what = "Go binary installed from an unknown module host"
            if not what:
                continue
            match = URL_SOURCE.search(joined)
            source = match[0] if match else ""
            host = host_of(source)
            if host and sc.allow.host_allowed(host):
                continue
            out.append(
                dict(
                    title=what + ": " + truncate(source or joined, 60),
                    summary=f"{what} with `{truncate(text, 200)}` in {_where(sc, e)}. The source is not on the tenant allowlist.",
                )
            )
        return out
    elif rule_id == "error-then-delete":
        errors = state.setdefault("errors", [])
        if kind == "tool.result" and tool:
            if tool.get("is_error") or cmd.get("exit_code", 0):
                call = next(
                    (
                        r
                        for r in reversed(sc.recent)
                        if tool.get("call_id")
                        and r["kind"] != "tool.result"
                        and r["call_id"] == tool["call_id"]
                    ),
                    {},
                )
                errors.append(
                    dict(
                        id=e["id"],
                        time=timestamp(e.get("time")),
                        index=sc.sequence,
                        path=call.get("path", ""),
                        command=call.get("command", ""),
                    )
                )
                del errors[:-20]
            return []
        if not errors:
            return []
        deleted = (
            [file["path"]]
            if kind == "file.write" and file.get("op") == "delete"
            else []
        )
        discard = ""
        for s in segs:
            if s.name in ("rm", "unlink", "remove-item", "del"):
                deleted.extend(non_flag_args(s.args))
            elif s.name == "git" and s.args:
                a, verb = s.args, s.args[0]
                if (
                    verb == "checkout"
                    and (
                        "--" in a or "." in a or len(a) > 2 and not a[1].startswith("-")
                    )
                    or verb == "restore"
                    or verb == "stash"
                    and set(a) & {"drop", "clear"}
                    or verb == "reset"
                    and "--hard" in a
                    or verb == "clean"
                    and len(a) > 1
                    and "f" in a[1]
                ):
                    discard = "git " + verb + " discards changes"
        last = errors[-1]
        if (
            not (deleted or discard)
            or timestamp(e.get("time")) - last["time"] > timedelta(minutes=5)
            or sc.sequence - last["index"] > 20
        ):
            return []
        match = None
        for err in reversed(errors):
            if timestamp(e.get("time")) - err["time"] > timedelta(minutes=5):
                break
            for d in deleted:
                resolve = lambda p: path.normpath(
                    path.join(sc.cwd, norm_path(p))
                ).lower()
                if (
                    err["path"]
                    and resolve(err["path"]) == resolve(d)
                    or err["command"]
                    and len(d) > 3
                    and d in err["command"]
                ):
                    match = err
                    break
            if match:
                break
        severity = "medium" if match or discard else "low"
        match = match or last
        return [
            dict(
                severity=severity,
                title="Deletion after tool error: " + truncate(_action(e), 60),
                summary=f"A tool call failed and the agent then ran `{truncate(_action(e), 120)}`. "
                + (discard or "Deleted paths: " + ", ".join(deleted)),
                event_ids=[match["id"], e["id"]],
                first_event_at=min(match["time"], timestamp(e.get("time"))),
            )
        ]
    elif (
        rule_id == "hook-denied"
        and kind == "hook.decision"
        and "deny" in (e.get("hook", {}).get("decision"), e.get("hook", {}).get("enforced"))
    ):
        cat = (
            "data_exfiltration"
            if e.get("network")
            else "secret_exfiltration"
            if file and is_secret_path(file["path"])
            else "destructive_command"
            if cmd
            else "excessive_agency"
        )
        reason = e["hook"].get("reason") or "policy rule " + e["hook"].get(
            "rule_id", ""
        )
        return [
            dict(
                category=cat,
                title="Blocked: " + truncate(_action(e), 70),
                summary=f"The sensor blocked `{truncate(_action(e), 200)}` in {_where(sc, e)}. Reason: {reason}.",
            )
        ]
    return []


def evaluate_session(events, allow=None):
    sc = SessionContext(allow=allow or Allowlist())
    hits = []
    for event in events:
        for rule in RULES:
            for candidate in evaluate_rule(rule["id"], sc, event):
                hits.append(dict(rule=rule, candidate=candidate))
        sc.observe(event)
    return hits


class Engine:
    def __init__(self, store, log=None, tenant_id=""):
        self.store, self.log = store, log or logging.getLogger(__name__)
        self.interval, self.batch_size, self.idle_expiry = 2, 1000, timedelta(hours=2)
        self.sessions, self.last_run = {}, None
        self.triager = lambda sc, event, candidate: candidate
        # A tenant-bound backend evaluates only its own tenant.
        self.tenant_id = tenant_id or ""
        # Stored OTLP logs exports without events yet are translated before
        # each pass so telemetry stored before an upgrade becomes detectable.
        self.backfill_limit = 200

    def run(self, stop):
        while not stop.is_set():
            try:
                self.tick()
            except Exception:
                self.log.exception("detect tick")
            stop.wait(self.interval)

    def tenant_ids(self):
        if self.tenant_id:
            return [self.tenant_id]
        return self.store.active_tenant_ids()

    def backfill(self):
        translate = getattr(self.store, "translate_untranslated_exports", None)
        if not callable(translate):
            return None
        try:
            return translate(self.tenant_id or None, self.backfill_limit)
        except Exception:
            self.log.exception("telemetry export backfill")
            return None

    def tick(self):
        written = 0
        self.backfill()
        for tenant_id in self.tenant_ids():
            written += self.process_tenant(tenant_id)
        cutoff = datetime.now(timezone.utc) - self.idle_expiry
        self.sessions = {
            key: sc
            for key, sc in self.sessions.items()
            if not sc.last_seen or sc.last_seen >= cutoff
        }
        self.last_run = datetime.now(timezone.utc)
        return written

    def process_tenant(self, tenant_id):
        import json

        cursor = self.store.get_detect_cursor(tenant_id)
        written = 0
        while True:
            rows = self.store.events_after(tenant_id, cursor, self.batch_size)
            if not rows:
                return written
            allow = Allowlist.from_policy(self.store.get_policy(tenant_id))
            disabled = self.store.disabled_rules(tenant_id)
            # Rules mutate correlation/deduplication state before persistence.
            # Restore this batch on failure so retries reproduce candidates.
            snapshot = {}
            try:
                for row in rows:
                    cursor = {"time": row["received_at"], "id": row["id"]}
                    if not row.get("session_id") or row["kind"] == "sensor":
                        continue
                    event = row.get("body") or {}
                    if isinstance(event, str):
                        try:
                            event = json.loads(event)
                        except ValueError:
                            self.log.warning("Cannot decode event %s", row["id"])
                            continue
                    event = dict(event)
                    for key in ("id", "kind", "time"):
                        event[key] = event.get(key) or row[key]
                    key = (tenant_id, row["session_id"])
                    if key not in snapshot:
                        snapshot[key] = copy.deepcopy(self.sessions.get(key))
                    sc = self.sessions.setdefault(key, SessionContext(*key))
                    sc.allow = allow
                    for rule in RULES:
                        if disabled.get(rule["id"]):
                            continue
                        for candidate in evaluate_rule(rule["id"], sc, event):
                            try:
                                candidate = self.triager(sc, event, candidate)
                            except Exception:
                                self.log.warning(
                                    "triage failed for rule %s",
                                    rule["id"],
                                    exc_info=True,
                                )
                                continue
                            if candidate is None:
                                continue
                            ids = list(
                                dict.fromkeys(
                                    candidate.get("event_ids", []) + [row["id"]]
                                )
                            )
                            finding = dict(
                                tenant_id=tenant_id,
                                rule_id=rule["id"],
                                category=candidate.get("category") or rule["category"],
                                severity=candidate.get("severity") or rule["severity"],
                                title=candidate["title"],
                                summary=candidate["summary"],
                                agent_id=row.get("agent_id"),
                                session_id=row.get("session_id"),
                                sensor_id=row.get("sensor_id"),
                                host=event.get("host", {}),
                                product=event.get("agent", {}).get("product")
                                or row.get("product", ""),
                                account=event.get("agent", {}).get("account", ""),
                                event_ids=ids,
                                primary_event_id=candidate.get("primary_event_id")
                                or row["id"],
                                first_event_at=candidate.get("first_event_at")
                                or event["time"],
                            )
                            if self.store.insert_finding(finding):
                                written += 1
                    sc.observe(event)
                self.store.set_detect_cursor(tenant_id, cursor)
            except Exception:
                for key, previous in snapshot.items():
                    if previous is None:
                        self.sessions.pop(key, None)
                    else:
                        self.sessions[key] = previous
                raise
            if len(rows) < self.batch_size:
                return written
