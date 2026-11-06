"""Path classification and portable glob matching for detection."""

import posixpath as path
import re
from functools import lru_cache
from .detect_constants import secretBaseNames, secretExts, rootishExact


def norm_path(p):
    return p.replace("\\", "/")


@lru_cache(maxsize=4096)
def _glob(pattern):
    p = norm_path(pattern)
    if p.startswith("~/"):
        p = "**/" + p[2:]
    out, i = "^", 0
    while i < len(p):
        c = p[i]
        if p[i : i + 2] == "**":
            i += 1
            if p[i + 1 : i + 2] == "/":
                i += 1
                out += "(?:.*/)?"
            else:
                out += ".*"
        elif c == "*":
            out += "[^/]*"
        elif c == "?":
            out += "[^/]"
        else:
            out += re.escape(c)
        i += 1
    return re.compile(out + "$", re.I)


def glob_match(pattern, value):
    return bool(pattern and _glob(pattern).fullmatch(value))


def host_match(pattern, host):
    pattern, host = pattern.strip().lower(), host.lower()
    if not pattern or not host:
        return False
    if not any(c in pattern for c in "*?"):
        return host == pattern or host.endswith("." + pattern)
    return glob_match(pattern, host)


SECRET_PARTS = (
    "/.aws/credentials",
    "/.kube/config",
    "/.docker/config.json",
    "/.gem/credentials",
    "/.config/gh/hosts.yml",
    "/.config/gcloud/",
    "/.azure/accesstokens",
    "/.vault-token",
    "/.gnupg/",
    "/.password-store/",
    "/.1password/",
    "/.claude/.credentials.json",
    "/.codex/auth.json",
    "/.gemini/oauth_creds.json",
    "/.cursor/auth",
    "/.config/op/",
)


def is_secret_path(p):
    p = norm_path(p.strip()).lower()
    base = path.basename(p)
    if base == ".env":
        return True
    if base.startswith(".env."):
        return not base.endswith(
            (".example", ".sample", ".template", ".dist", ".test", ".schema")
        )
    if base in secretBaseNames or re.fullmatch(
        r"id_(rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)", base
    ):
        return True
    if (
        "/.ssh/" in p
        and not base.endswith(".pub")
        and base not in ("known_hosts", "config", "authorized_keys", "known_hosts.old")
    ):
        return True
    return (
        path.splitext(base)[1] in secretExts
        or (
            ("service-account" in base or "service_account" in base)
            and base.endswith(".json")
        )
        or any(part in p or p.startswith(part.lstrip("/")) for part in SECRET_PARTS)
    )


def secret_refs(segments, text):
    refs = []
    for s in segments:
        if s.name in ("env", "printenv", "set") and not s.args:
            refs.append("environment dump (" + s.name + ")")
        refs.extend(t for a in s.args if is_secret_path(t := a.strip("<>\"'")))
        refs.extend(a for a in s.argv if a.lower().endswith("history") and "/." in a)
    refs.extend(
        re.findall(
            r"\$\{?[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)[A-Za-z0-9_]*\}?",
            text,
        )
    )
    return list(dict.fromkeys(refs))


def is_temp_path(p):
    p = norm_path(p).lower()
    return (
        any(
            p.startswith(t) or p == t.rstrip("/")
            for t in (
                "/tmp/",
                "/var/tmp/",
                "/private/tmp/",
                "/private/var/folders/",
                "/var/folders/",
                "/dev/null",
                "/dev/shm/",
                "/dev/stdout",
                "/dev/stderr",
                "c:/windows/temp/",
                "c:/temp/",
                "c:/tmp/",
            )
        )
        or "/appdata/local/temp/" in p
    )


def is_agent_dir(p):
    return any(
        part in norm_path(p).lower()
        for part in (
            "/.claude/",
            "/.codex/",
            "/.gemini/",
            "/.cursor/",
            "/.copilot/",
            "/.aider",
            "/.config/claude/",
            "/.cache/",
        )
    )


def is_rootish(p):
    p = norm_path(p).strip().strip("\"'").lower()
    return (
        p in rootishExact
        or p.rstrip("/") in rootishExact
        or bool(
            re.fullmatch(
                r"(/users/[^/]+|/home/[^/]+|/root|[a-z]:/users/[^/]+)/?",
                p.removesuffix("/*"),
            )
        )
    )


def outside_cwd(p, cwd):
    p, cwd = norm_path(p.strip().strip("\"'")), norm_path(cwd)
    if not p or not cwd:
        return False
    if p.startswith(("~", "$", "%")):
        return True
    absolute = p if p.startswith("/") or re.match(r"^.:/", p) else path.join(cwd, p)
    absolute, cwd = path.normpath(absolute).lower(), path.normpath(cwd).lower()
    return absolute != cwd and not absolute.startswith(cwd.rstrip("/") + "/")


def has_production_marker(text):
    return bool(
        re.search(r"(^|[^a-z0-9])(prod|production|live)([^a-z0-9]|$)", text, re.I)
    )
