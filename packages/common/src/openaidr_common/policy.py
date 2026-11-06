"""Pure policy pattern compilation, without evaluation or enforcement."""

import os
import re
from pathlib import Path


def compile_glob(pattern, host=False, *, path_windows=None, path_home=None):
    pattern = pattern.replace("\\", "/")
    prefix = ""
    if not host and (pattern == "~" or pattern.startswith("~/")):
        home = str(Path.home()) if path_home is None else path_home
        homes = ["/Users/[^/]+", "/home/[^/]+", "/root", "[A-Za-z]:/Users/[^/]+"]
        if home:
            home = home.replace("\\", "/")
            if path_home is not None:
                home = home.rstrip("/")
                if pattern == "~" and (not home or re.fullmatch("[A-Za-z]:", home)):
                    home += "/"
            homes.insert(0, re.escape(home))
        prefix = "(?:" + "|".join(homes) + ")"
        pattern = pattern[1:]
    out, i = prefix, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if host:
                out += ".*"
            elif pattern[i : i + 2] == "**":
                i += 1
                if pattern[i + 1 : i + 2] == "/":
                    i += 1
                    out += "(?:.*/)?"
                else:
                    out += ".*"
            else:
                out += "[^/]*"
        elif c == "?":
            out += "." if host else "[^/]"
        elif c == "[" and "]" in pattern[i + 1 :]:
            end = pattern.index("]", i + 1)
            cls = pattern[i + 1 : end]
            out += "[" + ("^" + cls[1:] if cls.startswith("!") else cls) + "]"
            i = end
        else:
            out += re.escape(c)
        i += 1
    windows = os.name == "nt" if path_windows is None else path_windows
    return re.compile("^" + out + "$", re.I if host or windows else 0)


def compile_rules(policy, *, path_windows=None, path_home=None):
    rules, errors = [], []
    for rule in policy.get("rules", []):
        compiled = {}
        for k, v in rule.get("match", {}).items():
            if k not in ("command_regex", "path_glob", "host_glob") or not v:
                continue
            try:
                compiled[k] = (
                    re.compile(v)
                    if k == "command_regex"
                    else compile_glob(v, k == "host_glob", path_windows=path_windows,
                                      path_home=path_home)
                )
            except (re.error, TypeError, ValueError) as exc:
                errors.append(f"rule {rule.get('id', '')}: {exc}")
                compiled[k] = None
        rules.append((rule, compiled))
    return rules, errors
