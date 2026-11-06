import json
import re
import shlex
from urllib.parse import urlsplit


def first(args, *keys):
    return next((args[k] for k in keys if isinstance(args.get(k), str) and args[k]), "")


def command_text(args):
    for key in ("cmd", "command"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list):
            return " ".join(shlex.quote(p) for p in value if isinstance(p, str))
    return ""


def extract_exec_commands(script):
    out = []
    for match in re.finditer(r"exec_command\(\s*", script):
        try:
            args, _ = json.JSONDecoder().raw_decode(script[match.end() :])
            if isinstance(args, dict) and command_text(args):
                out.append(command_text(args))
        except ValueError:
            pass
    return out


def parse_patch_files(patch):
    files = []
    for line in patch.splitlines():
        m = re.match(r"\*\*\* (Add File|Update File|Delete File): (.*)", line)
        if m:
            files.append(
                {
                    "path": m[2].strip(),
                    "op": {
                        "Add File": "create",
                        "Update File": "edit",
                        "Delete File": "delete",
                    }[m[1]],
                }
            )
        elif line.startswith("*** Move to: ") and files:
            files[-1]["op"] = "rename"
            files.append({"path": line[len("*** Move to: "):].strip(), "op": "rename"})
    return files


def network(url):
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    return {"kind": "network", "network": {"url": url, "method": "GET", "host": host}}


def map_tool(product, name, args=None, raw=""):
    if product == "workbuddy":
        product = "claude-code"
        if name == "PowerShell":
            name = "Bash"
    if product == "cowork":
        product = "claude-code"
    args = args if isinstance(args, dict) else {}
    fallback = [{"kind": "tool.call"}]
    if product in APP_TOOLS:
        return map_app_tool(product, name, args)
    if product == "codex-cli" and name == "exec":
        cmds = extract_exec_commands(raw)
        return [{"kind": "command", "command": {"text": c}} for c in cmds] or (
            [
                {
                    "kind": "command",
                    "command": {"text": raw, "description": "exec script"},
                }
            ]
            if raw.strip()
            else fallback
        )
    if product == "codex-cli" and name == "apply_patch":
        # Hook payloads carry the patch text as tool_input.command.
        return [
            {"kind": "file.write", "file": f}
            for f in parse_patch_files(raw or first(args, "patch", "input", "command"))
        ] or fallback
    supported = {
        "claude-code": {
            "Bash",
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
            "WebFetch",
        },
        "codex-cli": {
            "Bash",
            "shell",
            "shell_command",
            "exec_command",
            "container.exec",
            "local_shell",
            "bash",
            "read_file",
            "view_image",
            "list_dir",
            "grep_files",
            "read_many_files",
            "write_file",
            "create_file",
            "web_fetch",
            "fetch",
            "open_url",
        },
        "gemini-cli": {
            "run_shell_command",
            "shell",
            "read_file",
            "read_many_files",
            "list_directory",
            "glob",
            "grep_search",
            "search_file_content",
            "write_file",
            "replace",
            "edit",
            "edit_file",
            "web_fetch",
        },
    }
    if name not in supported.get(product, set()):
        return fallback
    if name in (
        "Bash",
        "shell",
        "shell_command",
        "exec_command",
        "container.exec",
        "local_shell",
        "bash",
        "run_shell_command",
    ):
        cmd = command_text(args) if product == "codex-cli" else first(args, "command")
        if cmd:
            return [
                {
                    "kind": "command",
                    "command": {
                        "text": cmd,
                        "cwd": first(args, "workdir", "cwd")
                        if product == "codex-cli"
                        else first(args, "directory")
                        if product == "gemini-cli"
                        else "",
                        "description": first(args, "justification")
                        if product == "codex-cli"
                        else first(args, "description"),
                        "background": bool(args.get("run_in_background", False)),
                    },
                }
            ]
    read = (
        "Read",
        "Grep",
        "Glob",
        "read_file",
        "view_image",
        "list_dir",
        "grep_files",
        "read_many_files",
        "list_directory",
        "glob",
        "grep_search",
        "search_file_content",
    )
    write = ("Write", "write_file", "create_file")
    edit = ("Edit", "MultiEdit", "NotebookEdit", "replace", "edit", "edit_file")
    if name in read + write + edit:
        if product == "claude-code":
            keys = (
                ("notebook_path", "file_path")
                if name == "NotebookEdit"
                else ("file_path", "path")
                if name in read
                else ("file_path",)
            )
        elif product == "codex-cli":
            keys = (
                ("path", "file_path", "absolute_path", "dir")
                if name in read
                else ("path", "file_path")
            )
        else:
            keys = (
                ("absolute_path", "file_path", "path", "dir_path")
                if name in read
                else ("file_path", "absolute_path", "path")
            )
        path = first(args, *keys)
        if path:
            op = "read" if name in read else "create" if name in write else "edit"
            return [
                {
                    "kind": "file.read" if op == "read" else "file.write",
                    "file": {
                        "path": path,
                        "op": op,
                        "bytes": len(
                            (
                                first(args, "content", "contents")
                                if product == "codex-cli" and name in write
                                else first(args, "content")
                                if name in write
                                else first(args, "new_string")
                                if name in ("Edit", "MultiEdit")
                                else ""
                            ).encode()
                        ),
                    },
                }
            ]
    if name in ("WebFetch", "web_fetch", "fetch", "open_url"):
        url = (
            first(args, "url", "href") if product == "codex-cli" else first(args, "url")
        )
        if not url and product == "gemini-cli":
            url = next(
                (
                    w.rstrip(".,;)")
                    for w in args.get("prompt", "").split()
                    if w.startswith(("https://", "http://"))
                ),
                "",
            )
        if url:
            return [network(url)]
    return fallback


# Native argument keys stay separate: converting tool names or rewriting input
# evidence would hide which operation the agent actually requested.
APP_TOOLS = {
    "github-copilot": {
        "commands": {"bash": ("command", "cwd"), "powershell": ("command", "cwd")},
        "reads": {name: ("path",) for name in ("view", "grep", "rg", "glob")},
        "writes": {"create": ("path",)},
        "edits": {"edit": ("path",), "str_replace_editor": ("path",)},
        "fetches": {"web_fetch": "url"},
    },
    "cursor": {
        "commands": {"Shell": ("command", "working_directory")},
        "reads": {name: ("path", "file_path") for name in ("Read", "Grep", "Glob", "LS")},
        "writes": {"Write": ("path", "file_path")},
        "edits": {"StrReplace": ("path", "file_path"), "Edit": ("path", "file_path")},
        "deletes": {"Delete": ("path", "file_path")},
        "fetches": {"WebFetch": "url"},
    },
    "antigravity": {
        "commands": {"run_command": ("CommandLine", "Cwd")},
        "reads": {"view_file": ("AbsolutePath",), "list_dir": ("DirectoryPath",),
                  "find_by_name": ("SearchDirectory",), "grep_search": ("SearchPath",)},
        "writes": {"write_to_file": ("TargetFile",)},
        "edits": {name: ("TargetFile",) for name in ("replace_file_content", "multi_replace_file_content")},
        "fetches": {"read_url_content": "Url"},
    },
    "opencode": {
        "commands": {"bash": ("command", "workdir")},
        "reads": {"read": ("filePath",), "glob": ("path",), "grep": ("path",), "list": ("path",)},
        "writes": {"write": ("filePath",)},
        "edits": {"edit": ("filePath",), "multiedit": ("filePath",)},
        "fetches": {"webfetch": "url"},
    },
    "hermes-agent": {
        "commands": {"terminal": ("command", "cwd")},
        "reads": {"read_file": ("path",), "search_files": ("path",)},
        "writes": {"write_file": ("path",)},
        "edits": {"patch": ("path",)},
        "fetches": {"browser_navigate": "url"},
    },
}


def map_app_tool(product, name, args):
    tools = APP_TOOLS[product]
    if product == "hermes-agent" and name == "web_extract":
        urls = args.get("urls")
        return ([network(url) for url in urls if isinstance(url, str) and url]
                if isinstance(urls, list) else []) or [{"kind": "tool.call"}]
    if product == "hermes-agent" and name == "patch" and args.get("mode") == "patch":
        return [{"kind": "file.write", "file": f} for f in parse_patch_files(first(args, "patch"))] or [{"kind": "tool.call"}]
    if name in tools["commands"]:
        command, cwd = tools["commands"][name]
        if text := first(args, command):
            return [{"kind": "command", "command": {"text": text, "cwd": first(args, cwd)}}]
    for category, op in (("reads", "read"), ("writes", "create"), ("edits", "edit"), ("deletes", "delete")):
        if name in tools.get(category, {}):
            if path := first(args, *tools[category][name]):
                return [{"kind": "file.read" if op == "read" else "file.write", "file": {"path": path, "op": op}}]
    if name in tools["fetches"] and (url := first(args, tools["fetches"][name])):
        return [network(url)]
    if product == "opencode" and name == "apply_patch":
        return [{"kind": "file.write", "file": f} for f in parse_patch_files(first(args, "patchText"))] or [{"kind": "tool.call"}]
    return [{"kind": "tool.call"}]
