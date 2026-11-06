"""Incremental transcript parsers and restart-safe polling collectors."""

import copy
from contextlib import closing, contextmanager
import glob
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from openaidr.core.event import now
from openaidr.core.files import durable_directory, sync_directory
from .hostinfo import user_from_path
from openaidr.core.toolmap import map_tool
from openaidr.core.reasoning import reasoning_effort

PATTERNS = {
    "claude-code": ".claude/projects/*/*.jsonl",
    "codex-cli": ".codex/sessions/*/*/*/rollout-*.jsonl",
    "gemini-cli": ".gemini/tmp/*/chats/session-*.json",
    "cowork": "Library/Application Support/Claude/local-agent-mode-sessions/*/*/local_*/audit.jsonl",
}
MAX_PARSERS = 64
MAX_PENDING_BYTES = 256 << 10
INJECTED = (
    "<environment_context>",
    "<permissions instructions>",
    "<turn_aborted>",
    "<user_instructions>",
    "<collaboration_mode>",
    "# AGENTS.md instructions",
    "<app-context>",
    "<skills_instructions>",
)
CLAUDE_INJECTED = (
    "<command-name>",
    "<command-message>",
    "<local-command-stdout>",
    "<local-command-caveat>",
    "<system-reminder>",
    "<ide_opened_file>",
    "<bash-input>",
    "<bash-stdout>",
    "<bash-stderr>",
    "<task-notification>",
)


def content_text(value, injected=False, gaps=None):
    gaps = gaps if gaps is not None else []
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        texts = []
        for part in value:
            if not isinstance(part, dict) or not isinstance(part.get("text"), str):
                gaps.append("unsupported_content")
            elif injected and part["text"].strip().startswith(INJECTED):
                gaps.append("skipped_content")
            elif part["text"]:
                texts.append(part["text"])
        return "\n".join(texts)
    if isinstance(value, dict):
        text = value.get("text") or value.get("output")
        if isinstance(text, str):
            return text
        text = json.dumps(value)
        if len(text) > 4096:
            gaps.append("content_truncated")
        return text[:4096]
    if value is not None:
        gaps.append("unsupported_content")
    return ""


def _identity(*parts):
    return hashlib.sha256(
        json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class Parser:
    def __init__(self, product, path, fresh=True, started=False, stream_id=None):
        self.product, self.path, self.fresh, self.started = (
            product,
            path,
            fresh,
            started,
        )
        self.session = {"id": "-".join(Path(path).stem.split("-")[-5:])}
        self.session_known = False
        self.agent = {"product": product}
        self.pending = {}
        self.pending_bytes = 0
        self.ended = False
        self.stream_id = stream_id or _identity(product, path)
        self.sequence = 0
        self.record_gaps = []
        self.stream_gaps = []

    def evidence(self, record, line, events, gaps=(), position=None):
        position = line if position is None else position
        if not events and gaps:
            events = [dict(self.base(record, line), kind="sensor")]
            if not self.session_known:
                self.stream_gaps = sorted(set(self.stream_gaps + list(gaps)))
        gaps = sorted(set(list(gaps) + self.stream_gaps))
        record_key = record.get("uuid") or record.get("id")
        if not isinstance(record_key, str) or not record_key:
            record_key = (
                events[0].get("source", {}).get("record_id") if events else None
            )
        if not isinstance(record_key, str) or not record_key:
            record_key = _identity(self.stream_id, position)
        part = 0
        for event in events:
            if event["kind"] in ("session.start", "session.end", "sensor"):
                event_part = 0
            else:
                part += 1
                event_part = part
            tool_id = event.get("tool", {}).get("call_id")
            if isinstance(tool_id, str) and tool_id:
                logical_id = _identity(
                    self.product,
                    self.session["id"],
                    "result" if event["kind"] == "tool.result" else "call",
                    tool_id,
                )
            else:
                logical_id = _identity(
                    self.product,
                    self.stream_id,
                    record_key,
                    event["kind"],
                    event_part,
                )
            event["evidence"] = {
                "version": 1,
                "logical_id": logical_id,
                "observation_id": _identity(
                    self.stream_id, position, event_part, event["kind"], record_key
                ),
                "stream_id": self.stream_id,
                "sequence": position,
                "part": event_part,
                "gaps": sorted(set(gaps + event.pop("_evidence_gaps", []))),
            }
            if event["kind"] == "sensor" and not self.session_known:
                event.pop("session", None)
        return events

    def gap(self, reason, line=0, marker="", position=None):
        position = line if position is None else position
        return self.evidence(
            {"id": _identity(reason, marker, position)}, line, [], [reason], position
        )

    def base(self, record, line=0):
        timestamp = record.get("timestamp") or now()
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                timestamp = now()
        except (ValueError, TypeError, AttributeError):
            timestamp = now()
        return {
            "time": timestamp,
            "host": {"user": user_from_path(self.path)},
            "agent": copy.deepcopy(self.agent),
            "session": copy.deepcopy(self.session),
            "source": {
                "collector": self.product,
                "path": self.path,
                "line": line,
                "record_id": record.get("uuid", record.get("id", "")),
            },
        }

    def remember(self, call_id, event):
        if call_id:
            self.pop_call(call_id)
            # Results only inherit a tool name and mapped command, not the raw
            # tool input, session, or source record retained in the call event.
            context = {"tool": {"name": event.get("tool", {}).get("name", "unknown")}}
            if event.get("command"):
                context["command"] = event["command"]
            size = len(json.dumps([call_id, context], ensure_ascii=True))
            if size > MAX_PENDING_BYTES:
                return
            while self.pending and self.pending_bytes + size > MAX_PENDING_BYTES:
                self.pop_call(next(iter(self.pending)))
            self.pending[call_id] = (size, copy.deepcopy(context))
            self.pending_bytes += size
            while len(self.pending) > 500:
                self.pop_call(next(iter(self.pending)))

    def pop_call(self, call_id):
        size, context = self.pending.pop(call_id, (0, {}))
        self.pending_bytes -= size
        return context

    def parse(self, record, line=0, position=None):
        self.sequence = line or self.sequence + 1
        line = self.sequence
        if not isinstance(record, dict):
            return self.gap("malformed_record", line, position=position)
        self.record_gaps = []
        try:
            events = (
                self.claude(record, line)
                if self.product == "claude-code"
                else self.cowork(record, line)
                if self.product == "cowork"
                else self.codex(record, line)
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return self.gap("malformed_record", line, position=position)
        return self.evidence(record, line, events, self.record_gaps, position)

    def cowork(self, record, line):
        if record.get("type") not in ("user", "assistant"):
            return []
        native = dict(record)
        native["sessionId"] = record.get("session_id") or record.get("sessionId")
        native["timestamp"] = record.get("timestamp") or record.get("_audit_timestamp")
        events = self.claude(native, line)
        for event in events:
            event["source"]["collector"] = "cowork-audit"
            # The key belongs to Claude Desktop. File presence is not a verified signature.
            event["source"]["audit_integrity"] = "unverified"
            if record.get("_audit_redactions"):
                event.setdefault("_evidence_gaps", []).append("content_redacted")
        return events

    def claude(self, r, line):
        if r.get("type") not in ("user", "assistant"):
            return []
        if (
            not isinstance(r.get("message"), dict)
            or not isinstance(r.get("sessionId"), str)
            or not 1 <= len(r["sessionId"]) <= 256
        ):
            self.record_gaps.append("malformed_record")
            return []
        self.session = {
            "id": r["sessionId"],
            "cwd": r.get("cwd", ""),
            "git_branch": r.get("gitBranch", ""),
            "entrypoint": r.get("entrypoint", ""),
        }
        self.session_known = True
        self.agent = {"product": self.product, "version": r.get("version", "")}
        if r["type"] == "assistant":
            self.agent["model"] = r["message"].get("model", "")
        base = self.base(r, line)
        out = (
            [dict(copy.deepcopy(base), kind="session.start")]
            if self.fresh and not self.started
            else []
        )
        self.started = True
        content = r["message"].get("content", [])
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        if not isinstance(content, list):
            self.record_gaps.append("malformed_record")
        texts = []
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                self.record_gaps.append("malformed_record")
                continue
            typ = block.get("type")
            e = copy.deepcopy(base)
            if typ == "text":
                if r["type"] == "user":
                    texts.append(block.get("text", ""))
                elif block.get("text", "").strip():
                    out.append(dict(e, kind="response", text=block["text"]))
            elif typ == "tool_use" and r["type"] == "assistant":
                e.update(
                    map_tool(self.product, block.get("name", ""), block.get("input"))[0]
                )
                e["tool"] = {
                    "name": block.get("name", ""),
                    "call_id": block.get("id", ""),
                    "input": block.get("input"),
                    "caller": "subagent"
                    if r.get("isSidechain")
                    else (block.get("caller") or {})
                    .get("type", "")
                    .replace("direct", ""),
                }
                if "command" in e and not e["command"].get("cwd"):
                    e["command"]["cwd"] = r.get("cwd", "")
                self.remember(block.get("id"), e)
                out.append(e)
            elif typ == "tool_result" and r["type"] == "user":
                call = self.pop_call(block.get("tool_use_id"))
                e.update(
                    kind="tool.result",
                    tool={
                        "name": call.get("tool", {}).get("name", "unknown"),
                        "call_id": block.get("tool_use_id", ""),
                        "output": content_text(
                            block.get("content"), gaps=self.record_gaps
                        ),
                        "is_error": bool(block.get("is_error")),
                    },
                )
                if not call:
                    e["_evidence_gaps"] = ["missing_tool_call"]
                if call.get("command"):
                    e["command"] = call["command"]
                    result = r.get("toolUseResult") or {}
                    if isinstance(result, dict):
                        for key in ("exitCode", "exit_code", "code"):
                            if key in result:
                                e["command"]["exit_code"] = result[key]
                                break
                out.append(e)
            else:
                self.record_gaps.append("unsupported_content")
        text = "\n".join(texts)
        if (
            text.strip()
            and not text.strip().startswith(CLAUDE_INJECTED)
            and not r.get("isSidechain")
            and "toolUseResult" not in r
        ):
            out.append(dict(copy.deepcopy(base), kind="prompt", text=text))
        elif text.strip():
            self.record_gaps.append("skipped_content")
        return out

    def codex(self, r, line):
        p = r.get("payload")
        if not isinstance(p, dict):
            self.record_gaps.append("malformed_record")
            return []
        typ = r.get("type")
        if typ == "session_meta":
            if p.get("id") is not None and (
                not isinstance(p["id"], str) or not 1 <= len(p["id"]) <= 256
            ):
                self.record_gaps.append("malformed_record")
                return []
            if p.get("id"):
                self.session_known = True
            self.session.update(
                {
                    k: v
                    for k, v in {
                        "id": p.get("id"),
                        "cwd": p.get("cwd"),
                        "git_branch": p.get("git", {}).get("branch", ""),
                        "entrypoint": p.get("originator", ""),
                    }.items()
                    if v
                }
            )
            source = p.get("source")
            if isinstance(source, dict):
                self.session["parent_id"] = (
                    source.get("subagent", {})
                    .get("thread_spawn", {})
                    .get("parent_thread_id", "")
                )
            self.agent["version"] = p.get("cli_version", "")
            if self.fresh and not self.started:
                self.started = True
                return [dict(self.base(r, line), kind="session.start")]
            return []
        if typ == "turn_context":
            if p.get("model"):
                self.agent["model"] = p["model"]
            self.agent.pop("reasoning_effort", None)
            if effort := reasoning_effort(p):
                self.agent["reasoning_effort"] = effort
            self.session.pop("turn_id", None)
            if isinstance(p.get("turn_id"), str) and 0 < len(p["turn_id"]) <= 256:
                self.session["turn_id"] = p["turn_id"]
            if p.get("cwd"):
                self.session["cwd"] = p["cwd"]
            return []
        if (
            typ == "event_msg"
            and p.get("type") == "task_complete"
            and self.started
            and not self.ended
        ):
            self.ended = True
            return [dict(self.base(r, line), kind="session.end")]
        if typ == "event_msg":
            return []
        if typ != "response_item":
            self.record_gaps.append("unsupported_content")
            return []
        if p.get("type") in ("reasoning", None, ""):
            self.record_gaps.append(
                "skipped_content"
                if p.get("type") == "reasoning"
                else "malformed_record"
            )
            return []
        base = self.base(dict(r, id=p.get("id", "")), line)
        out = []
        if (self.fresh and not self.started) or self.ended:
            out.append(dict(copy.deepcopy(base), kind="session.start"))
            self.started, self.ended = True, False
        typ = p["type"]
        if typ == "message":
            text = content_text(p.get("content"), injected=True, gaps=self.record_gaps)
            if text.strip() and p.get("role") in ("user", "assistant"):
                out.append(
                    dict(
                        base,
                        kind="prompt" if p["role"] == "user" else "response",
                        text=text,
                    )
                )
            elif text.strip():
                self.record_gaps.append("skipped_content")
        elif typ in ("function_call", "custom_tool_call"):
            raw, args = p.get("input", ""), {}
            if p.get("arguments"):
                try:
                    args = json.loads(p["arguments"])
                except ValueError:
                    raw = p["arguments"]
            input_value = args or (
                {"arguments": p["arguments"]}
                if p.get("arguments")
                else {"input": raw}
                if raw
                else None
            )
            actions = map_tool(self.product, p.get("name", ""), args, raw)
            for action in actions:
                e = copy.deepcopy(base)
                e.update(action)
                e["tool"] = {
                    "name": p.get("name", ""),
                    "call_id": p.get("call_id", ""),
                    "input": input_value,
                }
                if "command" in e and not e["command"].get("cwd"):
                    e["command"]["cwd"] = self.session.get("cwd", "")
                out.append(e)
            self.remember(
                p.get("call_id"),
                out[-1] if len(actions) == 1 else {"tool": {"name": p.get("name", "")}},
            )
        elif typ in ("function_call_output", "custom_tool_call_output"):
            call = self.pop_call(p.get("call_id"))
            value = p.get("output")
            if isinstance(value, str) and value.strip().startswith("{"):
                try:
                    wrapped = json.loads(value)
                    if isinstance(wrapped, dict) and wrapped.get("output"):
                        value = wrapped
                except ValueError:
                    pass
            text = content_text(value, gaps=self.record_gaps)
            e = dict(
                base,
                kind="tool.result",
                tool={
                    "name": call.get("tool", {}).get("name", "unknown"),
                    "call_id": p.get("call_id", ""),
                    "output": text,
                },
            )
            if not call:
                e["_evidence_gaps"] = ["missing_tool_call"]
            if call.get("command"):
                e["command"] = call["command"]
                code = (
                    value.get("metadata", {}).get("exit_code")
                    if isinstance(value, dict)
                    else None
                )
                match = re.search(
                    r"(?:Exit code: |exit code |exited with code )(\d+)", text
                )
                if code is not None or match:
                    e["command"]["exit_code"] = (
                        code if code is not None else int(match[1])
                    )
            out.append(e)
        else:
            self.record_gaps.append("unsupported_content")
        return out

    def gemini(self, doc, index):
        out = []
        if not isinstance(doc, dict) or not isinstance(doc.get("messages", []), list):
            return self.gap("malformed_record", index)
        session_id = doc.get("sessionId") or Path(self.path).stem.removeprefix(
            "session-"
        )
        if not isinstance(session_id, str) or not 1 <= len(session_id) <= 256:
            return self.gap("malformed_record", index)
        self.session = {"id": session_id}
        self.session_known = bool(doc.get("sessionId"))
        messages = doc.get("messages", [])
        for i, m in enumerate(messages[index:], index):
            if not isinstance(m, dict):
                out.extend(self.gap("malformed_record", i + 1))
                continue
            events = []
            gaps = []
            self.agent = {"product": self.product, "model": m.get("model", "")}
            base = self.base(m, i + 1)
            if not self.started and i == 0:
                events.append(dict(copy.deepcopy(base), kind="session.start"))
            self.started = True
            typ = m.get("type")
            if typ in ("gemini", "assistant", "model"):
                calls = m.get("toolCalls", [])
                if not isinstance(calls, list):
                    calls = []
                    gaps.append("malformed_record")
                for tc in calls:
                    if not isinstance(tc, dict) or not isinstance(
                        tc.get("name", ""), str
                    ):
                        gaps.append("malformed_record")
                        continue
                    e = copy.deepcopy(base)
                    e.update(
                        map_tool(self.product, tc.get("name", ""), tc.get("args"))[0]
                    )
                    e["tool"] = {
                        "name": tc.get("name", ""),
                        "call_id": tc.get("id", ""),
                        "input": tc.get("args"),
                    }
                    events.append(e)
                    if "result" in tc or tc.get("status"):
                        result = dict(
                            copy.deepcopy(base),
                            kind="tool.result",
                            tool={
                                "name": tc.get("name", ""),
                                "call_id": tc.get("id", ""),
                                "output": content_text(tc.get("result"), gaps=gaps),
                                "is_error": tc.get("status") == "error",
                            },
                        )
                        if e.get("command"):
                            result["command"] = e["command"]
                        events.append(result)
            text = content_text(m.get("content"), gaps=gaps)
            if text.strip() and typ in ("user", "gemini", "assistant", "model"):
                events.append(
                    dict(
                        copy.deepcopy(base),
                        kind="prompt" if typ == "user" else "response",
                        text=text,
                    )
                )
            elif typ not in ("user", "gemini", "assistant", "model"):
                gaps.append("unsupported_content")
            out.extend(self.evidence(m, i + 1, events, gaps))
        return out


def legacy_offsets(path):
    """Read the old flat JSON object one checkpoint at a time."""
    with path.open(encoding="utf-8") as source:
        buffer, eof = "", False
        decoder = json.JSONDecoder()

        def fill():
            nonlocal buffer, eof
            part = source.read(16 << 10)
            eof = not part
            buffer += part
            if len(buffer) > 1 << 20:
                raise ValueError("Oversized transcript checkpoint")

        def peek():
            nonlocal buffer
            buffer = buffer.lstrip()
            while not buffer and not eof:
                fill()
                buffer = buffer.lstrip()
            return buffer[:1]

        def consume(character):
            nonlocal buffer
            if peek() != character:
                raise ValueError("Invalid transcript checkpoints")
            buffer = buffer[1:]

        def value():
            nonlocal buffer
            peek()
            while True:
                try:
                    result, end = decoder.raw_decode(buffer)
                except ValueError:
                    if eof:
                        raise
                    fill()
                else:
                    buffer = buffer[end:]
                    return result

        consume("{")
        if peek() != "}":
            while True:
                key = value()
                consume(":")
                checkpoint = value()
                if not isinstance(key, str) or not isinstance(checkpoint, dict):
                    raise ValueError("Invalid transcript checkpoint")
                yield key, json.dumps(checkpoint)
                if peek() == "}":
                    break
                consume(",")
        consume("}")
        if peek():
            raise ValueError("Trailing transcript checkpoint data")


class Offsets:
    def __init__(self, path):
        self.path, self.lock = Path(path), threading.RLock()
        self.database = self.path.with_name(self.path.name + ".sqlite3")
        self.initialized = False

    def prepare(self):
        with self.lock:
            if not self.initialized:
                self.initialize()
                self.initialized = True

    def initialize(self):
        durable_directory(self.path.parent)
        self.database.touch(mode=0o600, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS offsets (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            previous = db.execute("SELECT value FROM metadata WHERE key='legacy'").fetchone()
            if previous is None or previous[0] != self.signature():
                # Import old checkpoints once, or after a rolled-back sensor
                # updates the JSON file. Never discard checkpoints on eviction.
                db.execute("DELETE FROM offsets")
                try:
                    db.executemany("INSERT OR REPLACE INTO offsets VALUES (?,?)", legacy_offsets(self.path))
                except (OSError, ValueError):
                    db.execute("DELETE FROM offsets")
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('legacy',?)", (self.signature(),))

    def signature(self):
        try:
            info = self.path.stat()
            return json.dumps([info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns])
        except FileNotFoundError:
            return "null"

    @contextmanager
    def connect(self):
        try:
            with self.lock, closing(sqlite3.connect(self.database)) as db, db:
                db.execute("PRAGMA cache_size=-512")
                yield db
        except sqlite3.Error as exc:
            raise OSError("Transcript checkpoints are unavailable") from exc

    def get(self, name, path):
        self.prepare()
        with self.connect() as db:
            row = db.execute("SELECT value FROM offsets WHERE key=?", (name + "|" + path,)).fetchone()
            return json.loads(row[0]) if row else None

    def set(self, name, path, value):
        self.prepare()
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO offsets VALUES (?,?)", (name + "|" + path, json.dumps(value)))

    def flush(self):
        if not self.initialized:
            return
        # Preserve rollback compatibility without materializing every checkpoint.
        with self.connect() as db:
            fd, name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write("{")
                    separator = ""
                    for key, value in db.execute("SELECT key,value FROM offsets ORDER BY key"):
                        stream.write(separator + json.dumps(key) + ":" + value)
                        separator = ","
                    stream.write("}")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(name, self.path)
                sync_directory(self.path.parent)
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('legacy',?)", (self.signature(),))
            finally:
                Path(name).unlink(missing_ok=True)


class Collector:
    def __init__(self, product, homes, extra, offsets, backfill=False, emit=None):
        self.name, self.offsets, self.backfill = product, offsets, backfill
        self.patterns = [str(Path(h) / PATTERNS[product]) for h in homes] + list(
            extra or []
        )
        if product == "cowork":
            roots = ("AppData/Roaming/Claude", "AppData/Local/Claude") if sys.platform == "win32" else ("Library/Application Support/Claude",)
            self.patterns = [str(Path(h) / root / "local-agent-mode-sessions" / tail)
                             for h in homes for root in roots
                             for tail in ("*/*/local_*/audit.jsonl", "*/*/agent/local_*/audit.jsonl")] + list(extra or [])
        self.emit = emit or (lambda e: None)
        self.files, self.events, self.error = {}, 0, ""
        self.retry_initial = False

    def status(self):
        return {
            "name": self.name,
            "status": "running" if self.files else "idle",
            "files_watched": len(self.files),
            "events_total": self.events,
            "error": self.error,
        }

    def poll(self, initial=False):
        initial = initial or self.retry_initial
        try:
            self.offsets.prepare()
        except OSError as exc:
            self.error = str(exc)
            self.retry_initial = initial and not self.backfill
            return
        def paths():
            # Retry parsed records first; backpressure must not retain one large
            # failed batch for every transcript discovered on the device.
            yield from [path for path, state in self.files.items() if state.get("pending_emit")]
            for pattern in self.patterns:
                for path in glob.iglob(str(Path(pattern).expanduser()), recursive=True):
                    if Path(path).is_file():
                        yield path

        error = ""
        for path in paths():
            try:
                self.read(path, initial)
            except (OSError, ValueError, TypeError) as exc:
                error = str(exc)
                if self.files.get(path, {}).get("pending_emit"):
                    break
        for path, state in list(self.files.items()):
            if not state.get("pending_emit") and not Path(path).exists():
                del self.files[path]
        try:
            self.offsets.flush()
        except OSError as exc:
            error = str(exc)
        self.error = error
        self.retry_initial = initial and not self.backfill and bool(error)

    def read(self, path, initial):
        if path in self.files:
            # Finish the already parsed record even if its source was replaced
            # or removed while registration/capture storage was unavailable.
            pending = self.files[path].get("pending_emit")
            self.drain_pending(self.files[path])
            if pending:
                self.offsets.set(self.name, path, self.files[path]["off"])
        stat = Path(path).stat()
        identity = f"{stat.st_dev}:{stat.st_ino}"
        first_gap = None
        if path not in self.files:
            off = self.offsets.get(self.name, path)
            if (not initial and off and off.get("id") == identity and off.get("size") == stat.st_size
                    and off.get("mtime_ns") == stat.st_mtime_ns
                    and (self.name == "gemini-cli" or off.get("offset") == stat.st_size)):
                return
            if len(self.files) >= MAX_PARSERS:
                victim = next((key for key, value in self.files.items() if not value.get("pending_emit")), None)
                if victim is None:
                    raise OSError("Transcript collection is waiting for pending records")
                del self.files[victim]
            new_offset = off is None
            fresh = off is None and (not initial or self.backfill)
            if off is None:
                offset = 0
                line = 0
                discarding = False
                if initial and not self.backfill and self.name != "gemini-cli":
                    offset = stat.st_size
                    discarding = bool(offset)
                off = {
                    "offset": offset,
                    "line": line,
                    "id": identity,
                    "size": stat.st_size,
                    "started": False,
                    "discarding": discarding,
                }
                if discarding:
                    off["tail_pending"] = True
                if self.name == "gemini-cli":
                    off["baseline_pending"] = initial and not self.backfill
                if offset:
                    off["gaps"] = ["skipped_history"]
                    first_gap = "skipped_history"
            elif off.get("offset"):
                off["gaps"] = sorted(set(off.get("gaps", []) + ["parser_restart"]))
                first_gap = "parser_restart"
            if self.name == "gemini-cli" and "baseline_pending" not in off:
                # Older checkpoints cannot distinguish skipped from consumed history.
                off["baseline_pending"] = (
                    not self.backfill and not off.get("offset") and not off.get("started")
                )
                if not self.backfill and off.get("offset", 0) > 0:
                    off["skipped_messages"] = off["offset"]
                    saved_native = off.get("native_stream") or (
                        off.get("session_id") if off.get("session_known") else None
                    )
                    if isinstance(saved_native, str) and 1 <= len(saved_native) <= 256:
                        off["skipped_session_id"] = saved_native
            if self.name == "gemini-cli" and "document_id" not in off:
                # Gap checkpoints used to overwrite the last complete source identity.
                off["document_id"] = None if off.get("pending_gaps") else off.get("id")
            off.setdefault("stream_id", _identity(self.name, path, identity))
            if (
                self.name == "gemini-cli"
                and off.get("session_known")
                and off.get("native_stream") != off.get("session_id")
            ):
                off["stream_id"] = _identity(self.name, path, off["session_id"])
                off["native_stream"] = off["session_id"]
            parser = Parser(
                self.name,
                path,
                fresh or off.get("started", False),
                off.get("started", False),
                off["stream_id"],
            )
            saved_session = off.get("session_id")
            if isinstance(saved_session, str) and saved_session:
                parser.session["id"] = saved_session
                parser.session_known = off.get("session_known", False)
            parser.ended = off.get("ended", False)
            parser.stream_gaps = off.get("gaps", [])
            self.files[path] = {
                "off": off,
                "parser": parser,
            }
            if new_offset:
                self.save_offset(path, stat, identity)
        state = self.files[path]
        # Keep recently used parsers at the end of the bounded insertion order.
        self.files.pop(path)
        self.files[path] = state
        off, parser = state["off"], state["parser"]
        if first_gap:
            if self.name == "gemini-cli":
                off.setdefault("pending_gaps", {})[first_gap] = off["offset"]
            else:
                self.emit_events(parser.gap(first_gap, marker=off["offset"]))
        if self.name == "gemini-cli":
            try:
                with Path(path).open("rb") as source:
                    stat = os.fstat(source.fileno())
                    identity = f"{stat.st_dev}:{stat.st_ino}"
                    limit = 64 << 20
                    content = source.read(limit + 1) if stat.st_size <= limit else None
                if content is None or len(content) > limit:
                    self.document_gap(path, stat, identity, "oversized_record")
                    return
                doc = json.loads(content)
                if not isinstance(doc, dict) or not isinstance(
                    doc.get("messages"), list
                ):
                    raise ValueError("invalid Gemini document")
            except (ValueError, UnicodeError):
                self.document_gap(path, stat, identity, "malformed_record")
                return
            except OSError:
                self.save_offset(path, stat, identity)
                raise
            count = len(doc.get("messages", []))
            native_session = doc.get("sessionId")
            if (
                not isinstance(native_session, str)
                or not 1 <= len(native_session) <= 256
            ):
                if native_session:
                    self.document_gap(path, stat, identity, "malformed_record")
                    return
                native_session = None
            previous_native = off.get("native_stream")
            source_changed = not native_session and off.get("document_id") != identity
            session_changed = (
                native_session != previous_native
                and (previous_native is not None or off["offset"] > 0)
            )
            if native_session:
                if not previous_native or session_changed:
                    parser.stream_id = _identity(self.name, path, native_session)
                    off["native_stream"] = native_session
                parser.session = {"id": native_session}
                parser.session_known = True
            else:
                if previous_native or source_changed:
                    parser.stream_id = _identity(self.name, path, identity)
                    off.pop("native_stream", None)
                parser.session = {"id": Path(path).stem.removeprefix("session-")}
                parser.session_known = False
            if count < off["offset"] or session_changed or source_changed:
                off["offset"], parser.started = 0, False
                if not session_changed and not source_changed:
                    parser.stream_id = _identity(parser.stream_id, "reset", count)
                parser.stream_gaps = ["source_reset"]
                self.emit_events(parser.gap("source_reset", marker=count))
            if off.get("baseline_pending"):
                off["baseline_pending"] = False
                off["skipped_messages"] = count
                off["offset"] = count
                if count:
                    first_gap = "skipped_history"
                    off.setdefault("pending_gaps", {})[first_gap] = count
            skipped = off.get("skipped_messages", 0)
            if skipped and native_session and not off.get("skipped_session_id"):
                off["skipped_session_id"] = native_session
            if skipped and (
                not native_session or native_session == off.get("skipped_session_id")
            ):
                # Startup history stays private through identity recovery and resets.
                off["offset"] = max(off["offset"], skipped)
                parser.stream_gaps = sorted(set(parser.stream_gaps + ["skipped_history"]))
            pending = off.get("pending_gaps", {})
            parser.stream_gaps = sorted(set(parser.stream_gaps + list(pending)))
            if native_session:
                off.pop("pending_gaps", None)
                for reason, marker in pending.items():
                    self.emit_events(parser.gap(reason, marker=marker))
            elif first_gap:
                self.emit_events(parser.gap(first_gap, marker=off["offset"]))
            events = parser.gemini(doc, off["offset"])
            self.emit_events(events)
            off["offset"] = count
            off["document_id"] = identity
        else:
            with open(path, "rb") as f:
                stat = os.fstat(f.fileno())
                identity = f"{stat.st_dev}:{stat.st_ino}"
                if (off.get("id") and off["id"] != identity) or stat.st_size < off["offset"]:
                    stream_id = (
                        _identity(self.name, path, identity)
                        if off.get("id") != identity
                        else _identity(parser.stream_id, "reset", identity, stat.st_size)
                    )
                    off.update(offset=0, line=0, started=False, discarding=False)
                    off.pop("tail_pending", None)
                    parser = state["parser"] = Parser(self.name, path, stream_id=stream_id)
                    parser.stream_gaps = ["source_reset"]
                    self.emit_events(parser.gap("source_reset", marker=identity))
                if off.get("tail_pending"):
                    f.seek(off["offset"] - 1)
                    off["discarding"] = f.read(1) != b"\n"
                    off.pop("tail_pending")
                f.seek(off["offset"])
                consumed = 0
                while consumed < 16 << 20:
                    position = f.tell() + 1
                    line = f.readline((8 << 20) + 1)
                    if not line:
                        break
                    consumed += len(line)
                    if off.get("discarding") or len(line) > 8 << 20:
                        if not off.get("discarding"):
                            self.emit_events(
                                parser.gap(
                                    "oversized_record",
                                    off["line"] + 1,
                                    position=position,
                                )
                            )
                        off["discarding"] = not line.endswith(b"\n")
                        off["offset"] = f.tell()
                        if not off["discarding"]:
                            off["line"] += 1
                        continue
                    if not line.endswith(b"\n"):
                        break
                    sequence = off.get("line", 0) + 1
                    try:
                        events = parser.parse(json.loads(line), sequence, position)
                    except (ValueError, UnicodeError):
                        events = parser.gap(
                            "malformed_record", sequence, position=position
                        )
                    # Parsing mutates native tool/session state. Retry this exact
                    # batch after managed startup or durable storage backpressure,
                    # without reparsing it or advancing the source checkpoint.
                    state["pending_emit"] = {
                        "events": events, "offset": f.tell(), "line": sequence, "next": 0,
                    }
                    self.drain_pending(state)
        self.save_offset(path, stat, identity)

    def document_gap(self, path, stat, identity, reason):
        # A replacement document may belong to a different native session.
        # Keep its gap unscoped until a complete document establishes identity.
        off = self.files[path]["off"]
        pending = off.setdefault("pending_gaps", {})
        marker = f"{identity}:{stat.st_size}:{stat.st_mtime_ns}"
        if pending.get(reason) != marker:
            pending[reason] = marker
            unknown = Parser(
                self.name, path, stream_id=_identity(self.name, path, identity)
            )
            self.emit_events(unknown.gap(reason, marker=marker))
        self.save_offset(path, stat, identity)

    def save_offset(self, path, stat, identity):
        state = self.files[path]
        off, parser = state["off"], state["parser"]
        off.update(
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            id=identity,
            started=parser.started,
            ended=parser.ended,
            session_known=parser.session_known,
            stream_id=parser.stream_id,
            gaps=parser.stream_gaps,
        )
        session_id = parser.session.get("id")
        if (
            parser.session_known
            and isinstance(session_id, str)
            and len(session_id) <= 256
        ):
            off["session_id"] = session_id
        else:
            off.pop("session_id", None)
        self.offsets.set(self.name, path, off)

    def emit_events(self, events):
        for event in events:
            self.emit(event)
            self.events += 1

    def drain_pending(self, state):
        pending = state.get("pending_emit")
        if pending is None:
            return
        while pending["next"] < len(pending["events"]):
            self.emit(pending["events"][pending["next"]])
            self.events += 1
            pending["next"] += 1
        state["off"]["offset"], state["off"]["line"] = pending["offset"], pending["line"]
        state.pop("pending_emit")

    def run(self, stop):
        self.poll(True)
        while not stop.wait(2 if self.name == "gemini-cli" else 1):
            self.poll()
