"""Accounting metadata from completed WorkBuddy responses, never transcript content."""

from datetime import datetime, timezone
import hashlib
import json
import os
import stat

from openaidr.core.agent_usage import text, token


def history_walk(root, guard, unavailable, cancelled):
    """Guard entry names before any target classification; never recurse into links."""
    pending = [root]
    while pending:
        if cancelled():
            raise InterruptedError
        directory = pending.pop()
        children, names = [], []
        try:
            directory = guard.check(directory)
            if not directory.is_relative_to(root):
                raise PermissionError
            with os.scandir(directory) as entries:
                for entry in entries:
                    if cancelled():
                        raise InterruptedError
                    candidate = directory / entry.name
                    try:
                        if not guard.check(candidate).is_relative_to(root):
                            raise PermissionError
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if not getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                                children.append(candidate)
                        else:
                            names.append(entry.name)
                    except OSError:
                        unavailable.add(str(candidate))
        except InterruptedError:
            raise
        except OSError:
            unavailable.add(str(directory))
            continue
        yield directory, (), names
        pending.extend(reversed(children))


def _count(raw, names, detail=None):
    values = [token(raw, name) for name in names if name in raw]
    if detail and detail in raw:
        nested = raw[detail]
        values.append(token(nested, "cached_tokens") if isinstance(nested, dict) else None)
    return values[0] if values and None not in values and len(set(values)) == 1 else None


def request_record(record, sensor_id):
    kind = record.get("type")
    if kind not in ("model-usage", "assistant", "reasoning", "function_call", "message") or (
        kind == "message" and record.get("role") != "assistant"
    ):
        return None, None, 0, 0
    provider = record.get("providerData")
    raw = provider.get("rawUsage") if isinstance(provider, dict) else None
    if not isinstance(raw, dict) or not isinstance(provider.get("usage"), dict):
        return None, None, 0, 0
    ident = text(provider, "messageId")
    if not ident:
        return None, None, 0, 1
    # This is also the native exporter modelRequestId. Forks retain it while
    # reminting history item IDs; transport retries reuse it within one model call.
    key = hashlib.sha256(json.dumps((str(sensor_id), "workbuddy", ident)).encode()).hexdigest()
    stamp = token(record, "timestamp")
    try:
        when = datetime.fromtimestamp(stamp / 1000, timezone.utc) if stamp else None
    except (OverflowError, OSError, ValueError):
        when = None
    inclusive = "prompt_tokens" in raw
    incoming = token(raw, "prompt_tokens" if inclusive else "input_tokens")
    outgoing = token(raw, "completion_tokens" if inclusive else "output_tokens")
    cached = _count(raw, ("cache_read_input_tokens", "prompt_cache_hit_tokens"), "prompt_tokens_details")
    written = _count(raw, ("cache_creation_input_tokens", "prompt_cache_write_tokens"))
    # The installed context-usage helper treats prompt counts as inclusive and
    # plain input_tokens as uncached. Reject mixed/SDK-normalized shapes and
    # missing cache counters rather than assuming an omitted value means zero.
    # DeepSeek cache misses are uncached input, not cache writes. This source
    # contract does not infer cache creation from hit/miss-only responses.
    mixed = ("inputTokens" in raw or "inputTokensDetails" in raw or "input_tokens_details" in raw or
             "prompt_cache_miss_tokens" in raw or
             (inclusive and ("input_tokens" in raw or "output_tokens" in raw)) or
             (not inclusive and any(name in raw for name in (
                 "completion_tokens", "prompt_tokens_details", "prompt_cache_hit_tokens",
                 "prompt_cache_write_tokens", "prompt_cache_miss_tokens"))))
    if mixed or when is None or None in (incoming, outgoing, cached, written):
        return key, None, 1, 0
    if inclusive:
        incoming -= cached + written
        if incoming < 0:
            return key, None, 1, 0
    total = incoming + cached + written + outgoing
    if not total:
        return key, None, 0, 0
    return key, dict(
        key=key, time=when, name="workbuddy.api_request",
        model=text(provider, "model", "requestModelId") or "Unattributed", reasoning_effort="unknown",
        usage=dict(tokens=total, input_tokens=incoming, output_tokens=outgoing,
                   cache_read_tokens=cached, cache_write_tokens=written, cost=None),
        attributes={},
    ), 0, 0
