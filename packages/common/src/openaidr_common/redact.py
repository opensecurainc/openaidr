import json
import re
from pathlib import Path

import yaml


class SecretRedactor:
    def __init__(self, rules_path):
        rules = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8"))
        if (
            not isinstance(rules, dict)
            or not isinstance(rules.get("patterns"), list)
            or not rules["patterns"]
        ):
            raise ValueError("secret redaction rules must contain a patterns list")
        key_pattern = rules.get("secret_key_pattern")
        if not isinstance(key_pattern, str) or not key_pattern:
            raise ValueError("secret redaction rules must contain secret_key_pattern")
        self.secret_key_pattern = re.compile(key_pattern, re.I)
        self.patterns = []
        names = set()
        for rule in rules["patterns"]:
            if not isinstance(rule, dict):
                raise ValueError("secret redaction pattern must be an object")
            if set(rule) - {"name", "pattern", "group", "keywords"}:
                raise ValueError("secret redaction pattern has unsupported fields")
            name, expression, group = (
                rule.get("name"),
                rule.get("pattern"),
                rule.get("group", 0),
            )
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[a-z0-9-]+", name)
                or name in names
                or not isinstance(expression, str)
                or not expression
                or type(group) is not int
            ):
                raise ValueError("invalid secret redaction pattern")
            keywords = rule.get("keywords", [])
            if not isinstance(keywords, list) or any(
                not isinstance(word, str) or not word for word in keywords
            ):
                raise ValueError(f"invalid keywords for {name}")
            pattern = re.compile(expression)
            if not 0 <= group <= pattern.groups:
                raise ValueError(f"invalid capture group for {name}")
            self.patterns.append(
                (name, pattern, group, tuple(word.lower() for word in keywords))
            )
            names.add(name)

    def is_secret_key(self, key):
        return bool(self.secret_key_pattern.search(key))

    def redact(self, text):
        spans = []
        lower = text.lower()
        for order, (name, pattern, group, keywords) in enumerate(self.patterns):
            if keywords and not any(word in lower for word in keywords):
                continue
            for match in pattern.finditer(text):
                start, end = match.span(group)
                if start >= 0 and end > start:
                    spans.append((start, end, order, name))
        if not spans:
            return text, []

        # Match the original text so one rule cannot hide a larger secret from
        # another rule. Overlapping matches redact their full combined span.
        merged = []
        for start, end, order, name in sorted(spans):
            if merged and start < merged[-1][1]:
                previous = merged[-1]
                previous[1] = max(previous[1], end)
                if order < previous[2]:
                    previous[2:] = [order, name]
            else:
                merged.append([start, end, order, name])
        parts, cursor = [], 0
        for start, end, _, name in merged:
            parts.extend((text[cursor:start], "[REDACTED:" + name + "]"))
            cursor = end
        parts.append(text[cursor:])
        names = [
            name for _, name in sorted({(order, name) for _, _, order, name in spans})
        ]
        return "".join(parts), names


_REDACTOR = SecretRedactor(Path(__file__).with_name("secret-redaction.yaml"))


def redact_string(text):
    return _REDACTOR.redact(text)


def is_secret_key(key):
    return _REDACTOR.is_secret_key(key)


def contains_secret(value):
    if isinstance(value, list):
        return any(contains_secret(item) for item in value)
    if not isinstance(value, str):
        return False
    if redact_string(value)[1]:
        return True
    if not value.lstrip().startswith(("{", "[", '"')):
        return False
    secret_key = False

    def object_values(pairs):
        nonlocal secret_key
        secret_key |= any(is_secret_key(key) or redact_string(key)[1] for key, _ in pairs)
        # Inspect every value, including duplicate keys that a dict would drop.
        return [item for _, item in pairs]

    try:
        decoded = json.loads(value, object_pairs_hook=object_values)
    except ValueError:
        return False
    return secret_key or contains_secret(decoded)




def redact_value(value):
    """Apply the shared sensor credential rules to nested backend evidence."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if is_secret_key(key) else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")):
            try:
                return json.dumps(redact_value(json.loads(value)), ensure_ascii=False)
            except ValueError:
                pass
        return redact_string(value)[0]
    return value
