"""Sensor product and evidence-gap vocabulary shared without application imports."""

PRODUCTS = (
    "claude-code",
    "cowork",
    "claude-ai",
    "codex-cli",
    "gemini-cli",
    "copilot-cli",
    "github-copilot",
    "cursor",
    "antigravity",
    "opencode",
    "hermes-agent",
    "aider",
    "unknown",
)
EVIDENCE_GAPS = frozenset(
    (
        "skipped_history",
        "source_reset",
        "parser_restart",
        "malformed_record",
        "oversized_record",
        "unsupported_content",
        "skipped_content",
        "missing_tool_call",
        "capture_disabled",
        "content_truncated",
        "content_redacted",
    )
)
