"""Reported effort metadata, without inferring model defaults or token budgets."""

EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra", "auto")


def reasoning_effort(attrs):
    for key in (
        "reasoning_effort", "gen_ai.request.reasoning_effort", "reasoning.effort",
        "effort", "model_reasoning_effort",
    ):
        if key not in attrs:
            continue
        value = attrs[key]
        if isinstance(value, dict):
            value = value.get("level")
        value = value.strip().lower() if isinstance(value, str) else None
        return value if value in EFFORTS else None
    return None
