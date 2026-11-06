"""Sensor control-plane wire defaults. Messages use snake_case JSON dictionaries."""

from copy import deepcopy

# Windows agents allow extra shell startup time before the native client starts.
HOOK_TIMEOUT_SECONDS = 3
WINDOWS_AGENT_HOOK_TIMEOUT_SECONDS = 5
# Windows clients retain a three-second response window from their own start.
# Backend work is independent; there is no Windows launcher watchdog.
AGENT_HOOK_TIMEOUT_SECONDS = 3
# Existing agent sessions keep immutable two-second launchers until restart.
AGENT_HOOK_TIMEOUTS_NS = (2_000_000_000, AGENT_HOOK_TIMEOUT_SECONDS * 1_000_000_000)
HOOK_DECISION_TIMEOUT_SECONDS = 2
HOOK_WORK_TIMEOUT_SECONDS = 10


def default_sensor_config() -> dict:
    return {
        "heartbeat_interval_s": 30,
        "batch_max_events": 500,
        "flush_interval_s": 5,
        "capture": {
            "prompt_text": True,
            "response_text": True,
            "tool_input": True,
            "tool_output": True,
            "raw": False,
            "max_text_bytes": 16384,
            "redact": True,
        },
    }


def normalize_sensor_config(config: dict) -> dict:
    config = deepcopy(config)
    for key, default in [
        ("heartbeat_interval_s", 30),
        ("batch_max_events", 500),
        ("flush_interval_s", 5),
    ]:
        if config.get(key, 0) <= 0:
            config[key] = default
    capture = config.setdefault("capture", {})
    if capture.get("max_text_bytes", 0) <= 0:
        capture["max_text_bytes"] = 16384
    return config
