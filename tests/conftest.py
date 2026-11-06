"""Shared test isolation."""

import importlib.util
from pathlib import Path
import re

import pytest


def unavailable_test_modules(directory):
    """Test modules that cannot import here: they need the private Intelligence
    service wheel (``openaidr_api``), or a sibling test module this tree does not
    carry. The published client tree ships without the service wheel, so those
    modules are skipped at collection instead of failing it."""
    sources = {path.stem: path.read_text(encoding="utf-8") for path in Path(directory).glob("*.py")}
    service = importlib.util.find_spec("openaidr_api") is not None
    imports = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
    unavailable = set()
    changed = True
    while changed:
        changed = False
        for name, source in sources.items():
            if name in unavailable:
                continue
            for module in imports.findall(source):
                if ((module == "openaidr_api" and not service) or module in unavailable
                        or (module.startswith("test_") and module not in sources)):
                    unavailable.add(name)
                    changed = True
                    break
    return sorted(unavailable)


# This suite uses a separate installed customer SDK. Its mandatory CI job runs
# through scripts/customer_api_tests.py with its own conftest boundary.
collect_ignore = ["customer_api", *[name + ".py" for name in unavailable_test_modules(Path(__file__).parent)]]


@pytest.fixture
def intelligence_key():
    """A synthetic credential accepted by the installed customer or retained SDK."""
    from openaidr_api_client.client import TOKEN

    return next(key for prefix in ("oasc_", "oati_")
                if TOKEN.fullmatch(key := prefix + "a" * 32 + "." + "b" * 43))


@pytest.fixture
def intelligence_environments(db, monkeypatch):
    """Synthetic multi-endpoint deployment for retained compatibility tests."""
    from psycopg import sql
    from openaidr.server import intelligence, model_keys, skill_llm

    origins = ("https://intelligence.example.test", "https://api.opensecura.ai")
    for module in (intelligence, model_keys, skill_llm):
        monkeypatch.setattr(module, "ORIGINS", origins)
    with db.transaction() as conn:
        for table in ("tenant_intelligence_selection", "tenant_intelligence_keys"):
            conn.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}").format(
                sql.Identifier(table), sql.Identifier(table + "_origin_check")))
            conn.execute(sql.SQL("ALTER TABLE {} ADD CHECK (origin IN ({}, {}))").format(
                sql.Identifier(table), *(sql.Literal(origin) for origin in origins)))
    return origins


@pytest.fixture
def backend_hook():
    """An external policy service stub with the ordinary hook wire contract."""
    import uuid
    from openaidr.guardrail.hooks import PRECEDENCE

    def service(policy=None, *, action="allow", mode="enforce"):
        requests = []

        def check(request, deadline):
            requests.append(request)
            selected, reason, rule = action, "Test policy reason", {}
            if policy is not None:
                decisions = [decision for _, decision in policy.evaluate_many(request["actions"])]
                if any(decision.get("evaluation_unavailable") for decision in decisions):
                    raise ValueError("backend evaluation unavailable")
                chosen = min(decisions, key=lambda item: PRECEDENCE[item["action"]],
                             default={"action": "allow", "reason": ""})
                rule, selected, reason = chosen.get("rule", {}), chosen["action"], chosen["reason"]
            return {
                "id": str(uuid.uuid4()), "request_id": request.get("request_id") or str(uuid.uuid4()),
                "product": request["product"], "hook_event": request["hook_event"],
                "status": "evaluated", "mode": mode, "settings_version": 1, "policy_version": 1,
                "evaluated_decision": selected, "returned_decision": "allow" if mode == "shadow" else selected,
                "reason": reason, "rule_id": rule.get("id", ""), "rule_name": rule.get("name", ""),
            }

        check.requests = requests
        return check

    return service


@pytest.fixture(autouse=True)
def isolated_mount_table(monkeypatch):
    from openaidr.sensor import privacy

    monkeypatch.setattr(privacy, "_protected_mounts", lambda: [])


@pytest.fixture
def sensor_executable(tmp_path):
    """A real executable file for hook installation and availability checks."""
    path = tmp_path / "bin" / "openaidr-sensor"
    path.parent.mkdir()
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return str(path)


@pytest.fixture(autouse=True)
def isolated_hook_paths(tmp_path, monkeypatch):
    """Keep every test away from the real ~/.codex and ~/.claude hook files.

    Sensor status, heartbeats, and desktop setup read and write the agents'
    hook settings; a test that exercises them must never touch the files of
    the person running the tests.
    """
    from openaidr.sensor import hooks, service

    # Mocked setup tests must not discover the test runner's own OS service.
    monkeypatch.setattr(service, "needs_migration", lambda: False)
    monkeypatch.setattr(hooks, "detect_apps", lambda config=None: {agent: False for agent in hooks.APP_EVENTS})
    hook_dir = tmp_path / "hook-homes"
    hook_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("GEMINI_CLI_HOME", str(hook_dir))
    monkeypatch.setenv("WORKBUDDY_CONFIG_DIR", str(hook_dir / "workbuddy"))
    monkeypatch.setattr(
        hooks,
        "settings_path",
        lambda agent="claude", config=None: hook_dir
        / ("claude-settings.json" if agent == "claude" else agent + "-hooks.json"),
    )
    monkeypatch.setattr(hooks, "codex_config_path", lambda config=None: hook_dir / "codex-config.toml")
    monkeypatch.setattr(hooks, "codex_paths", lambda config=None: {
        hooks.settings_path("codex", config): hooks.codex_config_path(config)})
    return hook_dir
