"""Rule authoring through real HTTP, PostgreSQL, and the isolated matcher."""

import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from openaidr.core.policy import Policy
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server import rule_authoring
from test_server_e2e import chat_system, system  # noqa: F401

BASE = "/api/v1/response/policy/rules"


def draft():
    return {
        "intent": "Block agents from reading files under /srv/payroll/",
        "explanation": "Deny file-read events under /srv/payroll/.",
        "limitations": ["Reads hidden inside shell commands are not covered."],
        "rule": {"name": "Protect payroll files", "action": "deny", "reason": "Payroll files are restricted.",
                 "match": {"kinds": ["file.read"], "products": [], "tool_name": "",
                           "command_regex": "", "path_glob": "/srv/payroll/**", "host_glob": ""}},
        "examples": [{"label": label, "kind": "file.read", "value": path, "expected_match": matches,
                      "product": "codex-cli", "tool_name": "Read", "os": "linux", "path_home": "/home/example"}
                     for label, path, matches in [("Payroll file", "/srv/payroll/salaries.csv", True),
                                                  ("Public file", "/srv/public/readme.txt", False)]],
    }


@pytest.fixture
def authoring(chat_system):
    client, st, app, tenant, user, sent, provider, _ = chat_system
    st.update_user(tenant, user["id"], role="analyst")
    st.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection',$2)",
               tenant, "test-provider-key")
    value = draft()
    provider["body"]["output"] = [{"type": "message", "role": "assistant", "content": [{
        "type": "output_text", "text": json.dumps({"status": "draft", **{k: v for k, v in value.items() if k != "intent"}}),
    }]}]
    return client, st, app, tenant, user, sent, provider


def test_generation_preview_save_and_enable_are_separate_audited_actions(authoring):
    client, st, app, tenant, user, sent, _, = authoring
    original = st.get_policy(tenant)
    mode = client.get("/api/v1/response/hook-settings").json()
    generated = client.post(BASE + "/generate", json={"intent": draft()["intent"]})
    assert generated.status_code == 200, generated.text
    assert generated.headers["cache-control"] == "no-store"
    value = generated.json()["draft"]
    assert value == draft()
    assert st.get_policy(tenant) == original
    assert sent[0]["store"] is False and sent[0]["tools"] == []
    assert sent[0]["text"]["format"]["strict"] is True
    assert json.loads(sent[0]["input"]) == {"intent": draft()["intent"]}
    assert "Private tenant name" not in json.dumps(sent)
    assert st.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1 AND purpose='assistant' AND status='completed'", tenant) == 1

    tested = client.post(BASE + "/preview", json={"version": original["version"], "draft": value, "rule_id": ""})
    assert tested.status_code == 200, tested.text
    assert tested.json()["passed"] is True
    assert [r["action"] for r in tested.json()["results"]] == ["deny", "allow"]
    assert st.get_policy(tenant) == original
    saved = client.post(BASE + "/drafts", json={"version": original["version"], "draft": value})
    assert saved.status_code == 200, saved.text
    data = saved.json()
    rule = data["policy"]["rules"][-1]
    assert rule["enabled"] is False and rule["authoring"] == value
    event = {"kind": "file.read", "file": {"path": "/srv/payroll/salaries.csv"}}
    assert Policy(data["policy"]).evaluate(event)["action"] == "allow"
    enabled = client.patch(BASE + "/" + rule["id"], json={"version": data["policy"]["version"], "enabled": True})
    assert enabled.status_code == 200, enabled.text
    assert Policy(enabled.json()["policy"]).evaluate(event)["action"] == "deny"
    disabled = client.patch(BASE + "/" + rule["id"], json={"version": enabled.json()["policy"]["version"], "enabled": False})
    assert disabled.status_code == 200
    assert Policy(disabled.json()["policy"]).evaluate(event)["action"] == "allow"
    assert client.get("/api/v1/response/hook-settings").json() == mode
    rows = st.many("SELECT action,actor_id,details FROM audit_log WHERE tenant_id=$1 AND target_id=$2 ORDER BY at", tenant, rule["id"])
    assert [r["action"] for r in rows] == ["policy.rule.add", "policy.rule.enable", "policy.rule.disable"]
    assert all(r["actor_id"] == user["id"] for r in rows)
    assert [r["details"]["enabled"] for r in rows] == [False, True, False]


def test_existing_precedence_stale_versions_and_concurrent_saves(authoring):
    client, st, _, tenant, user, _, _ = authoring
    value = draft()
    policy = st.get_policy(tenant)
    saved = client.post(BASE + "/drafts", json={"version": policy["version"], "draft": value}).json()
    policy = saved["policy"]
    assert client.post(BASE + "/drafts", json={"version": policy["version"] - 1, "draft": value}).status_code == 409
    assert client.post(BASE + "/preview", json={"version": policy["version"] - 1, "draft": value, "rule_id": ""}).status_code == 409
    earlier = {**value["rule"], "id": "earlier", "action": "warn", "enabled": True, "name": "Existing warning"}
    policy = st.save_policy(tenant, [earlier, *policy["rules"]])
    preview = client.post(BASE + "/preview", json={"version": policy["version"], "draft": value, "rule_id": saved["rule_id"]}).json()
    assert preview["passed"] is False
    assert preview["results"][0]["shadowed"] is True
    assert preview["results"][0]["action"] == "warn"
    assert client.patch(BASE + "/" + saved["rule_id"], json={"version": policy["version"], "enabled": True}).status_code == 400
    assert not st.get_policy(tenant)["rules"][-1]["enabled"]
    assert client.post(BASE + "/drafts", json={"version": policy["version"], "draft": value}).status_code == 400
    policy = st.save_policy(tenant, [])

    def save(_):
        try:
            return rule_authoring.save(st, tenant, user, policy["version"], draft=value)
        except rule_authoring.APIError as error:
            return error.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, range(2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert 409 in results
    assert len(st.get_policy(tenant)["rules"]) == 1


def test_authorization_tenant_isolation_and_bad_input(authoring):
    client, st, _, tenant, user, sent, _ = authoring
    value = draft()
    policy = st.get_policy(tenant)
    saved = client.post(BASE + "/drafts", json={"version": policy["version"], "draft": value}).json()
    rule_id = saved["rule_id"]
    version = saved["policy"]["version"]
    for role in ("viewer", "admin"):
        st.update_user(tenant, user["id"], role=role)
        for endpoint, payload in (("generate", {"intent": value["intent"]}),
                                  ("preview", {"version": version, "draft": value, "rule_id": ""}),
                                  ("drafts", {"version": version, "draft": value})):
            assert client.post(BASE + "/" + endpoint, json=payload).status_code == 403
        assert client.patch(BASE + "/" + rule_id, json={"version": version, "enabled": True}).status_code == 403
    assert not sent
    st.update_user(tenant, user["id"], role="analyst")
    for bad in ({"intent": ""}, {"intent": "x" * 4001}, {"intent": "x", "tenant": tenant}):
        assert client.post(BASE + "/generate", json=bad).status_code == 400
    for mutate in (
        lambda d: d["rule"].update(action="allow"),
        lambda d: d["rule"]["match"].update(command_regex="["),
        lambda d: d["rule"]["match"].update(command_regex="(" * 1000 + ")" * 1000),
        lambda d: d["rule"]["match"].update(unknown="ignored"),
        lambda d: d["rule"]["match"].update(products="codex-cli"),
        lambda d: d["examples"][0].update(expected_match=False),
        lambda d: d["examples"][0].update(value="/srv/public/actually-not-payroll.txt"),
        lambda d: d["examples"][0].update(path_home="relative/home"),
    ):
        invalid = copy.deepcopy(value)
        mutate(invalid)
        response = client.post(BASE + "/drafts", json={"version": version, "draft": invalid})
        assert response.status_code == 400, response.text
    assert len(st.get_policy(tenant)["rules"]) == len(saved["policy"]["rules"])
    other = st.bootstrap_tenant("Other", "other-" + tenant[:8])["tenant"]["id"]
    other_user = st.create_user(other, "other@example.test", "Other", "unused", "analyst")
    client.cookies.set(CONSOLE_COOKIE, st.create_session(other_user["id"], other))
    other_version = st.get_policy(other)["version"]
    assert client.patch(BASE + "/" + rule_id, json={"version": other_version, "enabled": True}).status_code == 403
    assert client.post(BASE + "/preview", json={"version": other_version, "draft": value, "rule_id": rule_id}).status_code == 403
    client.cookies.clear()
    assert client.post(BASE + "/generate", json={"intent": "test"}).status_code == 401


def test_clarifications_and_provider_failures_never_write_policy(authoring):
    client, st, app, tenant, _, sent, provider = authoring
    original = st.get_policy(tenant)
    part = provider["body"]["output"][0]["content"][0]
    for status in ("clarify", "unsupported"):
        part["text"] = json.dumps({"status": status, "explanation": "Specify the production path.",
                                   "limitations": [], "rule": None, "examples": []})
        reply = client.post(BASE + "/generate", json={"intent": "Block production changes"})
        assert reply.status_code == 200
        assert reply.json() == {"status": status, "explanation": "Specify the production path."}
    for malformed in ("not JSON", json.dumps({"status": "draft"}),
                      json.dumps({"status": "draft", **{k: v for k, v in draft().items() if k != "intent"},
                                  "rule": {**draft()["rule"], "action": "allow"}})):
        part["text"] = malformed
        assert client.post(BASE + "/generate", json={"intent": "test"}).status_code == 502
    provider["timeout"] = True
    assert client.post(BASE + "/generate", json={"intent": "test"}).status_code == 504
    provider["timeout"] = False
    provider["status"] = 401
    assert client.post(BASE + "/generate", json={"intent": "test"}).status_code == 503
    from openaidr.server.page_chat import PageChat
    app.state.service.page_chat = PageChat(st)
    assert client.post(BASE + "/generate", json={"intent": "test"}).status_code == 503
    assert st.get_policy(tenant) == original
    assert len(sent) == 7


def test_preview_uses_endpoint_path_context_and_bounds_regex_evaluation():
    value = draft()
    value["rule"]["match"]["path_glob"] = "~/.private/**"
    value["examples"][0].update(value="D:\\Profiles\\Ada\\.PRIVATE\\key", os="windows", path_home="D:\\Profiles\\Ada")
    assert rule_authoring.preview({"version": 1, "rules": []}, value)["passed"]
    value["rule"]["match"].update(kinds=["command"], path_glob="", command_regex="(a+)+$")
    for example in value["examples"]:
        example["kind"] = "command"
    value["examples"][0]["value"] = "aaaa"
    value["examples"][1]["value"] = "a" * 1000 + "!"
    result = rule_authoring.preview({"version": 1, "rules": []}, value)
    assert not result["passed"]
    assert result["results"][1]["matched"] is None
    assert result["results"][1]["action"] is None
    assert result["results"][1]["error"]
