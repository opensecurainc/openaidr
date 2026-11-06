"""Natural-language drafts and bounded previews of ordinary fixed rules."""

from openaidr_api_client.validation.rule_authoring import (
    KINDS as KINDS,
    ACTIONS as ACTIONS,
    MATCH_FIELDS as MATCH_FIELDS,
    EXAMPLE_FIELDS as EXAMPLE_FIELDS,
    object_schema as object_schema,
    TEXT as TEXT,
    RULE_SCHEMA as RULE_SCHEMA,
    EXAMPLE_SCHEMA as EXAMPLE_SCHEMA,
    text as text,
    validate_draft as validate_draft,
    validate_result as validate_result,
)


from psycopg.types.json import Jsonb

from openaidr.core.policy import Policy

from .httpx import APIError as APIError, require
from .page_chat import provider_errors
from .store import new_id


def generate(intent, chat, tenant):
    text(intent, "Description", 4000)
    # Share the existing assistant admission limits and record only billing metadata.
    with chat._admit(tenant) as connection:
        with provider_errors():
            return validate_result(intent, chat.generate(tenant, "rule_generation", {"intent": intent},
                                                       connection=connection))


def check_version(policy, version):
    require(type(version) is int and version >= 0, "invalid policy version")
    require(policy["version"] == version, "Fixed rules changed. Reload and test the draft again.", 409)


def preview(policy, draft, rule_id=""):
    draft = validate_draft(draft)
    candidate = {**draft["rule"], "id": rule_id or new_id(), "enabled": True}
    if rule_id:
        require(any(r.get("id") == rule_id and r.get("source") == "tenant_ai"
                    for r in policy["rules"]), "no such generated rule", 404)
        rules = [candidate if r.get("id") == rule_id else r for r in policy["rules"]]
    else:
        rules = policy["rules"] + [candidate]
    results = []
    for example in draft["examples"]:
        event = {"kind": example["kind"], "agent": {"product": example["product"]},
                 "tool": {"name": example["tool_name"]}}
        field, key = {"command": ("command", "text"), "file.read": ("file", "path"),
                      "file.write": ("file", "path"), "network": ("network", "host"),
                      "tool.call": ("tool", "name")}[example["kind"]]
        event[field] = {key: example["value"]}
        context = {"path_windows": example["os"] == "windows", "path_home": example["path_home"]}
        alone = Policy({"rules": [candidate]}, **context).evaluate(event)
        combined = Policy({"rules": rules}, **context).evaluate(event)
        unavailable = any(d.get("evaluation_unavailable") for d in (alone, combined))
        matched = alone.get("rule", {}).get("id") == candidate["id"] if not unavailable else None
        shadowed = bool(matched and combined.get("rule", {}).get("id") != candidate["id"])
        results.append({
            "label": example["label"], "matched": matched,
            "expected_match": example["expected_match"], "shadowed": shadowed,
            "action": combined["action"] if not unavailable else None,
            "rule_name": combined.get("rule", {}).get("name", "") if not unavailable else "",
            "passed": not unavailable and matched == example["expected_match"] and not shadowed,
            "error": "Evaluation could not complete within its limits." if unavailable else "",
        })
    return {"version": policy["version"], "passed": all(row["passed"] for row in results), "results": results}


def save(st, tenant, actor, version, *, draft=None, rule_id=None, enabled=False):
    require(type(enabled) is bool, "enabled must be a boolean")
    if rule_id is None:
        draft = validate_draft(draft)
    with st.transaction() as conn:
        # Serialize creation even for a tenant with no policy row yet. The row
        # lock also excludes ordinary policy writes while testing and saving.
        st.one("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", tenant, conn=conn)
        st.many("SELECT version FROM policies WHERE tenant_id=$1 FOR UPDATE", tenant, conn=conn)
        policy = st.get_policy(tenant, conn=conn)
        check_version(policy, version)
        if rule_id is None:
            result = preview(policy, draft)
            require(result["passed"], "Test cases must pass before saving the draft.")
            rule = {**draft["rule"], "id": new_id(), "enabled": False,
                    "source": "tenant_ai", "authoring": draft}
            rules = [*policy["rules"], rule]
            action = "policy.rule.add"
        else:
            rule = next((r for r in policy["rules"] if r.get("id") == rule_id
                         and r.get("source") == "tenant_ai"), None)
            require(rule is not None, "no such generated rule", 404)
            if enabled:
                draft = validate_draft(rule.get("authoring"))
                require(draft["rule"] == {key: rule.get(key) for key in ("name", "action", "reason", "match")},
                        "Saved rule differs from its reviewed draft. Create a new draft.")
                require(preview(policy, draft, rule_id)["passed"],
                        "Test cases no longer pass. Review the existing rules before enabling.")
            rules = [dict(r, enabled=enabled) if r.get("id") == rule_id else r for r in policy["rules"]]
            action = "policy.rule.enable" if enabled else "policy.rule.disable"
        saved = st.save_policy(tenant, rules, conn=conn)
        st.execute(
            """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
               VALUES($1,$2,'user',$3,$4,$5,'policy_rule',$6,$7)""",
            new_id(), tenant, actor["id"], actor["name"], action, rule["id"],
            Jsonb({"version": saved["version"], "enabled": enabled,
                   "rule": {key: rule[key] for key in ("name", "action", "reason", "match")}}), conn=conn,
        )
        return {"policy": saved, "rule_id": rule["id"]}
