"""Customer investigation admission readiness for the tenant worker."""

from . import intelligence, model_keys


def investigation_readiness(st, cfg):
    result = {"ready": False, "reason": "runtime_unavailable", "protocol_version": 4}
    try:
        connection = intelligence.selected_connection(cfg, st)
        if connection is not None and connection.tenant_id == cfg.tenant_id:
            value = model_keys.verify_capabilities(cfg.tenant_id, connection)
            result["ready"] = value["capabilities"]["investigations"] == "configured"
            result["reason"] = "configured" if result["ready"] else value["capabilities"]["investigations"]
    except Exception:
        # A configured route is an admission prerequisite, not proof that a
        # provider or remote worker can finish a future request.
        pass
    return result
