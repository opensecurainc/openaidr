"""Customer scanner worker with one service request per AI-enabled skill."""

import json
import subprocess
from uuid import UUID, uuid5

from openaidr_api_client.client import Connection, Unavailable
from openaidr.core.skill_bundle import canonical, digest
from . import skill_intel_proxy, skill_worker


PROFILE = "skill-assessment.1"
BUNDLE_PROFILE = "skill-full-scan.1"
PROTOCOL = "skills-service-v1"


def contracts(*, bundle=False):
    try:
        if bundle:
            from openaidr_api_client.contracts import service_skill_scans as service_skills
        else:
            from openaidr_api_client.contracts import service_skills
    except ImportError:
        raise Unavailable("Customer service SDK is unavailable") from None
    return service_skills


def scanner_profile(mode, *, intel_origin="", legacy=False):
    wire = contracts()
    if mode not in ("static", "llm"):
        raise ValueError("Invalid scanner mode")
    settings = {"adapter": 4 if legacy else 5, "mode": mode,
                "service_profile": (PROFILE if legacy else BUNDLE_PROFILE) if mode == "llm" else ""}
    if mode == "static":
        settings.update(intelligence_adapter=1, intelligence_origin=intel_origin)
    return wire.REVISION + ":" + digest(canonical(settings))


def model_environment(mode, client=None):
    contracts()
    if mode not in ("static", "llm"):
        raise ValueError("Invalid scanner mode")
    if mode == "static":
        return {}
    if client is None:
        raise ValueError("Service scanning requires the tenant worker connection")
    response = client.post("/internal/v1/skill-scans/model-mode", json={})
    response.raise_for_status()
    if response.json() != {"service": "intelligence", "profile": PROFILE}:
        raise ValueError("Invalid scanner service profile")
    return {"SKILLSPECTOR_PROVIDER": "openai", "SKILLSPECTOR_MODEL": PROFILE,
            "SKILLSPECTOR_REASONING_EFFORT": "none"}


def package_request_id(job, connection, queries):
    # Credential rotation must not turn an ambiguous batch into a new operation.
    identity = ["package_vulnerabilities", connection.tenant_id, connection.origin, queries]
    return str(uuid5(UUID(job["lease_id"]), json.dumps(identity, sort_keys=True, allow_nan=False)))


def scan(job, *, client, binary, mode="static", intel, timeout=skill_worker.SCAN_TIMEOUT,
         package_transport=None):
    contracts()
    connection = skill_worker.job_connection(job, intel)
    if not isinstance(connection, Connection):
        raise Unavailable("Scanner Intelligence connection is unavailable")
    if mode not in ("static", "llm"):
        raise ValueError("Invalid scanner mode")
    if mode == "llm" and not job.get("llm"):
        raise ValueError("AI analysis is not authorized for this scan")
    selected_mode = "llm" if job.get("llm") else "static"
    if selected_mode == "llm":
        from .service_skill_scan import scan as scan_bundle

        report = scan_bundle(job, client=client, binary=binary, timeout=timeout)
        return {key: value for key, value in report.items() if key not in ("model", "inference_usage", "usage_incomplete")}
    from openaidr_api_client.bridges import skill_intel_adapter

    def package_bridge(captured):
        return skill_intel_proxy.provider(captured, transport=package_transport,
            request_id_for=lambda queries: package_request_id(job, captured, queries))

    report = skill_worker.scan(job, binary=binary, mode=selected_mode,
        timeout=timeout, intel=connection, bridge_factory=package_bridge, adapter_script=skill_intel_adapter.__file__)
    # The shared validator has already bounded the shape. Keep captured finding
    # and coverage fields intact, including literal model/provider evidence.
    return {key: value for key, value in report.items() if key not in ("model", "inference_usage", "usage_incomplete")}


def run_once(client, profile, *, binary, mode="static", intel, package_transport=None):
    contracts(bundle=True)
    request = {"profile": profile, "model_protocol": PROTOCOL, "intelligence_credentials": True}
    request["llm_profile"] = scanner_profile("llm", intel_origin=intel.origin if intel else "") + ":metered-1"
    response = client.post("/internal/v1/skill-scans/claim", json=request)
    response.raise_for_status()
    job = response.json().get("job")
    if job is None:
        return False
    result = {"sha256": job["sha256"], "lease_id": job["lease_id"]}
    try:
        result["report"] = scan(job, client=client, binary=binary, mode=mode, intel=intel,
                                package_transport=package_transport)
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except (ValueError, TypeError, KeyError):
        result["error"] = "invalid_report"
    except Exception:
        result["error"] = "scanner_failed"
    reply = client.post("/internal/v1/skill-scans/complete", json=result)
    reply.raise_for_status()
    return True
