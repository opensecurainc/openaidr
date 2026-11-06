"""Worker credential isolation and pinned scanner integration with a stub gateway."""

import base64
from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from openaidr.core.skill_bundle import digest, validate_manifest
from openaidr_api_client.bridges import skill_intel_adapter
from openaidr.server import skill_intel_proxy, skill_worker
from openaidr_api_client.client import Connection, Unavailable
from openaidr_api_client.clients.threat_intel import ThreatIntelClient


CUSTOMER_SERVICES = "request_id" in inspect.signature(ThreatIntelClient.packages).parameters


class Gateway:
    def __init__(self):
        self.origin = "https://intel.example.com"
        self.requests, self.failed = [], False
        self.severity, self.vectors = "high", []
        self.checked = datetime.now(timezone.utc) - timedelta(hours=23)
        self.expires = self.checked + timedelta(days=1)

    def options(self):
        options = {"transport": httpx.MockTransport(self.handle)}
        if CUSTOMER_SERVICES:
            options["request_id_for"] = lambda queries: str(uuid4())
        return options

    def handle(self, request):
        self.requests.append(request)
        path = "/v1/services/packages/check" if CUSTOMER_SERVICES else "/v1/packages/check"
        assert str(request.url) == self.origin + path
        if self.failed:
            return httpx.Response(401, json={"private": "provider secret"})
        results = []
        for item in json.loads(request.content)["packages"]:
            query = {"package": {"ecosystem": "PyPI" if item["ecosystem"] == "pypi" else "npm", "name": item["name"]},
                     "version": item["version"]}
            findings = [{"id": "CVE-2026-1234", "aliases": ["GHSA-example"], "source_ids": ["GHSA-example"],
                         "summary": "Example dependency vulnerability", "severity": self.severity, "fixed_versions": ["2.0.0"],
                         "severity_vectors": self.vectors, "url": "https://osv.dev/vulnerability/GHSA-example"}]
            results.append({"query": query, "status": "complete", "findings": findings,
                            "checked_at": self.checked.isoformat(), "expires_at": self.expires.isoformat(), "reason": ""})
        value = {"provider": "OSV", "results": results}
        if CUSTOMER_SERVICES:
            value = {"profile": "package-vulnerabilities.1", "results": results,
                     "billing": {"request_id": request.headers["Idempotency-Key"],
                                 "service": "package_vulnerabilities", "state": "disabled",
                                 "credits_reserved": None, "credits_charged": None, "rate_version": None}}
        return httpx.Response(200, json=value)


@pytest.fixture
def intel(intelligence_key):
    return Connection("https://intel.example.com", intelligence_key, str(uuid4()))


def test_worker_bridge_authentication_limits_partial_failure_and_credential_isolation(intel):
    gateway = Gateway()
    with skill_intel_proxy.provider(intel, **gateway.options()) as bridge:
        env = bridge.environment
        assert intel.api_key not in json.dumps(env)
        origin = env["OPENAIDR_SKILL_INTEL_ORIGIN"]
        headers = {"Authorization": "Bearer " + env["OPENAIDR_SKILL_INTEL_TOKEN"]}
        package = {"ecosystem": "PyPI", "name": "Example", "version": "1.0.0"}
        body = {"packages": [package], "timeout": 10}
        with httpx.Client(base_url=origin, trust_env=False) as client:
            assert client.post("/v1/packages/check", json=body).status_code == 403
            assert client.post("/other", headers=headers, json=body).status_code == 403
            assert not gateway.requests
            result = client.post("/v1/packages/check", headers=headers,
                                 json={**body, "packages": [package, {**package, "version": "^1.0"}]}).json()
            assert [item["status"] for item in result["results"]] == ["complete", "unsupported"]
            assert result["results"][0]["findings"][0]["id"] == "CVE-2026-1234"
            assert bridge.expires_at == gateway.expires
            assert gateway.requests[0].headers["authorization"] == "Bearer " + intel.api_key
            assert intel.tenant_id not in gateway.requests[0].content.decode()
            assert intel.api_key not in json.dumps(result)
            gateway.failed = True
            result = client.post("/v1/packages/check", headers=headers, json=body).json()
            assert result["results"][0]["status"] == "unavailable"
            assert "provider secret" not in json.dumps(result)
            assert bridge.expires_at <= datetime.now(timezone.utc) + timedelta(minutes=5)
    with pytest.raises(httpx.TransportError):
        httpx.get(origin + "/healthz", timeout=0.2, trust_env=False)


@pytest.mark.parametrize("prefix", ["THREAT_INTEL", "INTELLIGENCE"])
def test_worker_configuration_and_profiles_keep_keys_out_of_scanner_identity(intel, monkeypatch, tmp_path, prefix):
    for family in ("THREAT_INTEL", "INTELLIGENCE"):
        for field in ("ORIGIN", "API_KEY", "API_KEY_FILE", "CA_FILE"):
            monkeypatch.delenv("OPENAIDR_" + family + "_" + field, raising=False)
    assert skill_intel_proxy.configuration() is None
    monkeypatch.setenv("OPENAIDR_" + prefix + "_ORIGIN", intel.origin)
    with pytest.raises(ValueError):
        skill_intel_proxy.configuration()
    monkeypatch.setattr(skill_worker, "memory_directory", lambda: tmp_path)
    with pytest.raises(ValueError):
        skill_worker.main()
    keyfile = tmp_path / "intel.key"
    keyfile.write_text(intel.api_key)
    monkeypatch.setenv("OPENAIDR_" + prefix + "_API_KEY_FILE", str(keyfile))
    monkeypatch.setenv("OPENAIDR_TENANT_ID", intel.tenant_id)
    if prefix == "THREAT_INTEL":
        with pytest.raises(ValueError, match="legacy threat-only"):
            skill_intel_proxy.configuration()
        monkeypatch.setenv("OPENAIDR_INTELLIGENCE_ORIGIN", intel.origin)
        monkeypatch.setenv("OPENAIDR_INTELLIGENCE_API_KEY_FILE", str(keyfile))
    assert skill_intel_proxy.configuration().api_key == intel.api_key
    direct = skill_worker.scanner_profile("static", {})
    profile = skill_worker.scanner_profile("static", {}, intel_origin=intel.origin)
    assert profile != direct
    keyfile.write_text(intel.api_key[:5] + "c" * 32 + "." + "d" * 43)
    assert skill_worker.scanner_profile("static", {}, intel_origin=skill_intel_proxy.configuration().origin) == profile


def pinned_binary():
    binary = Path(os.environ.get("OPENAIDR_TEST_SKILLSPECTOR_BINARY", "/opt/skillspector/bin/skillspector"))
    if not binary.is_file():
        pytest.skip("Pinned scanner integration requires OPENAIDR_TEST_SKILLSPECTOR_BINARY; the dedicated CI job supplies it")
    return binary


def test_pinned_model_bridge_loads_without_service_executor(tmp_path):
    binary = pinned_binary().with_name("python")
    resources = tmp_path / "bridges"
    resources.mkdir()
    source = Path(skill_intel_adapter.__file__).parent
    for name in ("skill_intel_adapter.py", "skill_model_adapter.py", "skill_projection.py"):
        shutil.copyfile(source / name, resources / name)
    script = f"""
import runpy, sys
from pathlib import Path
root = Path({str(resources)!r})
runpy.run_path(str(root / 'skill_projection.py'))
assert not any(name == 'skillspector' or name.startswith('skillspector.') for name in sys.modules)
runpy.run_path(str(root / 'skill_intel_adapter.py'))['install']()
runpy.run_path(str(root / 'skill_model_adapter.py'))['install']()
assert not any(name in ('api', 'openaidr', 'openaidr_api') or name.startswith(('api.', 'openaidr.', 'openaidr_api.')) for name in sys.modules)
print('installed bridge resources work without the service executor')
"""
    result = subprocess.run([str(binary), "-I", "-c", script], capture_output=True, text=True, timeout=20,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
             "OPENAIDR_SKILL_INTEL_ORIGIN": "http://127.0.0.1:12345",
             "OPENAIDR_SKILL_INTEL_TOKEN": "fixture-only",
             "OPENAIDR_SKILL_MODEL_ORIGIN": "http://127.0.0.1:12345",
             "OPENAI_API_KEY": "fixture-only"})
    assert result.returncode == 0, result.stderr
    assert 'installed bridge resources work without the service executor' in result.stdout


def test_pinned_adapter_retains_advisories_with_bounded_package_batches(intel):
    binary, gateway = pinned_binary(), Gateway()
    adapter = Path(skill_intel_adapter.__file__)
    script = (
        f"import runpy,json; runpy.run_path({str(adapter)!r})['install'](); "
        "from skillspector.nodes.analyzers.osv_client import query_batch; "
        "results=query_batch([(f'example{i}','1.0.0') for i in range(257)], 'PyPI'); "
        "print(json.dumps({'first':vars(results[0][0]),'count':len(results),'limitations':[v.reason.value for v in results.limitations]}))"
    )
    with skill_intel_proxy.provider(intel, **gateway.options()) as bridge:
        result = subprocess.run([str(binary.with_name("python")), "-P", "-c", script],
                                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **bridge.environment},
                                capture_output=True, text=True, check=True, timeout=30)
    value = json.loads(result.stdout)
    assert value["first"] == {"vuln_id": "CVE-2026-1234", "aliases": ["GHSA-example"],
                              "summary": "Example dependency vulnerability", "severity": "HIGH"}
    assert value["count"] == 256 and "output_limit" in value["limitations"]
    assert [len(json.loads(request.content)["packages"]) for request in gateway.requests] == [25] * 10 + [6]


@pytest.mark.parametrize("scenario", ["matched", "unavailable", "unpinned", "unknown_severity", "cvss"])
def test_pinned_scanner_gateway_findings_coverage_expiry_and_no_direct_provider(intel, monkeypatch, tmp_path, scenario):
    binary = pinned_binary()
    gateway = Gateway()
    gateway.failed = scenario == "unavailable"
    if scenario in ("unknown_severity", "cvss"):
        gateway.severity = "unknown"
    if scenario == "cvss":
        gateway.vectors = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]
    real_provider = skill_intel_proxy.provider
    monkeypatch.setattr(skill_intel_proxy, "provider", lambda cfg: real_provider(cfg, **gateway.options()))
    monkeypatch.setattr(skill_worker, "memory_directory", lambda: tmp_path)
    # The actual isolated scanner may connect only to the temporary worker bridge.
    guard = tmp_path / "guard"
    guard.mkdir()
    attempts = tmp_path / "external-network"
    (guard / "sitecustomize.py").write_text(
        "import socket\nfrom pathlib import Path\noriginal=socket.socket.connect\n"
        "def connect(self,address):\n"
        "    if isinstance(address,tuple) and address[0] not in ('127.0.0.1','::1'):\n"
        f"        Path({str(attempts)!r}).write_text('external network attempted')\n"
        "        raise RuntimeError('External scanner network is forbidden')\n"
        "    return original(self,address)\nsocket.socket.connect=connect\n"
    )
    contents = {"SKILL.md": b"---\nname: dependency-check\ndescription: Review dependencies\n---\nReview requirements.txt.\n",
                "requirements.txt": b"example>=1.0.0\n" if scenario == "unpinned" else b"example==1.0.0\n"}
    manifest = {"version": 1, "complete": True, "files": sorted(
        [{"path": name, "size": len(data), "sha256": digest(data)} for name, data in contents.items()], key=lambda item: item["path"])}
    job = {"manifest": manifest, "sha256": validate_manifest(manifest)[0],
           "files": {name: base64.b64encode(data).decode() for name, data in contents.items()}}
    options = {}
    if scenario == "matched":
        options = {"bridge_factory": lambda cfg: real_provider(cfg, **gateway.options()),
                   "adapter_script": skill_intel_adapter.__file__}
        # Explicit receiving inputs must not fall back to the current defaults.
        monkeypatch.setattr(skill_intel_proxy, "provider", lambda _: pytest.fail("Used the default bridge"))
        monkeypatch.setattr(skill_worker, "skill_intel_adapter", SimpleNamespace(__file__="must-not-run"))
    report = skill_worker.scan(job, binary=str(binary), intel=intel, model_env={"PYTHONPATH": str(guard)}, **options)
    assert not attempts.exists()
    assert intel.api_key not in json.dumps(report)
    if scenario in ("matched", "cvss", "unknown_severity"):
        assert gateway.requests
        assert any(issue["rule"] == "SC4" and issue["title"] == "example==1.0.0"
                   and issue["severity"] == ("CRITICAL" if scenario == "cvss" else "HIGH")
                   for issue in report["issues"]), report
        assert report["intel_expires_at"] == gateway.expires.isoformat()
        if scenario == "unknown_severity":
            assert report["complete"] is False
            assert any(reason["code"] == "opaque_content" for reason in report["coverage"]["reasons"])
        else:
            assert report["complete"] is True
    else:
        assert report["complete"] is False
        assert any(reason["code"] in ("opaque_content", "analyzer_runtime_error", "scanner_limitation")
                   for reason in report["coverage"]["reasons"])
        if scenario == "unavailable":
            assert gateway.requests
            assert datetime.fromisoformat(report["intel_expires_at"]) <= datetime.now(timezone.utc) + timedelta(minutes=5)
        else:
            assert not gateway.requests


@pytest.mark.parametrize("authorization", [None, False])
def test_customer_llm_worker_rejects_unauthorized_static_job(intel, authorization):
    from openaidr.server import service_skill_worker

    error = ValueError if CUSTOMER_SERVICES else Unavailable
    message = "AI analysis is not authorized" if CUSTOMER_SERVICES else "Customer service SDK is unavailable"
    with pytest.raises(error, match=message):
        service_skill_worker.scan({"llm": authorization}, client=None, binary="must-not-run",
                                  mode="llm", intel=intel)
