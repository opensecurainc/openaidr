"""Dedicated SkillSpector worker; backend access is limited to scan leases."""

import json
import logging
import os
from contextlib import ExitStack
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from dataclasses import replace

import httpx
import psutil

from openaidr.core.skill_bundle import canonical, digest, validate_files
from openaidr_api_client.bridges import skill_intel_adapter
from openaidr_api_client.contracts.errors import APIError
from .skill_references import reference_details
from .skill_reports import validate_report

try:
    from openaidr_api_client.contracts.service_skills import REVISION as SCANNER_REVISION
except ModuleNotFoundError as error:
    if error.name != "openaidr_api_client.contracts.service_skills":
        raise
    from openaidr_api_client.contracts.skills import REVISION as SCANNER_REVISION

SCAN_TIMEOUT = 600
MAX_REPORT_BYTES = 8 << 20


def coverage_diagnostics(coverage, source_files):
    # Keep bounded diagnostics only, never the ledger's content or raw report.
    result = {"reasons": [], "truncated": False}

    def add(code, message, file="", analyzer="", *, line=None, target=None):
        entry = {}
        for key, text, limit in (("code", code, 128), ("message", message, 512),
                                 ("file", file, 2048), ("analyzer", analyzer, 128)):
            if not isinstance(text, str):
                raise ValueError("Invalid coverage diagnostic")
            if len(text) > limit:
                result["truncated"] = True
            entry[key] = text[:limit]
        if type(line) is int and 0 < line <= 10_000_000:
            entry["line"] = line
        if target is not None:
            entry["target"] = target[:2048]
            result["truncated"] |= len(target) > 2048
        if entry in result["reasons"]:
            return
        if len(result["reasons"]) == 50:
            result["truncated"] = True
        else:
            result["reasons"].append(entry)

    references, output_only = reference_details(coverage, source_files)
    for exception in coverage.get("ledger_exceptions", []):
        code = exception.get("reason_code", "")
        matches = references.get((exception.get("path"), exception.get("start_line")), [])
        if code in ("reference_missing", "reference_unresolved") and matches:
            for reference in matches:
                add(**reference, analyzer=", ".join(exception.get("analyzers", [])))
            continue
        add(code, exception.get("message") or code.replace("_", " ") or "Scanner coverage exception.",
            exception.get("path") or "", ", ".join(exception.get("analyzers", [])),
            line=exception.get("start_line"))
    for limitation in coverage.get("limitations", []):
        add("scanner_limitation", limitation)
    return result, add, output_only


def normalize(raw, manifest, mode, *, model="", source_files=None):
    if not isinstance(raw, dict) or type(raw.get("execution_successful")) is not bool:
        raise ValueError("Missing scanner execution status")
    metadata, coverage = raw.get("metadata", {}), raw.get("analysis_completeness", {})
    diagnostics, explain, output_only = coverage_diagnostics(coverage, source_files or {})
    issues = raw.get("issues")
    if not isinstance(issues, list):
        raise ValueError("Missing findings")
    complete = (
        raw["execution_successful"]
        and manifest["complete"]
        and (coverage.get("is_complete") is True or output_only)
        and not metadata.get("llm_error")
        and len(issues) <= 500
    )
    if not raw["execution_successful"]:
        explain("execution_failed", "The scanner did not complete successfully.")
    if not manifest["complete"]:
        explain("collection_incomplete", "Skill file collection was incomplete. See Files for skipped entries.")
    if coverage.get("is_complete") is not True and not diagnostics["reasons"]:
        explain("coverage_unknown", "The scanner did not confirm complete coverage or provide a reason.")
    if metadata.get("llm_error"):
        explain("model_analysis_failed", "Model analysis reported an error.")
    if len(issues) > 500:
        explain("findings_truncated", "Only the first 500 findings were retained.")
    if mode == "llm" and not (
        metadata.get("llm_requested") is True and metadata.get("llm_available") is True
    ):
        complete = False
        explain("model_analysis_unavailable", "The requested model analysis was unavailable.")
    priorities = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if any(
        not isinstance(i, dict) or i.get("severity") not in priorities for i in issues
    ):
        raise ValueError("Invalid finding")
    findings = []
    finding_text_truncated = False
    for issue in sorted(issues, key=lambda i: priorities[i["severity"]])[:500]:
        location = issue.get("location", {})
        item = {"severity": issue["severity"], "line": location.get("start_line") or 0}
        for key, value, limit in (
            ("rule", issue.get("id"), 128),
            ("title", issue.get("finding") or issue.get("pattern"), 512),
            ("description", issue.get("explanation"), 4096),
            ("file", location.get("file"), 2048),
            ("remediation", issue.get("remediation"), 4096),
        ):
            value = value or ""
            if not isinstance(value, str):
                raise ValueError("Invalid finding text")
            if len(value) > limit:
                finding_text_truncated = True
            item[key] = value[:limit]
        findings.append(item)
    result = {
        "complete": complete,
        "mode": mode,
        "score": raw.get("risk_assessment", {}).get("score"),
        "scanner_version": metadata.get("skillspector_version"),
        "issues": findings,
        "coverage": diagnostics,
    }
    if finding_text_truncated:
        result["finding_text_truncated"] = True
    result = validate_report(result)
    if mode == "llm":
        optional = {"model": model}
        # The upstream projection contains billing counters, not prompts or responses.
        # Preserve missing counters as unknown, including on partial scans.
        if "inference_usage" in metadata:
            optional["inference_usage"] = metadata["inference_usage"]
        try:
            return validate_report({**result, **optional})
        except APIError:
            # Optional billing metadata must never discard security findings.
            result["usage_incomplete"] = True
    return result


def memory_directory():
    directory = Path(tempfile.gettempdir()).resolve()
    mounts = [p for p in psutil.disk_partitions(all=True)
              if directory.is_relative_to(p.mountpoint)]
    mount = max(mounts, key=lambda p: len(p.mountpoint), default=None)
    if mount is None or mount.fstype not in ("tmpfs", "ramfs"):
        raise RuntimeError("Skill scanning requires a memory-backed temporary directory")
    return directory


def scan(job, *, binary, mode="static", model_env=None, timeout=SCAN_TIMEOUT, intel=None,
         bridge_factory=None, adapter_script=None, raw_report=None):
    files = validate_files(job["manifest"], job["files"])
    with tempfile.TemporaryDirectory(prefix="openaidr-skill-", dir=memory_directory()) as temporary, ExitStack() as stack:
        work = Path(temporary)
        bundle = work / "skill"
        bundle.mkdir()
        for name, content in files.items():
            target = bundle / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        report = work / "report.json"
        args = [
            binary,
            "scan",
            str(bundle),
            "--format",
            "json",
            "--output",
            str(report),
        ]
        if mode == "static":
            args.append("--no-llm")
        # Never inherit backend credentials, tracing exporters, or CLI-agent auth.
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": temporary,
            "TMPDIR": temporary,
            "LANG": "C.UTF-8",
            "PYTHONUTF8": "1",
        }
        if model_env:
            env.update(model_env)
        if bridge_factory is None:
            from .skill_intel_proxy import provider as bridge_factory

        bridge = stack.enter_context(bridge_factory(intel))
        env.update(bridge.environment)
        args = [str(Path(binary).with_name("python")), "-P",
                adapter_script if adapter_script is not None else skill_intel_adapter.__file__, *args[1:]]
        process = subprocess.Popen(
            args,
            cwd=temporary,
            env=env,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            process.wait(timeout=timeout)
        finally:
            # Also reap subprocesses if a provider or parser leaves one running.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        # The pinned CLI also writes a valid partial report before exit 2 when
        # model execution fails. Retain its static findings and failure ledger.
        if process.returncode not in (0, 1, 2):
            raise RuntimeError("Scanner failed")
        with report.open("rb") as stream:
            data = stream.read(MAX_REPORT_BYTES + 1)
        if len(data) > MAX_REPORT_BYTES:
            raise ValueError("Oversized scanner report")
        raw = json.loads(data)
        if process.returncode == 2:
            raw["execution_successful"] = False
        if raw_report is not None:
            raw_report.update(raw)
        result = normalize(raw, job["manifest"], mode,
                           model=(model_env or {}).get("SKILLSPECTOR_MODEL", ""), source_files=files)
        if bridge is not None and bridge.expires_at is not None:
            result["intel_expires_at"] = bridge.expires_at.isoformat()
        return validate_report(result)


def job_connection(job, intel):
    origin = job.get("intelligence_origin")
    if job.get("intelligence_key") is not None:
        from .intelligence import ORIGINS

        if intel is None or origin not in (*ORIGINS, intel.origin) or intel.ca_file:
            raise ValueError("Scanner Intelligence connection does not match the workspace")
        intel = replace(intel, origin=origin, api_key=job["intelligence_key"])
    if origin and intel is not None and origin != intel.origin:
        from .intelligence import ORIGINS

        if origin not in ORIGINS or intel.origin not in ORIGINS or intel.ca_file:
            raise ValueError("Scanner Intelligence connection does not match the workspace")
        intel = replace(intel, origin=origin)
    return intel


def run_once(client, profile, *, binary, mode="static", model_env=None, intel=None):
    from .config import PLATFORM_AVAILABLE

    if not PLATFORM_AVAILABLE:
        raise ValueError("Legacy skill scanning requires the private platform package")
    from openaidr_api_client.contracts.skills import PROTOCOL

    request = {"profile": profile, "model_protocol": PROTOCOL, "intelligence_credentials": True}
    if mode == "static":
        from openaidr.platform.provider_settings import skill_environment

        request["llm_profile"] = scanner_profile("llm", skill_environment(),
                                                 intel_origin=intel.origin if intel else "") + ":metered-1"
    response = client.post("/internal/v1/skill-scans/claim", json=request)
    response.raise_for_status()
    job = response.json().get("job")
    if job is None:
        return False
    result = {"sha256": job["sha256"], "lease_id": job["lease_id"]}
    try:
        intel = job_connection(job, intel)
        intel_options = {"intel": intel} if intel is not None else {}
        if job.get("llm") or mode == "llm":
            from .skill_llm_proxy import provider

            with provider(client, job) as environment:
                result["report"] = scan(job, binary=binary, mode="llm", model_env=environment, **intel_options)
        else:
            result["report"] = scan(job, binary=binary, mode=mode, model_env=model_env, **intel_options)
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except (ValueError, TypeError, KeyError):
        result["error"] = "invalid_report"
    except Exception:
        result["error"] = "scanner_failed"
    reply = client.post("/internal/v1/skill-scans/complete", json=result)
    reply.raise_for_status()
    return True


def model_environment(mode, client=None):
    if mode not in ("static", "llm"):
        raise ValueError("OPENAIDR_SKILL_SCAN_MODE must be static or llm")
    if mode == "static":
        return {}
    if client is None:
        raise ValueError("LLM scanning requires the tenant worker connection")
    from .config import PLATFORM_AVAILABLE

    if not PLATFORM_AVAILABLE:
        raise ValueError("Legacy skill scanning requires the private platform package")
    from openaidr.platform.provider_settings import model_environment as legacy_environment

    return legacy_environment(mode, client)


def scanner_profile(mode, model_env, *, intel_origin=""):
    settings = {"adapter": 3, "mode": mode, "model": model_env.get("SKILLSPECTOR_MODEL", "")}
    if mode == "static":
        settings.update(intelligence_adapter=1, intelligence_origin=intel_origin)
    if "SKILLSPECTOR_REASONING_EFFORT" in model_env:
        settings["reasoning_effort"] = model_env["SKILLSPECTOR_REASONING_EFFORT"]
    return (
        SCANNER_REVISION
        + ":"
        + digest(canonical(settings))
    )


def main(*, customer=False):
    from .skill_intel_proxy import configuration

    if customer:
        from . import service_skill_worker
        service_skill_worker.contracts()
    logging.basicConfig(level=logging.INFO)
    memory_directory()
    configuration()
    token = Path(os.environ.get("OPENAIDR_SKILL_SCANNER_TOKEN_FILE", "/run/secrets/skill_scanner_token")).read_text().strip()
    mode = os.environ.get("OPENAIDR_SKILL_SCAN_MODE", "static")
    transport = httpx.HTTPTransport(
        uds=os.environ.get("OPENAIDR_SKILL_API_SOCKET", "/run/openaidr/server.sock")
    )
    with httpx.Client(
        transport=transport,
        base_url="http://localhost",
        timeout=60,
        headers={"Authorization": "Bearer " + token},
    ) as client:
        while True:
            try:
                # Refresh shared credentials before claiming a job so rotations
                # and temporarily missing keys do not strand or fail scan leases.
                intel = configuration()
                if customer:
                    service_skill_worker.model_environment(mode, client)
                    profile = service_skill_worker.scanner_profile(mode, intel_origin=intel.origin if intel else "")
                    execute, options = service_skill_worker.run_once, {}
                else:
                    model_env = model_environment(mode, client)
                    profile = scanner_profile(mode, model_env, intel_origin=intel.origin if intel else "")
                    execute, options = run_once, {"model_env": model_env}
                if execute(
                    client,
                    profile,
                    binary=os.environ.get(
                        "OPENAIDR_SKILLSPECTOR_BINARY",
                        "/opt/skillspector/bin/skillspector",
                    ),
                    mode=mode,
                    intel=intel,
                    **options,
                ):
                    continue
            except Exception:
                logging.warning(
                    "Skill scan delivery failed; durable lease will be retried."
                )
            time.sleep(15)


if __name__ == "__main__":
    main(customer=True)
