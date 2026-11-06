"""Failures and credentials must survive the report boundary correctly."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def invoke(tmp_path, program, **options):
    config = {"argv": [sys.executable, "-c", program], "prompt": "Run the fixture",
              "cwd": str(tmp_path), "output": str(tmp_path / "evidence"), "env": {}, **options}
    invocation = tmp_path / "private.json"
    invocation.write_text(json.dumps(config))
    result = subprocess.run([sys.executable, ROOT / "scripts/e2e_agent.py", invocation],
                            capture_output=True, text=True, timeout=10)
    assert not invocation.exists()
    return result, json.loads((tmp_path / "evidence/result.json").read_text())


def test_real_process_output_is_redacted_before_terminal_and_report(tmp_path):
    secret = "test-private-credential-123456789"
    result, status = invoke(tmp_path,
        "import os,json; print(json.dumps({'type':'result','result':os.environ['TEST_API_KEY']}))",
        env={"TEST_API_KEY": secret, "PATH": "/usr/bin:/bin"})
    assert result.returncode == status["returncode"] == 0
    transcript = (tmp_path / "evidence/agent.jsonl").read_text()
    assert secret not in result.stdout + transcript
    assert "[REDACTED]" in result.stdout and "[REDACTED]" in transcript
    assert json.loads(transcript)["type"] == "result"


def test_agent_failure_is_not_reported_as_success(tmp_path):
    result, status = invoke(tmp_path, "import sys; print('authentication failed',file=sys.stderr); sys.exit(7)")
    assert result.returncode == status["returncode"] == 7
    assert not status["timed_out"]
    assert "authentication failed" in (tmp_path / "evidence/agent.jsonl").read_text()


def test_agent_timeout_kills_descendants_holding_output_open(tmp_path):
    result, status = invoke(tmp_path,
        "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])",
        timeout=0.2)
    assert status["timed_out"]
    assert result.returncode == status["returncode"] == 124
    assert status["duration_seconds"] < 5
    # A completed parent is still a timeout when its descendant holds stdout.
    assert "Agent finished" in result.stdout


def test_missing_agent_has_immediate_failure_evidence(tmp_path):
    result, status = invoke(tmp_path, "", argv=[str(tmp_path / "missing-agent")])
    assert result.returncode == status["returncode"] == 127
    assert status["error"]


def test_setup_failure_report_is_explicit_and_escapes_stage_text(tmp_path):
    module("e2e_report").finalize(tmp_path, {"build": "failure", "tests": "skipped", "<script>": "<bad>"})
    report = (tmp_path / "index.html").read_text()
    assert "No end-to-end pass is claimed" in report
    assert "failure" in report and "skipped" in report
    assert "<script>" not in report and "&lt;script&gt;" in report


def results_fixture(tmp_path, status="passed", expected="passed"):
    """A Playwright JSON report with screenshot files, text bodies, a skip, and a stderr line."""
    import base64
    shot = tmp_path / "results" / "shot.png"
    shot.parent.mkdir(parents=True, exist_ok=True)
    shot.write_bytes(b"\x89PNG fake image bytes")
    body = lambda text: base64.b64encode(text.encode()).decode()
    outcome = "expected" if status == expected else "unexpected"
    results = {
        "config": {"metadata": {"gitCommit": {"hash": "abc123def"}, "ci": {"buildHref": "https://example.test/run/1"}}},
        "stats": {"startTime": "2026-10-21T07:32:46.359Z", "duration": 108143, "expected": 1, "skipped": 1, "unexpected": 0},
        "suites": [{"title": "macos.spec.ts", "file": "macos.spec.ts", "suites": [{"title": "macOS installed application", "file": "macos.spec.ts", "specs": [
            {"title": "Install and connect", "file": "macos.spec.ts", "line": 171, "tests": [
                {"status": outcome, "expectedStatus": expected, "annotations": [], "results": [{
                    "status": status, "duration": 32900,
                    "steps": [{"title": "Start the backend", "duration": 2877}],
                    "errors": [{"message": "Expected <b>Connected</b>\x1b[31m failed\x1b[0m"}] if status != "passed" else [],
                    "attachments": [
                        {"name": "app-connected (2026-10-21T07:33:18.502Z)", "contentType": "image/png", "path": str(shot)},
                        {"name": "Build and environment", "contentType": "text/plain",
                         "body": body('{"build": {"version": "2026.10.21+abc123d"}, "macOS": "ProductVersion:\\t15.7", "claude": "2.1", "codex": "0.1", "selected": "claude"}')},
                        {"name": "dashboard.log", "contentType": "text/plain", "body": body("\x1b[32m\u2713\x1b[0m Ready <script>alert(1)</script>")},
                        {"name": "missing-shot", "contentType": "image/png", "path": str(tmp_path / "results" / "gone.png")},
                    ],
                    "stdout": [], "stderr": [{"text": "No visible window for Terminal\n"}]}]}]},
            {"title": "codex: enforced command is blocked", "file": "macos.spec.ts", "line": 253, "tests": [
                {"status": "skipped", "expectedStatus": "skipped", "results": [{"status": "skipped", "duration": 0}],
                 "annotations": [{"type": "skip", "description": "codex was not selected for this run"}]}]}]}]}]}
    (tmp_path / "results.json").write_text(json.dumps(results))
    (tmp_path / "junit.xml").write_text("<testsuites/>")
    return tmp_path / "results.json"


def test_report_is_one_flat_page_with_evidence_inline(tmp_path, monkeypatch):
    import base64
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    stages = {"credentials": "success", "dependencies": "success", "checks": "success", "build": "success", "tests": "success"}
    verdict = module("e2e_report").finalize(tmp_path / "report", stages, results_fixture(tmp_path), "claude")
    report = (tmp_path / "report" / "index.html").read_text()
    assert verdict == "passed" and "PASSED: 1 of 1 selected tests passed, 1 skipped." in report
    # Only in-page navigation: no external links, no collapsed sections, no scripts, every image embedded.
    import re
    links = re.findall(r'<a [^>]*href="([^"]*)"', report)
    assert links and all(link.startswith("#") for link in links)
    assert '<a class="sub" href="#test-1">' in report and 'id="test-1"' in report
    assert "<details" not in report and "<script" not in report
    assert "data:image/png;base64," + base64.b64encode(b"\x89PNG fake image bytes").decode() in report
    assert "The screenshot file was not found." in report
    # Text evidence is inline, cleaned of terminal colors, and escaped.
    assert "\x1b[" not in report and "&lt;script&gt;alert(1)&lt;/script&gt;" in report and "alert(1)</script>" not in report
    assert "Start the backend" in report and "No visible window for Terminal" in report
    assert "Skipped: codex was not selected for this run" in report
    for value in ("2026.10.21+abc123d", "abc123def", "https://example.test/run/1", "ProductVersion: 15.7", "claude"):
        assert value in report
    assert (tmp_path / "report" / "results.json").exists() and (tmp_path / "report" / "junit.xml").exists()
    assert json.loads((tmp_path / "report" / "workflow-stages.json").read_text()) == stages
    text = summary.read_text()
    assert "PASSED: 1 of 1" in text and "| macOS installed application › Install and connect | passed |" in text
    assert "macos.spec.ts › macOS" not in report


def test_failed_test_and_failed_stage_are_never_reported_as_a_pass(tmp_path):
    e2e_report = module("e2e_report")
    stages = {"build": "success", "tests": "failure"}
    verdict = e2e_report.finalize(tmp_path / "report", stages, results_fixture(tmp_path, status="failed"))
    report = (tmp_path / "report" / "index.html").read_text()
    assert verdict == "failed" and "FAILED: 1 failed; stage tests did not succeed" in report
    assert "Expected &lt;b&gt;Connected&lt;/b&gt; failed" in report and "\x1b[" not in report
    # Passing tests do not outweigh a failed workflow stage such as teardown.
    verdict = e2e_report.finalize(tmp_path / "report", {"tests": "failure"}, results_fixture(tmp_path))
    assert verdict == "failed" and "FAILED: stage tests did not succeed. 1 passed" in (tmp_path / "report" / "index.html").read_text()
