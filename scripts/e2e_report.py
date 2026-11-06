#!/usr/bin/env python3
"""Render the macOS end-to-end evidence as one flat, self-contained HTML page.

Everything the run produced is visible on the page in reading order: the
verdict, the workflow stages, a table of tests, then each test with its steps,
screenshots, and log attachments inline. A sticky left column links to each
section and test. Nothing is behind a tab or a collapsed section, and the page
stays readable when the run never reached Playwright.
"""

import base64
import html
import json
import os
from pathlib import Path
import re
import shutil
import sys

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
TEXT_LIMIT = 200_000
OUTCOMES = {"expected": "passed", "unexpected": "failed", "flaky": "flaky", "skipped": "skipped"}
STYLE = """
*{box-sizing:border-box}
body{font:14px/1.45 system-ui,-apple-system,sans-serif;color:#1d2433;background:#fff;margin:0}
.layout{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}
nav{position:sticky;top:0;height:100vh;overflow-y:auto;background:#f3f5f8;border-right:1px solid #d9dee6;padding:16px 14px}
nav .title{font-size:15px;font-weight:700;margin:0 0 10px}
nav .verdict{font-size:13px;padding:8px 10px;margin:0 0 14px}
nav ul{list-style:none;margin:0;padding:0}nav li{margin:0}
nav a{display:block;color:#1d2433;text-decoration:none;padding:4px 8px;border-radius:4px;font-size:13px}
nav a:hover{background:#e3e8ef}nav a.sub{padding-left:22px;position:relative}
nav .dot{position:absolute;left:8px;top:11px;width:8px;height:8px;border-radius:50%}
nav .group{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#4a5567;margin:14px 8px 4px}
main{padding:20px 28px 48px;min-width:0}
h1{font-size:22px;margin:0 0 12px}h2{font-size:17px;margin:28px 0 8px;padding-top:14px;border-top:1px solid #d9dee6}
h3{font-size:14px;margin:16px 0 6px}
h2:first-of-type{margin-top:0;padding-top:0;border-top:0}
table{border-collapse:collapse;width:100%;margin:4px 0 10px;font-size:13px}
th,td{text-align:left;vertical-align:top;padding:4px 8px;border:1px solid #d9dee6}th{background:#f3f5f8}
td.k{width:150px;color:#4a5567;white-space:nowrap}
.cols{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:0 24px}
.verdict{font-size:16px;font-weight:600;padding:10px 14px;border-radius:5px;margin:0 0 16px;color:#fff}
.passed{background:#1f7a4d}.failed{background:#b42318}.skipped{background:#5b6472}.flaky{background:#b54708}.incomplete{background:#b54708}
.badge{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.03em;padding:1px 7px;border-radius:3px;color:#fff;margin-right:6px;vertical-align:middle}
.muted{color:#4a5567}.meta{margin:0 0 8px}
pre{white-space:pre-wrap;word-break:break-word;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:#f6f8fa;border:1px solid #d9dee6;border-radius:4px;padding:8px 10px;margin:0 0 10px;max-height:360px;overflow:auto}
pre.error{background:#fff4f2;border-color:#f0b4ac;max-height:none}
.shots{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:12px;margin:0 0 12px}
figure{margin:0;min-width:0}figcaption{font-weight:600;font-size:13px;margin:0 0 4px}
img{display:block;max-width:100%;height:auto;border:1px solid #d9dee6;border-radius:4px}
ol.steps{margin:0 0 10px;padding-left:22px}ol.steps li{margin:1px 0}
@media (max-width:900px){.layout{grid-template-columns:1fr}nav{position:static;height:auto;border-right:0;border-bottom:1px solid #d9dee6}.cols{grid-template-columns:1fr}}
"""


def esc(value):
    return html.escape(str(value), quote=True)


def clean(text):
    return ANSI.sub("", text)


def seconds(milliseconds):
    value = (milliseconds or 0) / 1000
    return f"{value / 60:.1f} min" if value >= 60 else f"{value:.1f} s"


def decode(attachment):
    body = attachment.get("body")
    if body is not None:
        return base64.b64decode(body)
    path = attachment.get("path")
    if path and Path(path).is_file():
        return Path(path).read_bytes()
    return None


def tests_of(suite, parents=()):
    title = suite.get("title")
    # The outermost suite repeats the spec file name, which the test location already shows.
    titles = parents + ((title,) if title and title != Path(suite.get("file") or "").name else ())
    for spec in suite.get("specs", []):
        for test in spec.get("tests", []):
            yield titles, spec, test
    for child in suite.get("suites", []):
        yield from tests_of(child, titles)


def outcome_of(test):
    return OUTCOMES.get(test.get("status"), test.get("status") or "unknown")


def badge(outcome):
    return f'<span class="badge {esc(outcome)}">{esc(outcome.upper())}</span>'


def render_text(name, data):
    text = clean(data.decode("utf-8", errors="replace"))
    note = ""
    if len(text) > TEXT_LIMIT:
        text = text[:TEXT_LIMIT]
        note = f'<p class="muted">Showing the first {TEXT_LIMIT:,} characters. The complete text is in results.json.</p>'
    if not text.strip():
        text = "(empty)"
    return f"<h3>{esc(name)}</h3>{note}<pre>{esc(text)}</pre>"


def render_image(name, data):
    if data is None:
        return f'<figure><figcaption>Screenshot: {esc(name)}</figcaption><p class="muted">The screenshot file was not found.</p></figure>'
    encoded = base64.b64encode(data).decode("ascii")
    return (f'<figure><figcaption>Screenshot: {esc(name)}</figcaption>'
            f'<img alt="{esc(name)}" src="data:image/png;base64,{encoded}"></figure>')


def render_attachment(attachment):
    name = attachment.get("name") or "attachment"
    data = decode(attachment)
    if (attachment.get("contentType") or "").startswith("image/"):
        return render_image(name, data)
    if data is None:
        return f'<h3>{esc(name)}</h3><p class="muted">The attachment file was not found.</p>'
    return render_text(name, data)


def render_result(result, attempt, attempts):
    parts = []
    if attempts > 1:
        parts.append(f"<h3>Attempt {attempt} of {attempts}: {esc(result.get('status'))}</h3>")
    steps = result.get("steps") or []
    if steps:
        parts.append('<p><strong>Steps</strong></p><ol class="steps">')
        for step in steps:
            failed = " (failed)" if step.get("error") else ""
            parts.append(f"<li>{esc(step.get('title'))}{failed} <span class=\"muted\">{seconds(step.get('duration'))}</span></li>")
        parts.append("</ol>")
    for error in result.get("errors") or []:
        message = clean(error.get("message") or error.get("value") or json.dumps(error))
        parts.append(f'<h3>Error</h3><pre class="error">{esc(message)}</pre>')
    shots = []
    for attachment in list(result.get("attachments") or []) + [None]:
        if attachment is not None and (attachment.get("contentType") or "").startswith("image/"):
            shots.append(render_attachment(attachment))
            continue
        if shots:
            parts.append('<div class="shots">' + "".join(shots) + "</div>")
            shots = []
        if attachment is not None:
            parts.append(render_attachment(attachment))
    for stream in ("stdout", "stderr"):
        chunks = [chunk.get("text") or chunk.get("buffer") or "" for chunk in result.get(stream) or []]
        if any(chunk.strip() for chunk in chunks):
            parts.append(render_text(f"Process output ({stream})", "".join(chunks).encode()))
    return "".join(parts)


def render_test(index, titles, spec, test):
    outcome = outcome_of(test)
    results = test.get("results") or []
    duration = sum(result.get("duration") or 0 for result in results)
    location = f"{Path(spec.get('file', '')).name}:{spec.get('line', '')}"
    parts = [f"<h2 id=\"test-{index}\">{badge(outcome)}{index}. {esc(' › '.join(titles + (spec.get('title'),)))}</h2>",
             f'<p class="muted meta">{esc(location)} · {seconds(duration)}</p>']
    reasons = [note.get("description") for note in test.get("annotations") or []
               if note.get("type") == "skip" and note.get("description")]
    if outcome == "skipped":
        parts.append(f"<p>Skipped: {esc('; '.join(reasons) or 'no reason recorded')}</p>")
    for attempt, result in enumerate(results, 1):
        parts.append(render_result(result, attempt, len(results)))
    return "".join(parts)


def build_info(tests):
    for _, _, test in tests:
        for result in test.get("results") or []:
            for attachment in result.get("attachments") or []:
                if attachment.get("name") == "Build and environment":
                    try:
                        return json.loads(decode(attachment).decode("utf-8"))
                    except (ValueError, AttributeError):
                        return {}
    return {}


def summarize(results, stages):
    tests = list(tests_of(results)) if results else []
    counts = {name: 0 for name in ("passed", "failed", "flaky", "skipped")}
    for _, _, test in tests:
        counts[outcome_of(test)] = counts.get(outcome_of(test), 0) + 1
    stage_failed = [name for name, value in stages.items() if value not in ("success", "skipped")]
    if results is None:
        verdict, text = "incomplete", ("End-to-end tests did not complete. No end-to-end pass is claimed. "
                                       "See the failed stage below and the workflow logs.")
    elif counts["failed"] or stage_failed:
        causes = [f"{counts['failed']} failed" if counts["failed"] else "",
                  f"stage {', '.join(stage_failed)} did not succeed" if stage_failed else ""]
        verdict, text = "failed", f"FAILED: {'; '.join(cause for cause in causes if cause)}. {counts['passed']} passed, {counts['skipped']} skipped."
    elif not counts["passed"]:
        verdict, text = "incomplete", "No test ran. No end-to-end pass is claimed."
    else:
        verdict, text = "passed", f"PASSED: {counts['passed']} of {counts['passed'] + counts['failed'] + counts['flaky']} selected tests passed, {counts['skipped']} skipped."
        if counts["flaky"]:
            text += f" {counts['flaky']} flaky."
    return tests, counts, verdict, text


def render_page(results, stages, agents):
    tests, counts, verdict, text = summarize(results, stages)
    info = build_info(tests)
    stats = (results or {}).get("stats") or {}
    metadata = ((results or {}).get("config") or {}).get("metadata") or {}
    commit = (metadata.get("gitCommit") or {}).get("hash") or (metadata.get("ci") or {}).get("commitHash") or ""
    run = [("Started", stats.get("startTime", "not recorded")),
           ("Total time", seconds(stats.get("duration")) if stats else "not recorded"),
           ("Commit", commit or "not recorded"),
           ("Workflow run", (metadata.get("ci") or {}).get("buildHref") or "not recorded"),
           ("Build", (info.get("build") or {}).get("version", "not recorded")),
           ("macOS", (info.get("macOS") or "not recorded").replace("\t", " ").replace("\n", " · ")),
           ("Claude Code", info.get("claude", "not recorded")), ("Codex", info.get("codex", "not recorded")),
           ("Agents selected", agents or info.get("selected") or "not recorded")]
    nav = ['<nav><p class="title">OpenAIDR macOS E2E</p>', f'<div class="verdict {verdict}">{esc(text)}</div>',
           '<ul><li><a href="#run">Run</a></li><li><a href="#stages">Workflow stages</a></li>']
    if results is not None:
        nav.append('<li><a href="#tests">Tests</a></li></ul><p class="group">Each test</p><ul>')
        for index, (titles, spec, test) in enumerate(tests, 1):
            nav.append(f'<li><a class="sub" href="#test-{index}"><span class="dot {esc(outcome_of(test))}"></span>'
                       f'{index}. {esc(spec.get("title"))}</a></li>')
    nav.append("</ul></nav>")
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
             f"<title>OpenAIDR macOS end-to-end report</title><style>{STYLE}</style></head><body><div class=\"layout\">",
             "".join(nav), "<main><h1>OpenAIDR macOS end-to-end report</h1>",
             f'<div class="verdict {verdict}">{esc(text)}</div><div class="cols"><div>',
             '<h2 id="run">Run</h2><table>' + "".join(f'<tr><td class="k">{esc(k)}</td><td>{esc(v)}</td></tr>' for k, v in run) + "</table></div><div>",
             '<h2 id="stages">Workflow stages</h2><table><tr><th>Stage</th><th>Outcome</th></tr>'
             + "".join(f"<tr><td>{esc(name)}</td><td>{esc(value)}</td></tr>" for name, value in stages.items()) + "</table></div></div>"]
    if results is None:
        parts.append("<p>The test reporter did not finish, so there are no test results or screenshots. "
                     "Screenshots may be unavailable if setup failed.</p>")
    else:
        parts.append('<h2 id="tests">Tests</h2><table><tr><th>#</th><th>Test</th><th>Result</th><th>Duration</th></tr>')
        for index, (titles, spec, test) in enumerate(tests, 1):
            duration = sum(result.get("duration") or 0 for result in test.get("results") or [])
            parts.append(f"<tr><td>{index}</td><td>{esc(' › '.join(titles + (spec.get('title'),)))}</td>"
                         f"<td>{badge(outcome_of(test))}</td><td>{seconds(duration)}</td></tr>")
        parts.append("</table>")
        for index, (titles, spec, test) in enumerate(tests, 1):
            parts.append(render_test(index, titles, spec, test))
    parts.append("</main></div></body></html>")
    return "".join(parts), verdict, text, tests, counts


def finalize(directory, stages, results_path=None, agents=None):
    """Write report/index.html, workflow-stages.json, and the GitHub step summary."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "workflow-stages.json").write_text(json.dumps(stages, indent=2))
    results = None
    if results_path and Path(results_path).is_file():
        results = json.loads(Path(results_path).read_text())
        for name in ("results.json", "junit.xml"):
            source = Path(results_path).parent / name
            if source.is_file() and source.resolve() != (directory / name).resolve():
                shutil.copyfile(source, directory / name)
    page, verdict, text, tests, _ = render_page(results, stages, agents)
    (directory / "index.html").write_text(page)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as stream:
            stream.write(f"## macOS end-to-end results\n\n**{text}**\n\n")
            stream.write("Download the **macos-e2e-report** artifact and open `index.html` for screenshots and logs.\n\n")
            stream.write("| Stage | Outcome |\n| --- | --- |\n")
            for name, result in stages.items():
                stream.write(f"| {name} | {result} |\n")
            if tests:
                stream.write("\n| Test | Result |\n| --- | --- |\n")
                for titles, spec, test in tests:
                    stream.write(f"| {' › '.join(titles + (spec.get('title'),))} | {outcome_of(test)} |\n")
    return verdict


if __name__ == "__main__":
    output = Path(sys.argv[1])
    finalize(output / "report", json.loads(os.environ["E2E_STAGE_RESULTS"]), output / "results.json",
             os.environ.get("E2E_AGENTS"))
