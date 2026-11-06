// Production dashboard flows with synthetic API state and retained evidence.
import { createHash } from "node:crypto";
import { test, expect, type Page } from "@playwright/test";
import { expectPublicNames } from "./public-names";
import { mockClipboard } from "./fixtures/clipboard";
import type {
  ApprovalGeneration, GuardrailAction, InlineDecision, Investigation,
  RetainedRead, SessionSummary, SnapshotItem, SnapshotPage,
} from "../src/lib/session";

const id = (value: number) => `a0b0c0d0-e0f0-4a0b-8c0d-${String(value).padStart(12, "0")}`;
const SESSION = id(1), REGISTRATION = id(2), SNAPSHOT = id(3), JOB = id(4);
const ATTEMPT = id(5), READ = id(6), ACTION = id(7), FINDING = id(8);
const TIME = "2026-10-02T10:00:00Z";
const RUNTIME = { version: "0.160.0", executable_sha256: "a".repeat(64), platform: "darwin-arm64", protocol_version: 1, prompt_version: 1 };
const NONCE = "retained-only-<img src=x onerror=alert(1)>-tail";
const USER = {
  id: id(90), name: "Tenant viewer", email: "viewer@example.test", roles: ["security_analyst"],
  tenant: { id: id(91), name: "Example tenant", slug: "example" },
};
const REPORT_PINNED = `/detections/reports/${JOB}?attempt=${ATTEMPT}&snapshot=${SNAPSHOT}`;
const PINNED = `/sessions/${SESSION}?investigation=${JOB}&attempt=${ATTEMPT}&snapshot=${SNAPSHOT}&finding=0#investigation`;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function fixture() {
  const counts = {
    logical_targets: 3, assessed: 2, unavailable: 0, pending: 0,
    missing_assessments: 1, invalid_assessments: 0, blocked: 0,
    pending_approvals: 0, approved_unconsumed: 0, unreported_outcomes: 1,
    uncertain_outcomes: 1,
  };
  const coverage = {
    status: "incomplete", scope: "captured_records",
    content: { status: "incomplete", reasons: ["unsupported_boundary"] },
    delivery: { status: "complete", reasons: [] },
    assessment: { status: "incomplete", reasons: ["missing_assessment"] },
    execution: { status: "incomplete", reasons: ["uncertain_outcome"] },
    gaps: ["unsupported_boundary", "missing_assessment", "uncertain_outcome"],
  };
  const decision: InlineDecision = {
    id: id(10), request_id: id(11), settings_version: 4, policy_version: 6,
    decision: { action: "ask", reason: "Stored risk threshold", warnings: [] },
    requested_policy_floor: null, approval_id: id(12), created_at: TIME, completed_at: TIME,
  };
  const approval: ApprovalGeneration = {
    id: id(12), originating_check_id: id(10), generation: 2,
    settings_version: 4, policy_version: 6, status: "approved", created_at: TIME,
    expires_at: "2026-10-02T10:10:00Z", decision: "approve", decided_at: TIME,
    decided_by_user_id: id(13), approved_until: "2026-10-02T10:05:00Z",
    revoked_at: null, reason_code: null,
  };
  const target = {
    id: id(14), time: TIME, kind: "command", command: { text: "git status", cwd: "/workspace" },
    agent: { product: "codex-cli" }, host: { hostname: "workstation", user: "reported-os-user" },
    session: { id: "native-session", registration_id: REGISTRATION },
    tool: { name: "exec_command", call_id: "native-call-1" },
    evidence: { version: 1, logical_id: "logical-ask", observation_id: "observation-1", stream_id: "stream-1", sequence: 1, part: 0, gaps: [] },
  };
  const asked: GuardrailAction = {
    id: ACTION, action_id: ACTION, event_id: target.id, logical_id: "logical-ask", created_at: TIME,
    origin: "inline_assessment", target_body: target,
    captured_context: { prior_events: [], latest_prompt: null, matched_tool_call: null, gaps: [] },
    assessment: { status: "scored", model: "systemone", rubric_version: 1,
      value: { status: "scored", score: 50 }, started_at: TIME, completed_at: TIME },
    latest_decision: decision, decision_count: 3, approval_count: 2, latest_approval: approval,
    release: { id: id(15), check_id: decision.id, approval_id: approval.id, consumed_at: TIME,
      outcome: "uncertain", outcome_at: TIME, outcome_details: { outcome: "uncertain" }, outcome_audit_id: id(16) },
    reported_outcome: { id: id(17), sequence: 2, payload: { release_id: id(15), outcome_audit_id: id(16) },
      captured_body: { outcome: "uncertain" }, received_at: TIME },
  };
  const actions: GuardrailAction[] = [asked, {
    ...asked, id: id(18), action_id: id(18), event_id: id(19), logical_id: "logical-zero",
    target_body: { ...target, id: id(19), command: { text: "pwd" } },
    assessment: { ...asked.assessment, value: { status: "scored", score: 0 } },
    latest_decision: { ...decision, id: id(20), approval_id: null, decision: { action: "allow", reason: "Below threshold", warnings: [] } },
    decision_count: 1, approval_count: 0, latest_approval: null,
    release: { ...asked.release!, id: id(21), approval_id: null, outcome: "succeeded" },
    reported_outcome: null,
  }, {
    ...asked, id: id(22), action_id: null, event_id: id(23), logical_id: "logical-outage",
    origin: "delivery_receipt", target_body: { ...target, id: id(23), command: { text: "echo outage" } },
    captured_context: null,
    assessment: { status: "missing", model: null, rubric_version: null, value: null, started_at: null, completed_at: null },
    latest_decision: null, decision_count: 0, approval_count: 0, latest_approval: null,
    release: null, reported_outcome: { id: id(38), sequence: 7,
      payload: { event_id: id(39), logical_id: "logical-outage" },
      captured_body: { logical_id: "logical-outage", outcome: "succeeded", reason: "backend_unavailable" }, received_at: TIME },
  }];
  const summary: SessionSummary = {
    eligibility: { status: "excluded", reason: "sensor_unavailable", evaluated_at: TIME, next_evaluation_at: null,
      owner: null, history_available: false, job_id: JOB, job_state: "completed" },
    session: {
      id: SESSION, agent_id: id(24), sensor_id: id(25), external_id: "native-session", product: "codex-cli",
      cwd: "/workspace", git_branch: "example", started_at: TIME, last_event_at: TIME, ended_at: TIME,
      events_total: 7, tool_calls: 3, commands: 3, client: { product: "codex-cli", version: "0.160.0" },
      device: { hostname: "workstation", os: "macos", arch: "arm64", reported_user: "reported-os-user",
        sensor_label: "Development device", sensor_disabled: true, sensor_deleted_at: null },
    },
    registration: { id: REGISTRATION, assessment_mode: "inline", verified_at: TIME, delivery_protocol: 1,
      delivery_epoch: id(26), owner: { id: id(13), name: "Verified owner", email: "owner@example.test", status: "disabled" }, owner_available: false },
    projection: { available: true, updated_at: TIME, input_version: 8, revision: 2, snapshot_id: SNAPSHOT,
      snapshot_current: false, dirty: true, evaluation_due: false, settings_changed: true, finalization_error: null },
    detection: {
      lifecycle: "incomplete", risk_total: "50", risk_max: "50", counts, coverage,
      last_sequence: 7, closing_sequence: 7, closing_at: TIME, last_activity_at: TIME,
      next_evaluation_at: null, delivery: { received: 7, expected: 7, complete: true, gaps: [] },
      routing: { status: "completed", reason: "persistent_gap", job_id: JOB, settings_version: 4, detector_config_version: 2 },
    },
    investigations: { items: [{ id: JOB, snapshot_id: SNAPSHOT, revision: 2, state: "completed",
      settings_version: 4, detector_config_version: 2, routing_reason: "persistent_gap", created_at: TIME,
      completed_at: TIME, snapshot_current: false, configuration_current: false }], next_cursor: "" },
  };
  const items: SnapshotItem[] = [
    { ordinal: 1, kind: "observation", source_id: id(14), body: target },
    { ordinal: 2, kind: "observation", source_id: id(27), body: { id: id(27), time: TIME, kind: "response", text: NONCE,
      tenant_id: id(91), session: { id: "native-session", registration_id: REGISTRATION } } },
    { ordinal: 3, kind: "assessment", source_id: ACTION, body: { status: "scored", score: 50, target_body: target } },
  ];
  const snapshot: SnapshotPage = {
    snapshot: { id: SNAPSHOT, sensor_id: id(25), registration_id: REGISTRATION, owner_user_id: id(13),
      revision: 2, input_version: 8, epoch_id: id(26), closing_sequence: 7, lifecycle: "incomplete",
      coverage, counts, risk_total: "50", risk_max: "50", item_count: items.length, sealed_at: TIME, created_at: TIME },
    items, next_cursor: "", pagination: { scope: "immutable", order: "ordinal_asc", byte_limit: 1 << 20 },
  };
  const retainedResponse = {
    read_id: READ, session_id: id(28), version: { kind: "live", observed_at: TIME, last_event_id: id(29) },
    items: [{ ordinal: 1, source_id: id(29), start: 0, end: Buffer.byteLength(NONCE), total_bytes: Buffer.byteLength(NONCE), text: NONCE }],
    next_cursor: "", tenant_id: id(91),
  };
  const retained: RetainedRead = {
    id: READ, job_id: JOB, attempt_id: ATTEMPT, step_id: id(30), tool_name: "read_session", status: "delivered",
    created_at: TIME, session_id: id(28), source_registration_id: id(31), source_sensor_id: id(32),
    source_snapshot_id: null, response_sha256: createHash("sha256").update(canonical(retainedResponse)).digest("hex"),
    response: retainedResponse,
  };
  const report: Investigation = {
    id: JOB, job_id: JOB, session_id: SESSION, registration_id: REGISTRATION, snapshot_id: SNAPSHOT,
    snapshot_revision: 2, state: "completed", settings_version: 4, detector_config_version: 2,
    configuration: { model: "gpt-6.1-sol", max_tokens_per_attempt: 200000, max_cost_usd_per_attempt: "10" },
    routing_reason: "persistent_gap", created_at: TIME, completed_at: TIME,
    snapshot_current: false, configuration_current: false, report_attempt_id: ATTEMPT,
    report: { status: "finding", summary: "Retained investigation summary", gaps: ["unsupported_boundary"],
      findings: [{ title: "Captured session finding", explanation: NONCE, category: "excessive_agency", severity: "high",
        evidence: [{ source: "target", ordinal: 2, start: 0, end: 100 }, { source: "history", read_id: READ, item: 0 }],
        action_outcomes: [{ logical_id: "logical-ask", execution: "uncertain", authorization: "approved" }] }],
      coverage: { status: "complete", target_item_count: 3, target_byte_count: 1000, target_chunk_count: 1,
        completed_chunks: 1, completed_steps: 1, inconclusive_steps: 0, gaps: [] },
      source_coverage: coverage, snapshot_id: SNAPSHOT, model: "gpt-6.1-sol", runtime: RUNTIME,
      usage: { actual_tokens: 1020, actual_cost_usd: "0.00154" } },
    attempts: [{ id: ATTEMPT, ordinal: 1, state: "completed", created_at: TIME, dispatched_at: TIME,
      completed_at: TIME, reserved_tokens: 200000, reserved_cost_usd: "10", actual_tokens: 1020,
      actual_cost_usd: "0.00154", runtime: RUNTIME, target_item_count: 3, target_byte_count: 1000, target_chunk_count: 1 }],
    attempt_count: 1, attempts_truncated: false,
    usage: [{ request_id: id(33), attempt_id: ATTEMPT, purpose: "detection", provider: "openai", model: "gpt-6.1-sol",
      reported_model: "gpt-6.1-sol", service_tier: "default", status: "completed", started_at: TIME, completed_at: TIME,
      input_tokens: 1000, output_tokens: 20, cached_input_tokens: 400, cache_write_input_tokens: 200,
      reasoning_output_tokens: 10, cost_usd: "0.00154", price_quote: {} },
    { request_id: id(34), attempt_id: ATTEMPT, purpose: "detection", provider: "openai", model: "gpt-6.1-sol",
      reported_model: "gpt-6.1-sol", service_tier: "default", status: "completed", started_at: TIME, completed_at: TIME,
      input_tokens: 0, output_tokens: 0, cached_input_tokens: 0, cache_write_input_tokens: 0,
      reasoning_output_tokens: 0, cost_usd: "0", price_quote: {} }],
    usage_count: 2, usage_truncated: false,
    reads: [{ id: READ, step_id: id(30), tool_name: "read_session", status: "delivered", session_id: id(28),
      source_snapshot_id: null, response_sha256: retained.response_sha256, created_at: TIME }],
    read_count: 1, reads_truncated: false,
  };
  const finding = {
    id: FINDING, title: "Captured session finding", summary: "The retained report remains available after event retention.",
    severity: "high", status: "open", rule_name: "Session investigation", category: "excessive_agency",
    product: "codex-cli", created_at: TIME, host: { hostname: "workstation", user: "reported-os-user" },
    account: "", event_ids: [id(14)], assignee: null, resolution: "", session_id: SESSION,
    investigation_job_id: JOB, investigation_attempt_id: ATTEMPT, snapshot_id: SNAPSHOT, finding_index: 0,
    investigation_evidence: { evidence: report.report!.findings[0].evidence },
  };
  const policy = { ...finding, id: id(81), title: "Blocked: synthetic policy action", rule_name: "Action blocked by policy",
    investigation_job_id: null, investigation_attempt_id: null, snapshot_id: null, finding_index: null, investigation_evidence: null };
  const reports = [{ id: JOB, job_id: JOB, session_id: SESSION, snapshot_id: SNAPSHOT, report_attempt_id: ATTEMPT,
    state: "completed", created_at: TIME, completed_at: TIME, title: "Retained investigation report", summary: report.report!.summary,
    outcome: "actionable_findings", verdict: "true_positive" as string | null, severity: "high", confidence: "medium",
    subject: { name: "Verified owner", email: "owner@example.test", reported_user: "reported-os-user", hostname: "workstation", ownership_verified: true },
    snapshot_current: false, configuration_current: false }];
  return { summary, actions, decision, approval, snapshot, retained, report, finding, policy, reports };
}

type Fixture = ReturnType<typeof fixture>;
type Controls = {
  userRoles?: string[];
  summaryGate?: Promise<void>; summaryFailure?: boolean; snapshotFailure?: boolean;
  missingPinnedAttempt?: boolean;
  incidentEmpty?: boolean; incidentFailure?: boolean;
  decisionsGate?: Promise<void>; approvalsFailure?: boolean;
};

async function mockArchive(page: Page, data: Fixture, controls: Controls = {}) {
  const mutations: string[] = [], ownerRequests: string[] = [], reads: URL[] = [];
  let ownerState: "unassigned" | "verified" | "revoked" = "unassigned";
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.replace("/api/v1/", "");
    reads.push(url);
    if (request.method() !== "GET" && path !== "audit/page-views") mutations.push(`${request.method()} ${path}`);
    if (path.startsWith("me/") || path.includes("guardrail-checks") || path.includes("guardrail-releases")) ownerRequests.push(path);
    if (path === "auth/me") return route.fulfill({ json: { user: { ...USER, roles: controls.userRoles ?? USER.roles } } });
    if (path === "users/detection-owners") return route.fulfill({ json: { items: [
      { id: id(13), name: "Verified owner", email: "owner@example.test", status: "active" },
    ] } });
    if (path === `sessions/${SESSION}/detection-owner`) {
      if (request.method() === "PUT") {
        expect(request.postDataJSON()).toEqual({ owner_user_id: ownerState === "unassigned" ? id(13) : null });
        ownerState = ownerState === "unassigned" ? "verified" : "revoked";
      }
      return route.fulfill({ json: { session_id: SESSION, status: ownerState, assignable: ownerState === "unassigned",
        revoked_at: ownerState === "revoked" ? TIME : null,
        owner: ownerState === "verified" ? { owner_user_id: id(13), verified_at: TIME, name: "Verified owner", email: "owner@example.test" } : null } });
    }
    if (path === "detections/rankings") return route.fulfill({ json: {
      group: url.searchParams.get("group") || "sessions", band: "all", selection_policy: "legacy", items: [], next_cursor: "",
    } });
    if (path === "detections/pipeline") return route.fulfill({ json: {
      range: url.searchParams.get("range") || "30d", since: "2026-09-02T10:00:00Z", until: TIME,
      actions_scored: 742, sessions_scored: 112, sessions_inspected: 2, sessions_with_alerts: 1,
      alerts: 1, sessions_eligible: 100, sessions_escalated: 1,
    } });
    if (path === `sessions/${SESSION}/detection`) {
      if (controls.summaryGate) await controls.summaryGate;
      if (controls.summaryFailure) return route.fulfill({ status: 503, json: { error: { code: "unavailable", message: "Archive temporarily unavailable" } } });
      return route.fulfill({ json: data.summary });
    }
    if (path === `sessions/${SESSION}/guardrail-actions`) {
      const view = url.searchParams.get("view") ?? "actions";
      const cursor = url.searchParams.get("cursor");
      if (view === "decisions" && controls.decisionsGate) await controls.decisionsGate;
      if (view === "approvals" && controls.approvalsFailure) return route.fulfill({ status: 503, json: { error: { message: "Approval history temporarily unavailable" } } });
      if (view !== "actions" && url.searchParams.get("action_id") === id(18)) return route.fulfill({ json: {
        items: view === "decisions" ? [data.actions[1].latest_decision] : [], next_cursor: "",
      } });
      if (view === "decisions") return route.fulfill({ json: {
        items: cursor ? [{ ...data.decision, id: id(35), request_id: id(36), policy_version: 5 }] : [data.decision],
        next_cursor: cursor ? "" : "opaque-decisions-page-2",
      } });
      if (view === "approvals") return route.fulfill({ json: {
        items: cursor ? [{ ...data.approval, id: id(37), generation: 1, status: "expired", decision: null, decided_at: null, approved_until: null }] : [data.approval],
        next_cursor: cursor ? "" : "opaque-approvals-page-2",
      } });
      return route.fulfill({ json: { items: data.actions, next_cursor: "", pagination: { scope: "live", order: "created_at_desc", byte_limit: 1 << 20 } } });
    }
    if (path === `session-snapshots/${SNAPSHOT}`) {
      if (controls.snapshotFailure) return route.fulfill({ status: 503, json: { error: { code: "unavailable", message: "Snapshot temporarily unavailable" } } });
      const cursor = url.searchParams.get("cursor");
      expect(cursor === null || cursor === "opaque-snapshot-page-2").toBe(true);
      return route.fulfill({ json: { ...data.snapshot,
        items: cursor ? data.snapshot.items.slice(1) : data.snapshot.items.slice(0, 1),
        next_cursor: cursor ? "" : "opaque-snapshot-page-2" } });
    }
    if (path === "session-investigations") {
      if (controls.incidentFailure) return route.fulfill({ status: 503, json: { error: { message: "Investigation reports temporarily unavailable" } } });
      const outcome = url.searchParams.get("outcome");
      return route.fulfill({ json: { items: controls.incidentEmpty ? [] : data.reports.filter((item) => !outcome || outcome === "all" || item.outcome === outcome || item.verdict === outcome), next_cursor: "" } });
    }
    if (path === `session-investigations/${JOB}`) {
      if (controls.missingPinnedAttempt && url.searchParams.has("attempt_id")) return route.fulfill({ status: 404, json: { error: { message: "Retained investigation is unavailable" } } });
      return route.fulfill({ json: data.report });
    }
    if (path === `session-investigation-reads/${READ}`) return route.fulfill({ json: data.retained });
    if (path === "findings") {
      const policy = url.searchParams.get("source") === "policy";
      if (!policy && controls.incidentFailure) return route.fulfill({ status: 503, json: { error: { message: "Incident reports temporarily unavailable" } } });
      return route.fulfill({ json: { items: policy ? [data.policy] : controls.incidentEmpty ? [] : [data.finding], next_cursor: "" } });
    }
    if (path === `findings/${data.policy.id}`) return route.fulfill({ json: { finding: data.policy, events: [], notes: [], actions: [] } });
    if (path === `findings/${FINDING}`) return route.fulfill({ json: { finding: data.finding, events: [], notes: [], actions: [] } });
    if (path === `sessions/${SESSION}`) return route.fulfill({ json: data.summary.session });
    if (path.includes("/events") || path.includes("/evidence")) return route.fulfill({ status: 404, json: { error: { message: "Live evidence was removed by retention" } } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  return { mutations, ownerRequests, reads };
}

async function readOnly(page: Page, trace: Awaited<ReturnType<typeof mockArchive>>) {
  expect(trace.mutations).toEqual([]);
  expect(trace.ownerRequests).toEqual([]);
  await expect(page.getByRole("button", { name: /^(Approve once|Reject|Revoke approval|Consume|Retry investigation)$/ })).toHaveCount(0);
}

test("an incident opens its exact retained investigation and separates recorded action states", async ({ page }, info) => {
  const data = fixture(), trace = await mockArchive(page, data);
  await page.goto("/user-risk/findings?source=incident");
  await page.getByRole("button", { name: data.finding.title, exact: true }).click();
  const detail = page.getByRole("dialog", { name: "Finding details" });
  const link = detail.getByRole("link", { name: "View retained session investigation" });
  await expect(link).toHaveAttribute("href", PINNED);
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/sessions/${SESSION}\\?investigation=${JOB}&attempt=${ATTEMPT}&snapshot=${SNAPSHOT}&finding=0#investigation$`));
  await expect(page.getByRole("heading", { level: 1, name: "Session", exact: true })).toBeVisible();
  const overview = page.getByRole("region", { name: "Session overview" });
  await expect(overview.getByRole("region", { name: "Detection eligibility" })).toContainText("The session's sensor is disabled or deleted.");
  await expect(overview.getByText("reported-os-user", { exact: true })).toBeVisible();
  await expect(overview.getByText("owner@example.test", { exact: true })).toBeVisible();
  await expect(overview.getByText("Managed lifecycle: incomplete", { exact: true })).toBeVisible();
  await expect(overview.getByText("Pending approvals", { exact: true })).toBeVisible();
  await expect(overview.locator("dt", { hasText: /^Stored risk total$/ }).locator("+ dd")).toHaveText("50");
  await expect(overview.locator("dt", { hasText: /^Logical targets$/ }).locator("+ dd")).toHaveText("3");
  await expect(page.getByRole("table", { name: "Session coverage" })).toContainText("incomplete");
  await expect(page.getByText("Snapshot is stale", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Investigation configuration is stale", { exact: true }).first()).toBeVisible();

  const section = page.getByRole("region", { name: "Guardrail actions" });
  const expand = section.getByRole("button", { name: "Expand action logical-ask" });
  await expand.focus();
  await page.keyboard.press("Enter");
  const asked = section.locator("li").filter({ has: page.getByRole("button", { name: "Collapse action logical-ask" }) });
  const state = asked.locator('dl[aria-label="Action state"]');
  await expect(state.getByText("ask", { exact: true })).toBeVisible();
  await expect(state.getByText("approved", { exact: true })).toBeVisible();
  await expect(asked.getByText("uncertain", { exact: true }).first()).toBeVisible();
  await expect(asked.getByRole("tablist")).toHaveCount(0);
  await expect(asked.getByRole("region", { name: "Action target", exact: true })).toHaveText("git status");
  const decisions = asked.getByRole("region", { name: "Decision history (3)", exact: true });
  const approvals = asked.getByRole("region", { name: "Approval history (2)", exact: true });
  await expect(decisions.getByRole("table")).toContainText("6 / 4");
  await expect(approvals.getByRole("table")).toContainText("approved");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    await asked.scrollIntoViewIfNeeded();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    // Capture the complete action below the sticky page header.
    await page.setViewportSize({ width, height: Math.max(1080, Math.ceil((await asked.boundingBox())!.height) + 160) });
    await asked.evaluate((element) => { element.scrollIntoView({ block: "start" }); window.scrollBy(0, -80); });
    await asked.screenshot({ path: info.outputPath(`session-action-${width}.png`) });
    await page.setViewportSize({ width, height: 1080 });
  }
  await decisions.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(decisions.getByRole("table")).toContainText("5 / 4");
  await expect(approvals.getByRole("table")).not.toContainText("expired");
  await approvals.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(approvals.getByRole("table")).toContainText("expired");
  await expect(decisions.getByRole("table")).toContainText("5 / 4");
  await page.setViewportSize({ width: 1440, height: 1080 });
  await expect(section.getByRole("button", { name: "Expand action logical-zero" })).toContainText("Risk 0");
  await expect(section.getByRole("button", { name: "Expand action logical-outage" })).toContainText("Risk Unavailable");
  await section.getByRole("button", { name: "Expand action logical-outage" }).click();
  const outage = section.locator("li").filter({ has: page.getByRole("button", { name: "Collapse action logical-outage" }) });
  await expect(outage.locator("dt", { hasText: /^Release consumption$/ }).locator("+ dd")).toHaveText("Not recorded");
  await expect(outage.locator("dt", { hasText: /^Reported native or delivery outcome$/ }).locator("+ dd")).toContainText("succeeded");
  await expect(outage.getByRole("region", { name: "Decision history", exact: true })).toContainText("unavailable");
  await expect(outage.getByRole("region", { name: "Approval history", exact: true })).toContainText("unavailable");
  expect(trace.reads.filter((url) => url.searchParams.has("view")).every((url) => url.searchParams.get("action_id") === ACTION)).toBe(true);
  const report = page.getByRole("region", { name: "Investigation report" });
  await report.getByText("Investigation attempts (1)", { exact: true }).click();
  await expect(report.getByRole("table", { name: "Investigation attempts" })).toContainText("Attempt 1");
  await expect(report.getByRole("table", { name: "Investigation attempts" })).not.toContainText("0.160.0");
  await expect(report.getByRole("link", { name: "View credit usage" })).toHaveCount(0);
  const uppercasePins = PINNED.replace(/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/g, (value) => value.toUpperCase());
  await page.goto(uppercasePins);
  await expect(page.getByRole("heading", { level: 1, name: "Session", exact: true })).toBeVisible();
  await expect(page.getByText("Retained investigation summary", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert").filter({ hasText: /\S/ })).toHaveCount(0);
  await readOnly(page, trace);
});

test("action histories load and retry independently while empty and unavailable states stay distinct", async ({ page }) => {
  let releaseDecisions!: () => void;
  const controls: Controls = {
    decisionsGate: new Promise<void>((resolve) => { releaseDecisions = resolve; }), approvalsFailure: true,
  };
  const trace = await mockArchive(page, fixture(), controls);
  await page.goto(`/sessions/${SESSION}`);
  const section = page.getByRole("region", { name: "Guardrail actions" });
  const expand = section.getByRole("button", { name: "Expand action logical-ask" });
  await expect(expand).toBeVisible();
  expect(trace.reads.filter((url) => url.searchParams.has("view"))).toEqual([]);
  await expand.click();
  const asked = section.locator("li").filter({ has: page.getByRole("button", { name: "Collapse action logical-ask" }) });
  const decisions = asked.getByRole("region", { name: "Decision history (3)", exact: true });
  const approvals = asked.getByRole("region", { name: "Approval history (2)", exact: true });
  await expect(asked.getByRole("region", { name: "Action target", exact: true })).toHaveText("git status");
  await expect(decisions.getByText("Loading decision history…")).toBeVisible();
  await expect(approvals.getByRole("alert")).toContainText("Approval history temporarily unavailable");
  await expect(approvals).not.toContainText("No recorded approval generations.");
  releaseDecisions();
  await expect(decisions.getByRole("table")).toContainText("6 / 4");
  controls.approvalsFailure = false;
  await approvals.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(approvals.getByRole("table")).toContainText("approved");
  await expect(decisions.getByRole("table")).toContainText("6 / 4");
  await asked.getByRole("button", { name: "Collapse action logical-ask" }).focus();
  await page.keyboard.press("Space");
  await expect(expand).toBeFocused();
  await expect(section.getByRole("region", { name: "Decision history (3)", exact: true })).toHaveCount(0);
  await section.getByRole("button", { name: "Expand action logical-zero" }).click();
  const allowed = section.locator("li").filter({ has: page.getByRole("button", { name: "Collapse action logical-zero" }) });
  await expect(allowed.getByRole("table", { name: "Decision history" })).toContainText("allow");
  const empty = allowed.getByRole("region", { name: "Approval history (0)", exact: true });
  await expect(empty).toContainText("No recorded approval generations.");
  await expect(empty.getByRole("table")).toHaveCount(0);
  await readOnly(page, trace);
});

test("queue prioritizes reports with all outcomes and directs policy findings to Risky Sessions/Users", async ({ page }, info) => {
  const data = fixture();
  data.reports[0].title = "Attempted credential upload during repository review";
  data.reports[0].summary = "The agent attempted an external credential upload outside the stated task. Delivery is unconfirmed; verify exposure before selecting a response.";
  data.reports.push({ ...data.reports[0], id: id(82), job_id: id(82), outcome: "no_actionable_findings", verdict: "true_positive_non_malicious", title: "Approved diagnostics reviewed" },
    { ...data.reports[0], id: id(83), job_id: id(83), outcome: "inconclusive", verdict: null, title: "Upload delivery remains unknown" },
    { ...data.reports[0], id: id(84), job_id: id(84), outcome: "no_actionable_findings", verdict: "false_positive", title: "Quoted command did not run" });
  const controls: Controls = {};
  const trace = await mockArchive(page, data, controls);
  await page.goto("/detections");
  const reports = page.getByRole("region", { name: "Investigation reports", exact: true });
  const policy = page.getByRole("region", { name: "Policy findings", exact: true });
  await expect(reports.getByRole("link", { name: data.reports[0].title, exact: true })).toHaveAttribute("href", REPORT_PINNED);
  await expect(reports.getByRole("list", { name: "Investigation report list" }).getByRole("listitem")).toHaveCount(4);
  await expect(reports.getByText("True Positive Non-malicious", { exact: true })).toBeVisible();
  await expect(reports.getByText("False Positive", { exact: true })).toBeVisible();
  await expect(reports.getByText("Investigation incomplete", { exact: true })).toBeVisible();
  await expect(reports.getByText(/^Confidence:/)).toHaveCount(0);
  await expect(policy).toHaveCount(0);
  expect(trace.reads.some((url) => url.pathname.endsWith("/findings"))).toBe(false);
  await reports.getByRole("combobox", { name: "Report outcomes" }).click();
  await page.getByRole("option", { name: "True Positive", exact: true }).click();
  await expect.poll(() => trace.reads.some((url) => url.pathname.endsWith("/session-investigations") &&
    url.searchParams.get("outcome") === "true_positive")).toBe(true);
  await expect(reports.getByRole("list", { name: "Investigation report list" }).getByRole("listitem")).toHaveCount(1);
  await expect(page.locator('main [role="status"]').filter({ hasText: /Loading|Checking access/ })).toHaveCount(0);
  for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await expect(reports.getByRole("link", { name: data.reports[0].title, exact: true })).toBeVisible();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await expect(page.getByRole("heading", { level: 1 })).toBeInViewport();
    await expect(reports.getByRole("heading", { name: "Investigation reports", exact: true })).toBeInViewport();
    expect((await reports.boundingBox())!.y).toBeLessThan((await page.getByRole("region", { name: "Detection pipeline", exact: true }).boundingBox())!.y);
    await page.screenshot({ path: info.outputPath(`report-queue-${viewport.width}.png`), fullPage: true, animations: "disabled" });
  }
  controls.incidentFailure = true;
  await reports.getByRole("button", { name: "Refresh reports", exact: true }).click();
  await expect(reports.getByRole("alert")).toContainText("Showing the last successful reports.");
  await expect(reports.getByRole("link", { name: data.reports[0].title, exact: true })).toBeVisible();
  controls.incidentFailure = false;
  controls.incidentEmpty = true;
  await reports.getByRole("button", { name: "Refresh reports", exact: true }).click();
  await expect(reports.getByText("No investigation reports match", { exact: true })).toBeVisible();
  await expect(policy).toHaveCount(0);
  const coverage = page.locator("details").filter({ has: page.locator("summary").filter({ hasText: "Detection coverage" }) });
  await coverage.locator("summary").click();
  await expect(coverage.getByRole("link", { name: "Risky Sessions/Users", exact: true })).toHaveAttribute("href", "/user-risk?view=findings");
  await readOnly(page, trace);
});

test("incident reports show analysis, recommendations and pinned timeline evidence", async ({ page }, info) => {
  const data = fixture();
  Object.assign(data.report.report!.findings[0], {
    title: "Attempted credential upload during repository review",
    explanation: "The user asked for a repository review. The agent attempted to send a credential file to an external host. The retained evidence does not confirm delivery.",
    severity_rationale: "High severity because the requested upload included credentials outside the stated task.",
    timeline: [{ description: "The agent requested an external upload.", evidence_indices: [0] },
      { description: "Related retained history provides context for the request.", evidence_indices: [1] }],
    impact: { observed: "An upload was attempted. Delivery is unconfirmed.", potential: "Successful delivery could expose the credentials." },
    recommended_actions: [{ action: "Verify whether the external host received data.", rationale: "Establish exposure before selecting containment steps." }],
    uncertainties: ["The external outcome is unknown.", NONCE],
  });
  const trace = await mockArchive(page, data);
  await page.goto(PINNED);
  const report = page.getByRole("region", { name: "Investigation report", exact: true });
  await expect(report.getByRole("heading", { name: "Attempted credential upload during repository review" })).toBeVisible();
  await expect(report.getByRole("region", { name: "Severity rationale" })).toContainText("outside the stated task");
  await expect(report.getByRole("region", { name: "Incident impact" })).toContainText("Delivery is unconfirmed");
  await expect(report.getByRole("region", { name: "Recommended response" })).toContainText("have not been performed");
  await expect(report.getByRole("region", { name: "Uncertainty and missing evidence" })).toContainText(NONCE);
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  const timeline = report.getByRole("region", { name: "Incident timeline" });
  await expect(timeline.getByRole("link").first()).toHaveAttribute("href", new RegExp(`attempt=${ATTEMPT}.*snapshot=${SNAPSHOT}.*ordinal=2`));
  await timeline.getByRole("link", { name: `View retained history read ${READ}, item 0` }).click();
  await expect(page.getByRole("dialog", { name: "Retained history read" }).getByLabel("History item 0", { exact: true })).toHaveText(NONCE);
  await page.keyboard.press("Escape");
  for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.setViewportSize({ ...viewport, height: 3000 });
    await report.getByRole("list", { name: "Retained investigation findings", exact: true }).screenshot({
      path: info.outputPath(`incident-report-${viewport.width}.png`), animations: "disabled",
    });
  }
  await readOnly(page, trace);
});

test("standalone reports present the full investigation and preserve scoped evidence through every outcome", async ({ page }, info) => {
  const data = fixture();
  data.report.snapshot_current = true;
  data.report.configuration_current = true;
  Object.assign(data.report.report!, {
    title: "Credential upload investigation", outcome: "actionable_findings", verdict: "true_positive", confidence: "medium",
    conclusion: "The evidence supports an unauthorized upload attempt; receipt is unconfirmed.",
    summary: "During a repository review, the agent tried to send credentials to an external host. Delivery is unconfirmed. Check the destination logs and rotate any exposed credentials.",
    scope: { tenant_id: USER.tenant.id, user_id: id(13), ownership_verified: true,
      subject: { name: "Verified owner", email: "owner@example.test", reported_user: "reported-os-user", hostname: "JeV-workstation", ownership_verified: true },
      devices: [{ hostname: "JeV-workstation", user: "reported-os-user" }], projects: ["/workspace/JeV-customer-project"],
      reviewed_sessions: [{ session_id: SESSION, snapshot_id: SNAPSHOT, revision: 2, started_at: TIME, ended_at: TIME }],
      context_sessions: [{ session_id: id(28), snapshot_id: null, read_id: READ },
        { session_id: id(28), snapshot_id: null, read_id: id(29) }], review_cutoff: TIME, detector_config_version: 2 },
    evidence: data.report.report!.findings[0].evidence,
    timeline: [{ description: "An earlier session read credentials.", evidence_indices: [1] },
      { description: "The triggering session attempted the upload.", evidence_indices: [0] }],
    authorization: { assessment: "Troubleshooting did not authorize credential disclosure.", policy_basis: "Only approved destinations may receive diagnostics.",
      policy_quote: "Do not send secrets to JeV.example.", policy_revision: 8, evidence_indices: [0] },
    impact: { observed: "Upload attempted; delivery unconfirmed.", potential: "Credential exposure if the upload reached its destination." },
    recommendations: [{ priority: "urgent", action: "Confirm delivery and rotate exposed credentials.", rationale: "Destination records establish whether exposure occurred." }],
    alternative_explanations: ["The endpoint may have rejected the upload."],
    limitations: ["The upload response was not retained.", NONCE],
  });
  Object.assign(data.report.report!.findings[0], { category: "data_exposure", confidence: "medium", tags: ["agent_compromise"] });
  const trace = await mockArchive(page, data);
  await page.goto("/detections");
  const auditVisit = page.waitForRequest((request) => request.url().endsWith("/api/v1/audit/page-views")
    && request.postDataJSON()?.path?.startsWith("/detections/reports/"));
  await page.getByRole("link", { name: data.reports[0].title, exact: true }).click();
  expect((await auditVisit).postDataJSON()).toEqual({ path: `/detections/reports/${JOB}` });
  await expect(page).toHaveURL(new RegExp(`/detections/reports/${JOB}\\?attempt=${ATTEMPT}&snapshot=${SNAPSHOT}$`));
  const report = page.getByRole("region", { name: "Investigation report", exact: true });
  await expect(report.getByRole("region", { name: "Investigation verdict" })).toContainText("True Positive");
  await expect(report.getByText(/^Confidence:/)).toHaveCount(0);
  const sectionOrder = ["Executive summary", "Investigation impact", "Prioritized recommended response", "Investigation scope", "Investigation timeline"];
  for (let index = 1; index < sectionOrder.length; index++) {
    const before = await report.getByRole("region", { name: sectionOrder[index - 1], exact: true }).boundingBox();
    const after = await report.getByRole("region", { name: sectionOrder[index], exact: true }).boundingBox();
    expect(before!.y + before!.height).toBeLessThanOrEqual(after!.y);
  }
  await expect(report.getByRole("region", { name: "Investigation conclusion" })).toContainText("receipt is unconfirmed");
  await expect(report.getByRole("region", { name: "Executive summary" })).toContainText("During a repository review");
  await expect(report.getByRole("region", { name: "Investigation scope" })).toContainText("Context access does not establish");
  await expect(report.getByRole("region", { name: "Investigation scope" })).toContainText("JeV-workstation");
  await expect(report.getByRole("region", { name: "Investigation scope" })).toContainText("/workspace/JeV-customer-project");
  await expect(report.getByRole("heading", { name: "Sessions retrieved as context (1)", exact: true })).toBeVisible();
  await expect(report.getByRole("list", { name: "Context sessions" }).getByRole("link")).toHaveCount(2);
  await expect(report.getByRole("region", { name: "Authorization and policy", exact: true })).toContainText("Do not send secrets to JeV.example.");
  await expect(report.getByRole("region", { name: "Investigation impact" })).toContainText("delivery unconfirmed");
  await expect(report.getByRole("region", { name: "Prioritized recommended response" })).toContainText("urgent priority");
  await expect(report.getByRole("region", { name: "Evidence and limitations" })).toContainText(NONCE);
  await expect(report.getByText("Category: Data exposure and exfiltration", { exact: true })).toBeVisible();
  await expect(report.getByText("Additional categories: Agent and supply-chain compromise", { exact: true })).toBeVisible();
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  const timeline = report.getByRole("region", { name: "Investigation timeline" });
  await timeline.getByRole("link", { name: `View retained history read ${READ}, item 0` }).click();
  await expect(page.getByRole("dialog", { name: "Retained history read" }).getByLabel("History item 0", { exact: true })).toHaveText(NONCE);
  await page.keyboard.press("Escape");
  await timeline.getByRole("link", { name: "View target record 2, bytes 0 to 100" }).click();
  await expect(page).toHaveURL(new RegExp(`/detections/reports/${JOB}.*attempt=${ATTEMPT}.*snapshot=${SNAPSHOT}.*ordinal=2`));
  await page.getByRole("button", { name: "Load through cited record 2" }).click();
  await expect(page.locator("#snapshot-record-2")).toContainText(NONCE);
  for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 640 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await report.getByRole("region", { name: "Prioritized recommended response" }).scrollIntoViewIfNeeded();
    await expect(report.getByRole("region", { name: "Prioritized recommended response" })).toBeInViewport();
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await expect(page.getByRole("heading", { level: 1 })).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`complete-investigation-report-${viewport.width}.png`), fullPage: true, animations: "disabled", style: "nextjs-portal { display: none; }" });
    await page.screenshot({ path: info.outputPath(`investigation-report-overview-${viewport.width}.png`), animations: "disabled", style: "nextjs-portal { display: none; }" });
  }
  data.report.report!.findings = [];
  data.report.report!.status = "no_finding";
  data.report.report!.outcome = "no_actionable_findings";
  data.report.report!.verdict = "false_positive";
  data.report.report!.conclusion = "No supported violation in the reviewed evidence.";
  await page.goto(REPORT_PINNED);
  await expect(report.getByRole("region", { name: "Investigation verdict" })).toContainText("False Positive");
  await expect(report.getByRole("region", { name: "Investigation conclusion" })).toContainText("No supported violation");
  data.report.report!.verdict = "true_positive_non_malicious";
  await page.reload();
  await expect(report.getByRole("region", { name: "Investigation verdict" })).toContainText("True Positive Non-malicious");
  delete data.report.report!.verdict;
  await page.reload();
  await expect(report.getByRole("region", { name: "Investigation verdict" })).toContainText("Not classified");
  await expect(report.getByRole("region", { name: "Executive summary" })).toHaveText(`Executive summary${data.report.report!.summary}`);
  data.report.report!.status = "inconclusive";
  data.report.report!.outcome = "inconclusive";
  data.report.report!.confidence = "high";
  data.report.report!.verdict = "false_positive";
  data.report.report_generated_from_state = true;
  await page.reload();
  const verdict = report.getByRole("region", { name: "Investigation verdict" });
  await expect(verdict).toContainText("Investigation incomplete");
  await expect(verdict).toContainText("No verdict assigned");
  await expect(verdict).not.toContainText("False Positive");
  await expect(report.getByText(/^Confidence:/)).toHaveCount(0);
  await expect(report.getByText("No completed model report was retained for this attempt.", { exact: false })).toBeVisible();
  await expect(report.getByRole("region", { name: "Evidence and limitations" })).toContainText("not retained");
  await readOnly(page, trace);
});

test("product metadata uses public names while retained action evidence stays exact", async ({ page }) => {
  const data = fixture();
  const rawCommand = " \t/usr/local/bin/jev /tmp/JeV\r\n";
  data.summary.session.product = "jEvClient";
  data.summary.session.client = { product: "JeVAgent", version: "JEV-3.2" };
  data.actions[0].target_body.tool = { name: "JevModel", input: { model: "jev2", url: "https://jev.example" } };
  data.actions[0].target_body.command = { text: rawCommand, cwd: "/workspace/jev" };
  data.actions[0].assessment.model = "jEv-1.13.0";
  data.actions[0].assessment.value = { status: "scored", score: 50, reason: "Executed /usr/local/bin/jev against https://JeV.example" };
  data.decision.decision!.reason = "Review /usr/local/bin/jev";
  data.decision.decision!.warnings = ["Action contacts JeV.example"];
  data.actions[0].captured_context = { latest_prompt: { text: "Inspect /tmp/jev" }, matched_tool_call: { tool: { name: "JevModel", input: { model: "jev2" } } } };
  data.report.configuration.model = "JEV-1.13.0";
  data.report.report!.summary = "The command sent /tmp/JeV to jev.example.";
  const titles = [
    "Destructive command: /usr/local/bin/jev /tmp/JeV",
    "Destructive command:/usr/local/bin/jev /tmp/JeV",
    "Destructive command:\n/usr/local/bin/jev /tmp/JeV",
    "Secret access then egress to jev.example",
    "Upload to JeV.example via jevctl",
  ];
  data.report.report!.findings = titles.map((title) => ({ ...data.report.report!.findings[0], title,
    explanation: "The agent ran /usr/local/bin/jev and contacted https://JEV.example.",
  }));
  Object.assign(data.report.usage[0], {
    provider: "JEV", model: "jev-1.13.0", reported_model: "JeV-1.13.0 [ref 8939aeec]",
    price_quote: { model: "jev-1.13.0" },
  });
  data.snapshot.items[2].body.model = "JEV-1.13.0";
  const trace = await mockArchive(page, data);
  await page.goto(PINNED);
  const identity = page.getByRole("region", { name: "Session overview" });
  await expect(identity.locator("dt", { hasText: /^Client$/ }).locator("+ dd")).toHaveText("GuardrailAgent Guardrail-3.2");
  await expect(page.getByText(data.report.report!.summary, { exact: true })).toBeVisible();
  const section = page.getByRole("region", { name: "Guardrail actions" });
  await expect(section.getByRole("button", { name: "Expand action logical-ask" })).toContainText("JevModel");
  await section.getByRole("button", { name: "Expand action logical-ask" }).click();
  const asked = section.locator("li").filter({ has: page.getByRole("button", { name: "Collapse action logical-ask" }) });
  await expect(asked.getByText("Rubric 1", { exact: true })).toBeVisible();
  await expect(asked).toContainText(data.actions[0].assessment.value.reason as string);
  await expect(asked).toContainText("Review /usr/local/bin/jev");
  await expect(asked).toContainText("Action contacts JeV.example");
  await asked.getByText("Captured assessment context", { exact: true }).click();
  await asked.getByRole("button", { name: /^Expand Assessment context:/ }).click();
  await expect(asked.getByRole("region", { name: "Action target", exact: true })).toHaveText("/usr/local/bin/jev /tmp/JeV");
  await mockClipboard(page);
  await asked.getByRole("region", { name: "Action target", exact: true }).getByRole("button", { name: "Copy text", exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(rawCommand);
  await expect.poll(() => asked.locator("details").filter({ has: page.getByText("Captured assessment context", { exact: true }) }).locator("pre").textContent()).toBe(JSON.stringify(data.actions[0].captured_context, null, 2));
  const report = page.getByRole("region", { name: "Investigation report" });
  await report.getByText("Investigation attempts (1)", { exact: true }).click();
  await expect(report.getByRole("table", { name: "Investigation usage" })).toHaveCount(0);
  await expect(report.getByRole("button", { name: /^Expand Stored price quote:/ })).toHaveCount(0);
  await expect(report).not.toContainText("gpt-6.1-sol");
  await expect(report).not.toContainText("1.13.0");
  await report.getByText("Report identifiers", { exact: true }).click();
  await expect(report.getByRole("button", { name: /^Expand Investigation configuration:/ })).toHaveCount(0);
  const findings = report.getByRole("list", { name: "Retained investigation findings" });
  await expect.poll(() => findings.getByRole("heading").allTextContents()).toEqual(titles);
  await expect(findings.getByText(data.report.report!.findings[0].explanation, { exact: true })).toHaveCount(titles.length);
  const decisions = asked.getByRole("table", { name: "Decision history" });
  await expect(decisions).toContainText("Review /usr/local/bin/jev");
  await expect(decisions).toContainText("Action contacts JeV.example");
  const snapshot = page.getByRole("region", { name: "Retained snapshot", exact: true });
  await snapshot.getByRole("button", { name: "Load more", exact: true }).click();
  await snapshot.getByRole("button", { name: "Expand snapshot record 3", exact: true }).click();
  const record = snapshot.locator("#snapshot-record-3");
  await record.getByText("Full retained metadata", { exact: true }).click();
  await record.getByRole("button", { name: /^Expand Snapshot record 3 metadata:/ }).click();
  await expect.poll(() => record.locator("details").filter({ has: page.getByText("Full retained metadata", { exact: true }) }).locator("pre").textContent()).toBe(JSON.stringify(data.snapshot.items[2], null, 2));
  data.summary.session.client.product = "";
  await page.reload();
  await expect(identity.locator("dt", { hasText: /^Client$/ }).locator("+ dd")).toHaveText("GuardrailClient Guardrail-3.2");
  await readOnly(page, trace);
});

test("installed-hook sessions show retained evidence without managed-session controls", async ({ page }) => {
  const data = fixture();
  data.summary.registration = null;
  data.snapshot.snapshot.registration_id = null;
  data.snapshot.snapshot.session_id = SESSION;
  data.snapshot.snapshot.owner_user_id = null;
  data.report.registration_id = null;
  const trace = await mockArchive(page, data);
  await page.goto(`/sessions/${SESSION}?snapshot=${SNAPSHOT}&ordinal=2#snapshot`);
  const overview = page.getByRole("region", { name: "Session overview", exact: true });
  await expect(overview).toBeVisible();
  await expect(overview).not.toContainText(/Managed lifecycle|Pending approvals|Approved but not consumed|Owner binding verified|Assessment mode|Delivery protocol|Registration ID|Delivery epoch/);
  await expect(page.getByRole("region", { name: "Guardrail actions", exact: true })).toHaveCount(0);
  expect(trace.reads.some((url) => url.pathname.endsWith("/guardrail-actions"))).toBe(false);
  const snapshot = page.getByRole("region", { name: "Retained snapshot", exact: true });
  await snapshot.getByRole("button", { name: "Load through cited record 2", exact: true }).click();
  await expect(snapshot.getByLabel("Snapshot record 2", { exact: true })).toHaveText(NONCE);
  expect(trace.ownerRequests).toEqual([]);
  data.snapshot.snapshot.session_id = id(99);
  await page.reload();
  await expect(page.getByRole("alert").filter({ hasText: "This snapshot does not belong to the selected session" })).toBeVisible();
  await expect(page.getByLabel("Snapshot record 2", { exact: true })).toHaveCount(0);
});

test("only Security Analysts can verify detection ownership and revoked sessions cannot be reassigned", async ({ page }) => {
  const data = fixture();
  data.summary.registration = null;
  const controls: Controls = { userRoles: ["security_leadership"] };
  const trace = await mockArchive(page, data, controls);
  await page.goto(`/sessions/${SESSION}`);
  const ownership = page.getByRole("region", { name: "Detection user context" });
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(ownership.getByRole("combobox")).toHaveCount(0);
  controls.userRoles = ["security_analyst"];
  await page.reload();
  await ownership.getByRole("combobox", { name: "Verified session user" }).click();
  await expect(page.getByRole("option", { name: /Disabled user/ })).toHaveCount(0);
  await page.getByRole("option", { name: "Verified owner (owner@example.test)" }).click();
  await ownership.getByRole("button", { name: "Assign verified user" }).click();
  await expect(ownership).toContainText("Verified user: Verified owner (owner@example.test)");
  await expect(ownership.getByRole("combobox")).toHaveCount(0);
  await ownership.getByRole("button", { name: "Revoke detection ownership" }).click();
  await expect(ownership).toContainText("This session cannot be reassigned");
  await expect(ownership.getByRole("button")).toHaveCount(0);
  await page.reload();
  await expect(ownership).toContainText("Detection ownership was revoked");
  expect(trace.mutations).toEqual([`PUT sessions/${SESSION}/detection-owner`, `PUT sessions/${SESSION}/detection-owner`]);
});

test("retained snapshot and history citations preserve exact pages and escape untrusted text", async ({ page }) => {
  const data = fixture(), trace = await mockArchive(page, data);
  const dialogs: string[] = [];
  page.on("dialog", async (dialog) => { dialogs.push(dialog.message()); await dialog.dismiss(); });
  await page.goto(PINNED);
  const targetLink = page.getByRole("link", { name: "View target record 2, bytes 0 to 100", exact: true });
  await targetLink.click();
  const snapshot = page.getByRole("region", { name: "Retained snapshot" });
  await snapshot.getByRole("button", { name: "Load through cited record 2", exact: true }).click();
  await expect(snapshot.getByLabel("Snapshot record 2", { exact: true })).toHaveText(NONCE);
  await expect(snapshot.getByText(/Citation: bytes 0 to 100, end excluded/)).toBeVisible();
  await expect(snapshot.getByText("3 retained records", { exact: false })).toBeVisible();
  expect(trace.reads.filter((url) => url.pathname.endsWith(`/session-snapshots/${SNAPSHOT}`))
    .some((url) => url.searchParams.get("cursor") === "opaque-snapshot-page-2")).toBe(true);
  await expect(page.locator("img[src='x']")).toHaveCount(0);

  const history = page.getByRole("link", { name: `View retained history read ${READ}, item 0`, exact: true });
  await history.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Retained history read" });
  await expect(dialog.getByLabel("History item 0", { exact: true })).toHaveText(NONCE);
  await dialog.getByText("Read identifiers and digest", { exact: true }).click();
  await expect(dialog).toContainText(data.retained.response_sha256);
  await dialog.getByText("Full retained response", { exact: true }).click();
  await expect(dialog.getByLabel("Retained history response", { exact: true })).toContainText('"tenant_id"');
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const bounds = await dialog.evaluate((element) => {
      const outer = element.getBoundingClientRect();
      return {
        clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
        contentFits: Array.from(element.children).every((child) => {
          const inner = child.getBoundingClientRect();
          return inner.left >= outer.left && inner.right <= outer.right;
        }),
      };
    });
    expect(bounds.scrollWidth).toBeLessThanOrEqual(bounds.clientWidth);
    expect(bounds.contentFits).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("link", { name: `View retained history read ${READ}, item 0`, exact: true })).toBeFocused();
  expect(dialogs).toEqual([]);
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  await readOnly(page, trace);
});

test("projected assessment views distinguish returned bytes from retained source integrity", async ({ page }) => {
  const data = fixture();
  const original = data.snapshot.items[1];
  const item = { ...original, kind: "assessment", body: { target_body: original.body, assessment: { score: 50 } } };
  data.snapshot.items[1] = { ...item, representation: "customer_service_metadata_v1",
    retained_source_sha256: "a".repeat(64), representation_sha256: createHash("sha256").update(canonical(item)).digest("hex") };
  const text = canonical(item);
  data.retained.response.items = [{ ordinal: 2, source_id: item.source_id, start: 0,
    end: Buffer.byteLength(text), total_bytes: Buffer.byteLength(text), text,
    sha256: createHash("sha256").update(text).digest("hex"), representation: "customer_service_metadata_v1",
    retained_source_range: { start: 41, end: 82, total_bytes: 999, sha256: "a".repeat(64) } }];
  data.retained.response.representation = "customer_service_metadata_v1";
  data.retained.representation = "customer_service_metadata_v1";
  data.retained.retained_response_sha256 = "b".repeat(64);
  data.retained.response_sha256 = createHash("sha256").update(canonical(data.retained.response)).digest("hex");
  const trace = await mockArchive(page, data);
  await page.goto(PINNED);
  await page.getByRole("link", { name: "View target record 2, bytes 0 to 100", exact: true }).click();
  const snapshot = page.getByRole("region", { name: "Retained snapshot" });
  await snapshot.getByRole("button", { name: "Load through cited record 2", exact: true }).click();
  await expect(snapshot.getByLabel("Snapshot record 2", { exact: true })).toHaveText(NONCE);
  await expect(snapshot).toContainText("Citation byte ranges refer to the original stored record.");
  await expect(snapshot).toContainText("The assessment view below has separate bytes and a separate hash.");
  await page.getByRole("link", { name: `View retained history read ${READ}, item 0`, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Retained history read" });
  await dialog.getByRole("button", { name: /^Expand History item 0:/ }).click();
  await expect(dialog.getByLabel("History item 0", { exact: true }).locator("pre")).toHaveText(text);
  await expect(dialog).toContainText("Assessment view UTF-8 bytes 0");
  await expect(dialog).not.toContainText("Exact response retained");
  await dialog.getByText("Original source range and view digest", { exact: true }).click();
  await expect(dialog).toContainText('"start": 41');
  await expect(dialog).toContainText("a".repeat(64));
  await dialog.getByText("Read identifiers and digest", { exact: true }).click();
  await expect(dialog).toContainText(data.retained.response_sha256);
  await expect(dialog).toContainText(data.retained.retained_response_sha256);
  await expect(dialog.getByText("Full assessment view response", { exact: true })).toBeVisible();
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  await readOnly(page, trace);
});

test("mobile loading, failure and stale states do not invent zero risk or replace pinned evidence", async ({ page }) => {
  const data = fixture();
  let release!: () => void;
  const controls: Controls = { summaryGate: new Promise<void>((resolve) => { release = resolve; }) };
  const trace = await mockArchive(page, data, controls);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/sessions/${SESSION}`);
  await expect(page.getByRole("status").filter({ hasText: /Loading session/ })).toBeVisible();
  controls.summaryFailure = true;
  release();
  await expect(page.getByRole("alert").filter({ hasText: "Archive temporarily unavailable" })).toBeVisible();
  data.summary.projection = { ...data.summary.projection, available: false, updated_at: null,
    revision: 0, snapshot_id: null, snapshot_current: false };
  data.summary.detection = null;
  data.summary.investigations = { items: [], next_cursor: "" };
  controls.summaryFailure = false;
  await page.getByRole("alert").filter({ hasText: "Archive temporarily unavailable" }).getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("No stored detection summary", { exact: true })).toBeVisible();
  const overview = page.getByRole("region", { name: "Session overview" });
  await expect(overview.locator("dt", { hasText: /^Stored risk total$/ }).locator("+ dd")).toHaveText("Unavailable");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

  data.summary = fixture().summary;
  controls.missingPinnedAttempt = true;
  await page.goto(PINNED);
  await expect(page.getByRole("alert").filter({ hasText: "Retained investigation is unavailable" })).toBeVisible();
  expect(trace.reads.filter((url) => url.pathname.endsWith(`/session-investigations/${JOB}`))
    .every((url) => url.searchParams.get("attempt_id") === ATTEMPT)).toBe(true);
  await expect(page.getByText("Retained investigation summary", { exact: true })).toHaveCount(0);
  controls.snapshotFailure = true;
  await page.reload();
  await expect(page.getByRole("alert").filter({ hasText: "The exact retained snapshot remains selected." })).toBeVisible();
  expect(page.url()).toContain(`snapshot=${SNAPSHOT}`);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await readOnly(page, trace);
});

test("investigation details preserve evidence and attempts without exposing private accounting", async ({ page }) => {
  const data = fixture();
  data.report.state = "inconclusive";
  Object.assign(data.report.attempts[0], { state: "inconclusive", actual_tokens: null, actual_cost_usd: null, runtime: null });
  Object.assign(data.report.report!, { status: "inconclusive", findings: [], runtime: null,
    reason: "usage_unknown", coverage: { status: "incomplete" },
    summary: "The investigation could not complete.", usage: { actual_tokens: null, actual_cost_usd: null } });
  const trace = await mockArchive(page, data, { userRoles: ["security_analyst", "security_leadership"] });
  await page.goto(PINNED);
  const investigation = page.getByRole("region", { name: "Investigation report" });
  await expect(investigation.getByText("Stopped: usage unknown.", { exact: true })).toBeVisible();
  await investigation.getByText("Investigation attempts (1)", { exact: true }).click();
  const attempts = investigation.getByRole("table", { name: "Investigation attempts" });
  await expect(attempts).toContainText("Attempt 1");
  await expect(attempts).toContainText("inconclusive");
  await expect(investigation.getByRole("table", { name: "Investigation usage" })).toHaveCount(0);
  await expect(investigation).not.toContainText(/gpt-|200,000|\$10\.00|Measured tokens|Reserved USD/);
  await expect(investigation.getByRole("link", { name: "View credit usage" })).toHaveAttribute("href", "/costs/openaidr");
  await readOnly(page, trace);
});
