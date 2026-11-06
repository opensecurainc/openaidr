import { test, expect, type Page } from "@playwright/test";

const ID = "11111111-2222-4333-8444-555555555555";
const PATH = `/approvals/${ID}`;
const USER = { id: "owner", email: "owner@example.test", name: "Owner", roles: ["security_leadership"], tenant: { id: "tenant", name: "Example", slug: "example" } };
const TARGET = { id: "event", kind: "command", time: "2026-10-02T08:00:00Z", command: { text: "git status", cwd: "/workspace/project" }, tool: { name: "Shell" } };

function approval(overrides: Record<string, unknown> = {}) {
  return {
    id: ID, status: "pending", expires_at: "2026-10-04T08:00:00Z", reason_code: "",
    tenant: { name: "Example" }, client: { product: "codex-cli", version: "0.159.0" },
    device: { hostname: "workstation", label: "Development laptop" }, boundary: "tool_call",
    preview: { target: TARGET, context: { latest_prompt: null, matched_tool_call: null, prior_events: [] } },
    preview_withheld: false, assessment: { status: "scored", score: 50, category: "excessive_agency" },
    reason: "Matched guardrail risk threshold", warnings: [], gaps: [], release: null, ...overrides,
  };
}

async function signedIn(page: Page) {
  await page.route("**/api/v1/auth/me", (route) => route.fulfill({ json: { user: USER } }));
}

test("the owner reviews exact content and approves once without releasing from the browser", async ({ page }) => {
  await signedIn(page);
  const command = "  /usr/local/bin/jev --url https://JEV.example/api\n# <img src=x onerror=alert(1)>  ";
  const input = { command, model: "jev2", path: "/tmp/JeV", timeout: 10 };
  let current = approval({
    preview: {
      target: { ...TARGET, tool: { name: "JevModel", input }, command: { text: command, cwd: "/workspace/JeV" } },
      context: {
        latest_prompt: { id: "prompt", kind: "prompt", text: "Inspect /tmp/jev without changing it." },
        matched_tool_call: null,
        prior_events: [
          { id: "file", kind: "file", file: { path: "/tmp/jev/config.json" } },
          { id: "network", kind: "network", network: { url: "https://jev.example/api" } },
        ],
      },
    },
    gaps: ["content_redacted"],
    client: { product: "JEV", version: "jev2" },
    tenant: { name: "Jev research" },
    device: { hostname: "jev.example", label: "" },
    reason: "The command runs /usr/local/bin/jev",
    warnings: ["Action contacts https://JEV.example/api"],
  });
  let decisions = 0;
  const ingest: string[] = [];
  page.on("request", (request) => { if (request.url().includes("/ingest/")) ingest.push(request.url()); });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route(`**/api/v1/me/approvals/${ID}`, (route) => route.fulfill({ json: current }));
  await page.route(`**/api/v1/me/approvals/${ID}/decision`, async (route) => {
    decisions++;
    expect(route.request().headers()["x-openaidr-csrf"]).toBe("1");
    expect(route.request().postDataJSON()).toEqual({ decision: "approve" });
    await gate;
    current = { ...current, status: "approved" };
    await route.fulfill({ json: current });
  });
  await page.goto(PATH);
  await expect(page.getByText(current.device.hostname, { exact: true })).toBeVisible();
  await expect(page.getByText("Guardrail Guardrail2", { exact: true })).toBeVisible();
  await expect(page.getByText("Jev research", { exact: true })).toBeVisible();
  await expect(page.getByText(current.reason, { exact: true })).toBeVisible();
  await expect(page.getByText(current.warnings[0], { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Captured action · JevModel", exact: true })).toBeVisible();
  await expect(page.getByText("content redacted.", { exact: true })).toBeVisible();
  await expect.poll(() => page.getByLabel("Captured action", { exact: true }).textContent()).toBe(command);
  await expect.poll(() => page.getByLabel("Captured action arguments", { exact: true }).textContent()).toBe(JSON.stringify(input, null, 2));
  await expect(page.getByText("/workspace/JeV", { exact: true })).toBeVisible();
  await page.getByText("Review captured context", { exact: true }).click();
  await expect(page.getByLabel("Latest prompt", { exact: true })).toHaveText("Inspect /tmp/jev without changing it.");
  await expect(page.getByLabel("Earlier file", { exact: true })).toHaveText("/tmp/jev/config.json");
  await expect(page.getByLabel("Earlier network", { exact: true })).toHaveText("https://jev.example/api");
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  const approve = page.getByRole("button", { name: "Approve once" });
  await approve.focus();
  await page.keyboard.press("Enter");
  await expect.poll(() => decisions).toBe(1);
  await expect(page.getByRole("button", { name: "Saving…" })).toBeDisabled();
  await page.keyboard.press("Enter");
  release();
  await expect(page.getByText("Approved, waiting for the client")).toBeVisible();
  expect(decisions).toBe(1);
  expect(ingest).toEqual([]);
  await expect(page.getByRole("button", { name: "Revoke approval" })).toBeVisible();
});

test("rejection is explicit and leaves the action unavailable for approval", async ({ page }) => {
  await signedIn(page);
  let current = approval({
    boundary: "tool_output",
    preview: { target: { id: "result", kind: "tool.result", tool: { name: "Read", output: { content: "structured output" } } }, context: { latest_prompt: null, matched_tool_call: null, prior_events: [] } },
  });
  await page.route(`**/api/v1/me/approvals/${ID}`, (route) => route.fulfill({ json: current }));
  await page.route(`**/api/v1/me/approvals/${ID}/decision`, (route) => {
    expect(route.request().postDataJSON()).toEqual({ decision: "reject" });
    current = { ...current, status: "rejected" };
    return route.fulfill({ json: current });
  });
  await page.goto(PATH);
  await expect(page.getByLabel("Captured action", { exact: true })).toContainText('"content": "structured output"');
  await page.getByRole("button", { name: "Reject", exact: true }).click();
  await expect(page.getByText("Rejected", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve once" })).toHaveCount(0);
});

test("wrong-account reads disclose no preview and offer account switching", async ({ page }) => {
  await signedIn(page);
  await page.route(`**/api/v1/me/approvals/${ID}`, (route) => route.fulfill({ status: 404, json: { error: { message: "not found" } } }));
  await page.goto(PATH);
  await expect(page.locator("main").getByRole("alert")).toContainText("unavailable for your account");
  await expect(page.getByText("git status", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Approve once" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Switch account" })).toBeVisible();
});

test("password login returns to the held action without approving it", async ({ page }) => {
  let authenticated = false;
  let decisions = 0;
  await page.route("**/api/v1/auth/me", (route) => route.fulfill(authenticated
    ? { json: { user: USER } } : { status: 401, json: { error: { message: "Sign in" } } }));
  await page.route("**/api/v1/auth/config", (route) => route.fulfill({ json: { mode: "local", password_login: true } }));
  await page.route("**/api/v1/auth/login", (route) => {
    expect(route.request().headers()["x-openaidr-csrf"]).toBe("1");
    authenticated = true;
    return route.fulfill({ json: { user: USER } });
  });
  await page.route(`**/api/v1/me/approvals/${ID}`, (route) => route.fulfill({ json: approval() }));
  await page.route(`**/api/v1/me/approvals/${ID}/decision`, (route) => { decisions++; return route.fulfill({ json: approval() }); });
  await page.goto(PATH);
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("Email address").fill(USER.email);
  await page.getByLabel("Password", { exact: true }).fill("test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`${PATH}$`));
  await expect(page.getByRole("button", { name: "Approve once" })).toBeVisible();
  expect(decisions).toBe(0);
  expect(await page.evaluate(() => sessionStorage.getItem("openaidr.sessionActionReturn"))).toBeNull();
});

test("authenticated Google return resumes only the fixed local action path", async ({ page }) => {
  let authenticated = false;
  let telemetryReads = 0;
  await page.route("**/api/v1/auth/me", (route) => route.fulfill(authenticated
    ? { json: { user: USER } } : { status: 401, json: { error: { message: "Sign in" } } }));
  await page.route("**/api/v1/auth/config", (route) => route.fulfill({ json: { mode: "cloud_google", password_login: false } }));
  await page.route("**/api/v1/auth/oidc/start", (route) => route.fulfill({ json: { authorization_url: "https://auth.example.test/authorize" } }));
  await page.route("https://auth.example.test/authorize", (route) => route.fulfill({ contentType: "text/plain", body: "Identity provider" }));
  await page.route("**/api/v1/telemetry/overview*", (route) => { telemetryReads++; return route.fulfill({ json: {} }); });
  await page.route(`**/api/v1/me/approvals/${ID}`, (route) => route.fulfill({ json: approval() }));
  await page.goto(PATH);
  await page.getByRole("button", { name: "Continue with Google" }).click();
  await expect(page).toHaveURL("https://auth.example.test/authorize");
  authenticated = true;
  await page.goto("/");
  await expect(page).toHaveURL(new RegExp(`${PATH}$`));
  await expect(page.getByRole("button", { name: "Approve once" })).toBeVisible();
  expect(telemetryReads).toBe(0);
  expect(await page.evaluate(() => sessionStorage.getItem("openaidr.sessionActionReturn"))).toBeNull();
});

test("registration uses a pasted one-use code without putting it in navigation or storage", async ({ page }) => {
  await signedIn(page);
  const code = "oasr_" + "a".repeat(43);
  let confirmations = 0;
  await page.route("**/api/v1/session-registrations/confirm", (route) => {
    confirmations++;
    expect(route.request().headers()["x-openaidr-csrf"]).toBe("1");
    expect(route.request().postDataJSON()).toEqual({ token: code });
    return route.fulfill({ json: { id: "registration", product: "codex-cli", external_id: "native-session", status: "verified" } });
  });
  await page.goto("/register-session");
  await page.getByLabel("Code from your client").fill(code);
  expect(confirmations).toBe(0);
  await page.getByRole("button", { name: "Register session", exact: true }).click();
  await expect(page.getByText("Registered to your account")).toBeVisible();
  expect(confirmations).toBe(1);
  await expect(page.getByLabel("Native session ID")).toHaveText("native-session");
  await expect(page.getByLabel("Code from your client")).toHaveCount(0);
  expect(page.url()).not.toContain(code);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain(code);
});

test("held responses, unknown risk, expiry conflicts and uncertain outcomes stay explicit", async ({ page }) => {
  await signedIn(page);
  let current = approval({ boundary: "assistant_response", preview: null, preview_withheld: true, assessment: { status: "unavailable", score: null, category: "unknown" } });
  await page.route(`**/api/v1/me/approvals/${ID}`, (route) => route.fulfill({ json: current }));
  await page.route(`**/api/v1/me/approvals/${ID}/decision`, (route) => {
    current = { ...current, status: "expired" };
    return route.fulfill({ status: 409, json: { error: { code: "approval_expired", message: "Approval expired" } } });
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(PATH);
  await expect(page.getByText("The response is held until you approve.")).toBeVisible();
  await expect(page.getByText("Risk assessment: Unavailable")).toBeVisible();
  await expect(page.getByText(/0 \/ 100/)).toHaveCount(0);
  await page.getByRole("button", { name: "Approve once" }).click();
  await expect(page.getByText("Expired", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve once" })).toHaveCount(0);
  current = approval({ status: "approved", release: { id: "release", consumed_at: "2026-10-02T08:00:00Z", outcome: "uncertain" } });
  await page.reload();
  await expect(page.getByText("Outcome: uncertain.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke approval" })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("an arbitrary stored return URL is discarded after authentication", async ({ page }) => {
  await page.route("**/api/v1/auth/config", (route) => route.fulfill({ json: { mode: "local", password_login: true } }));
  await page.route("**/api/v1/auth/login", (route) => route.fulfill({ json: { user: USER } }));
  await signedIn(page);
  await page.route("**/api/v1/telemetry/overview*", (route) => route.fulfill({ status: 503, json: { error: { message: "Unavailable" } } }));
  await page.goto("/login");
  await page.evaluate(() => sessionStorage.setItem("openaidr.sessionActionReturn", "https://attacker.example.test/"));
  await page.getByLabel("Email address").fill(USER.email);
  await page.getByLabel("Password", { exact: true }).fill("test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/$/);
  expect(await page.evaluate(() => sessionStorage.getItem("openaidr.sessionActionReturn"))).toBeNull();
});
