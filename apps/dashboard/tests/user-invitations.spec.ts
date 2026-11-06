import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { resolve } from "node:path";

let backend: ChildProcess;
let output = "";
const password = "invitation-test-password";
test.beforeAll(async () => {
  if (!process.env.OPENAIDR_TEST_DATABASE_URL)
    throw new Error("Set OPENAIDR_TEST_DATABASE_URL to a disposable PostgreSQL database.");
  backend = spawn(process.env.OPENAIDR_TEST_PYTHON || "python3", [resolve(__dirname, "fixtures/user-invitations-server.py")], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  backend.stdout!.on("data", (chunk) => { output += chunk.toString(); });
  backend.stderr!.on("data", (chunk) => { output += chunk.toString(); });
  const port = process.env.OPENAIDR_INVITATION_TEST_API_PORT || "8787";
  await expect.poll(async () => {
    if (backend.exitCode !== null || backend.signalCode !== null) throw new Error(output);
    try { return (await fetch(`http://127.0.0.1:${port}/api/v1/auth/me`)).status; }
    catch { return 0; }
  }, { timeout: 30_000 }).toBe(401);
});
test.afterAll(async () => {
  if (backend && backend.exitCode === null) {
    const closed = once(backend, "close");
    backend.kill("SIGTERM");
    const [code] = await closed;
    expect(code, output).toBe(0);
  }
});

async function signIn(page: Page, email = "owner@example.invalid") {
  await page.goto("/login");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/$/);
  await page.goto("/administration/users");
  await expect(page.getByRole("heading", { name: "Users and Roles", exact: true })).toBeVisible();
}

async function invitation(page: Page, email: string) {
  const reply = await page.request.post("/api/v1/users/invites", {
    headers: { "X-OpenAIDR-CSRF": "1", Origin: new URL(page.url()).origin },
    data: { email, role: "viewer" },
  });
  expect(reply.status()).toBe(201);
  return await reply.json() as { id: string; token: string; accept_url: string };
}

async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

test("IT Admins invite users with multiple roles and recipients keep every tag", async ({ page, context, browser, browserName }, info) => {
  await signIn(page);
  await page.getByRole("button", { name: "Invite user", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("button", { name: "Create invitation" })).toBeDisabled();
  await expect(dialog.getByRole("checkbox")).toHaveCount(3);
  await dialog.getByRole("checkbox", { name: "Security Analyst", exact: true }).check();
  await dialog.getByRole("checkbox", { name: "Security Leadership", exact: true }).check();
  await dialog.getByLabel("Email address").fill("new-member@example.invalid");
  await dialog.screenshot({ path: info.outputPath("invite-user-desktop.png") });
  let creates = 0;
  let resume!: () => void;
  const held = new Promise<void>((resolve) => { resume = resolve; });
  await page.route("**/api/v1/users/invites", async (route) => {
    if (route.request().method() === "POST") { creates++; await held; }
    await route.continue();
  });
  const createdReply = page.waitForResponse((reply) => reply.url().endsWith("/users/invites") && reply.request().method() === "POST");
  try {
    await dialog.locator("form").evaluate((form: HTMLFormElement) => { form.requestSubmit(); form.requestSubmit(); });
    await expect(dialog.getByLabel("Email address")).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
  } finally { resume(); }
  const reply = await createdReply;
  expect(reply.status()).toBe(201);
  const created = await reply.json();
  expect(created.roles).toEqual(["security_analyst", "security_leadership"]);
  expect(creates).toBe(1);
  await expect(dialog.getByLabel("Invitation link")).toHaveValue(created.accept_url);
  if (browserName === "chromium") await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  else await page.evaluate(() => {
    let copied = "";
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async (text: string) => { copied = text; }, readText: async () => copied }, configurable: true });
  });
  await dialog.getByRole("button", { name: "Copy link", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(created.accept_url);
  expect(await page.evaluate(() => JSON.stringify([localStorage, sessionStorage]))).not.toContain(created.token);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(page.getByLabel("Invitation link")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Invite user", exact: true })).toBeFocused();
  await page.getByRole("button", { name: "Invite user", exact: true }).click();
  await expect(dialog.getByLabel("Email address")).toHaveValue("");
  await expect(dialog.getByRole("checkbox", { checked: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();

  const guest = await browser.newContext({ baseURL: new URL(page.url()).origin, viewport: { width: 390, height: 844 } });
  try {
    const recipient = await guest.newPage();
    const referrers: string[] = [];
    recipient.on("request", (request) => referrers.push(request.headers().referer || ""));
    const document = await recipient.goto(created.accept_url);
    expect(document?.headers()["referrer-policy"]).toBe("no-referrer");
    await expect(recipient.getByRole("heading", { name: "Accept invitation" })).toBeVisible();
    await expect(recipient.getByText("new-member@example.invalid", { exact: true })).toBeVisible();
    await noOverflow(recipient);
    await recipient.screenshot({ path: info.outputPath("accept-invitation-mobile.png"), fullPage: true });
    const pending = await (await page.request.get("/api/v1/users/invites")).json();
    expect(pending.items.some((item: { id: string }) => item.id === created.id)).toBe(true);
    await recipient.getByLabel("Your name").fill("New member");
    await recipient.getByLabel("Password", { exact: true }).fill(password);
    await recipient.getByLabel("Confirm password").fill("different-password");
    await recipient.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(recipient.getByRole("main").getByRole("alert")).toHaveText("Passwords do not match.");
    await recipient.getByLabel("Confirm password").fill(password);
    await recipient.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(recipient).toHaveURL(/\/$/);
    const me = await (await guest.request.get(new URL("/api/v1/auth/me", created.accept_url).href)).json();
    expect(me.user).toMatchObject({ email: "new-member@example.invalid", name: "New member", roles: ["security_analyst", "security_leadership"] });
    expect(referrers.some((value) => value.includes(created.token))).toBe(false);
    expect(await recipient.evaluate(() => JSON.stringify([localStorage, sessionStorage]))).not.toContain(created.token);
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByRole("row").filter({ hasText: "new-member@example.invalid" })).toContainText("Security Leadership");
    await recipient.goto(created.accept_url);
    await expect(recipient.getByRole("main").getByRole("alert")).toContainText("already used");
    await expect(recipient.getByRole("button", { name: "Create account" })).toHaveCount(0);
    await signIn(recipient, "new-member@example.invalid");
    await expect(recipient.getByRole("button", { name: "Invite user", exact: true })).toHaveCount(0);
  } finally { await guest.close(); }
});

test("IT Admins can assign every role, errors are recoverable, and other roles cannot invite", async ({ page }, info) => {
  await signIn(page, "admin@example.invalid");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Invite user", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("checkbox")).toHaveCount(3);
  await dialog.getByRole("checkbox", { name: "Security Analyst", exact: true }).check();
  await dialog.getByLabel("Email address").fill("new-analyst@example.invalid");
  await noOverflow(page);
  await dialog.screenshot({ path: info.outputPath("invite-user-mobile.png") });
  await dialog.getByLabel("Email address").fill("viewer@example.invalid");
  await dialog.getByRole("button", { name: "Create invitation", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("a user with this email already exists");
  await expect(dialog.getByLabel("Email address")).toBeEnabled();
  await dialog.getByLabel("Email address").fill("new-analyst@example.invalid");
  await dialog.getByRole("button", { name: "Create invitation", exact: true }).click();
  await expect(dialog.getByRole("heading", { name: "Invitation created" })).toBeVisible();
  await expect(dialog).toContainText("Security Analyst");
  const headers = { "X-OpenAIDR-CSRF": "1", Origin: new URL(page.url()).origin };
  const elevated = await page.request.post("/api/v1/users/invites", { headers, data: { email: "forged-owner@example.invalid", role: "owner" } });
  expect(elevated.status()).toBe(201);
  for (const role of ["viewer", "analyst"]) {
    await signIn(page, `${role}@example.invalid`);
    await expect(page.getByRole("button", { name: "Invite user", exact: true })).toHaveCount(0);
    expect((await page.request.get("/api/v1/users/invites")).status()).toBe(403);
    expect((await page.request.post("/api/v1/users/invites", { headers, data: { email: "forged-viewer@example.invalid", role: "viewer" } })).status()).toBe(403);
  }
});

test("incomplete, expired, revoked, and unavailable invitations never create accounts", async ({ page, browser }, info) => {
  await signIn(page);
  const revoked = await invitation(page, "revoked@example.invalid");
  const headers = { "X-OpenAIDR-CSRF": "1", Origin: new URL(page.url()).origin };
  expect((await page.request.delete(`/api/v1/users/invites/${revoked.id}`, { headers })).status()).toBe(204);
  const guest = await browser.newContext({ baseURL: new URL(page.url()).origin });
  try {
    const recipient = await guest.newPage();
    for (const url of ["/accept-invite", "/accept-invite?token=invalid", "/accept-invite?token=expired-browser-invitation", revoked.accept_url]) {
      await recipient.goto(new URL(url, page.url()).href);
      await expect(recipient.getByRole("main").getByRole("alert")).toContainText(/incomplete|invalid|expired/);
      await expect(recipient.getByRole("button", { name: "Create account" })).toHaveCount(0);
    }
    const pending = await invitation(page, "revoked-after-preview@example.invalid");
    await recipient.route("**/api/v1/auth/invite?*", (route) => route.abort(), { times: 1 });
    await recipient.goto(pending.accept_url);
    await expect(recipient.getByRole("main").getByRole("alert")).toBeVisible();
    await recipient.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(recipient.getByLabel("Your name")).toBeVisible();
    await recipient.screenshot({ path: info.outputPath("accept-invitation-desktop.png"), fullPage: true });
    await recipient.getByLabel("Your name").fill("Revoked member");
    await recipient.getByLabel("Password", { exact: true }).fill(password);
    await recipient.getByLabel("Confirm password").fill(password);
    expect((await page.request.delete(`/api/v1/users/invites/${pending.id}`, { headers })).status()).toBe(204);
    await recipient.getByRole("button", { name: "Create account", exact: true }).click();
    await expect(recipient.getByRole("main").getByRole("alert")).toContainText("no longer valid");
    await expect(recipient.getByLabel("Password", { exact: true })).toHaveCount(0);
    const users = await (await page.request.get("/api/v1/users")).json();
    expect(users.items.some((user: { email: string }) => user.email.startsWith("revoked"))).toBe(false);
  } finally { await guest.close(); }
});

test("Google workspaces use sign-in instead of accepting a password", async ({ page }) => {
  // The workspace authentication setting is the only simulated environment value.
  await page.route("**/api/v1/auth/config", (route) => route.fulfill({ json: { mode: "cloud_google", password_login: false } }));
  const previewRequests: string[] = [];
  page.on("request", (request) => { if (request.url().includes("/auth/invite?")) previewRequests.push(request.url()); });
  await page.goto("/accept-invite?token=old-invitation");
  await expect(page.getByText("This workspace uses Google sign-in.", { exact: false })).toBeVisible();
  await expect(page.getByLabel("Password", { exact: true })).toHaveCount(0);
  expect(previewRequests).toEqual([]);
  await page.getByRole("link", { name: "Continue to sign in" }).click();
  await expect(page.getByRole("button", { name: "Continue with Google" })).toBeVisible();
});


test("IT Admins edit multiple tags, filter membership, cancel changes, and retain the last admin", async ({ page }, info) => {
  await signIn(page);
  const row = page.getByRole("row").filter({ hasText: "viewer@example.invalid" });
  await row.getByRole("button", { name: "Edit roles" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("checkbox", { name: "Security Leadership", exact: true }).uncheck();
  await expect(dialog.getByRole("button", { name: "Save roles" })).toBeDisabled();
  await dialog.getByRole("checkbox", { name: "IT Admin", exact: true }).check();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(row).not.toContainText("IT Admin");
  await row.getByRole("button", { name: "Edit roles" }).click();
  await dialog.getByRole("checkbox", { name: "IT Admin", exact: true }).check();
  await dialog.getByRole("checkbox", { name: "Security Analyst", exact: true }).check();
  await page.route("**/api/v1/users/*", (route) => route.request().method() === "PATCH"
    ? route.fulfill({ status: 503, json: { error: { message: "Roles were not saved. Retry." } } }) : route.continue(), { times: 1 });
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("Roles were not saved. Retry.");
  await expect(dialog.getByRole("checkbox", { checked: true })).toHaveCount(3);
  await expect(page.getByRole("row", { includeHidden: true }).filter({ hasText: "viewer@example.invalid" })).not.toContainText("IT Admin");
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  for (const role of ["IT Admin", "Security Analyst", "Security Leadership"]) {
    await expect(row).toContainText(role);
    await page.getByRole("combobox", { name: "Filter by role" }).click();
    await page.getByRole("option", { name: role, exact: true }).click();
    await expect(row).toBeVisible();
  }
  await page.getByRole("combobox", { name: "Filter by role" }).click();
  await page.getByRole("option", { name: "All roles", exact: true }).click();
  await expect(page.getByRole("option", { name: "All roles", exact: true })).toBeHidden();
  await page.screenshot({ path: info.outputPath("users-and-roles-desktop.png"), fullPage: true, animations: "disabled" });
  await row.getByRole("button", { name: "Edit roles" }).click();
  await dialog.screenshot({ path: info.outputPath("edit-roles-desktop.png") });
  await page.setViewportSize({ width: 390, height: 600 });
  await noOverflow(page);
  await dialog.getByRole("button", { name: "Cancel" }).scrollIntoViewIfNeeded();
  await dialog.screenshot({ path: info.outputPath("edit-roles-mobile.png") });
  await dialog.getByRole("checkbox", { name: "IT Admin", exact: true }).uncheck();
  await dialog.getByRole("checkbox", { name: "Security Analyst", exact: true }).uncheck();
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await noOverflow(page);
  const headers = { "X-OpenAIDR-CSRF": "1", Origin: new URL(page.url()).origin };
  const { items } = await (await page.request.get("/api/v1/users")).json();
  const admin = items.find((user: { email: string }) => user.email === "admin@example.invalid");
  expect((await page.request.patch(`/api/v1/users/${admin.id}`, { headers, data: { roles: ["security_leadership"] } })).status()).toBe(200);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByRole("row").filter({ hasText: "owner@example.invalid" }).getByRole("button", { name: "Edit roles" }).click();
  await expect(dialog.getByRole("checkbox", { name: "IT Admin", exact: true })).toBeDisabled();
  await expect(dialog).toContainText("last active IT Admin");
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect((await page.request.patch(`/api/v1/users/${admin.id}`, { headers, data: { roles: ["it_admin"] } })).status()).toBe(200);
});

test("self-removal immediately hides administration and blocks direct access", async ({ page }) => {
  await signIn(page, "admin@example.invalid");
  await page.getByRole("row").filter({ hasText: "admin@example.invalid" }).getByRole("button", { name: "Edit roles" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("checkbox", { name: "IT Admin", exact: true }).uncheck();
  await dialog.getByRole("checkbox", { name: "Security Leadership", exact: true }).check();
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(page.getByRole("table")).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Workspace navigation" }).getByText("Administration", { exact: true })).toHaveCount(0);
  expect((await page.request.get("/api/v1/users")).status()).toBe(403);
  await page.goto("/evidence");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await signIn(page);
  const { items } = await (await page.request.get("/api/v1/users")).json();
  const admin = items.find((user: { email: string }) => user.email === "admin@example.invalid");
  expect((await page.request.patch(`/api/v1/users/${admin.id}`, {
    headers: { "X-OpenAIDR-CSRF": "1", Origin: new URL(page.url()).origin }, data: { roles: ["it_admin"] },
  })).status()).toBe(200);
});

test("navigation combines all seven role selections and refreshes after external revocation", async ({ page, browser }) => {
  await signIn(page);
  const { items } = await (await page.request.get("/api/v1/users")).json();
  const target = items.find((user: { email: string }) => user.email === "viewer@example.invalid");
  const headers = { "X-OpenAIDR-CSRF": "1", Origin: new URL(page.url()).origin };
  const context = await browser.newContext({ baseURL: new URL(page.url()).origin });
  const member = await context.newPage();
  await member.clock.install();
  try {
    await signIn(member, "viewer@example.invalid");
    for (const roles of [
      ["it_admin"], ["security_analyst"], ["security_leadership"],
      ["it_admin", "security_analyst"], ["it_admin", "security_leadership"],
      ["security_analyst", "security_leadership"], ["it_admin", "security_analyst", "security_leadership"],
    ]) {
      expect((await page.request.patch(`/api/v1/users/${target.id}`, { headers, data: { roles } })).status()).toBe(200);
      await member.goto("/");
      const nav = member.getByRole("navigation", { name: "Workspace navigation" });
      await expect(nav.getByRole("link", { name: "AI Apps", exact: true })).toBeVisible();
      await expect(nav.getByRole("link", { name: "Users and Roles", exact: true })).toHaveCount(roles.includes("it_admin") ? 1 : 0);
      await expect(nav.getByRole("link", { name: "Evidence Search", exact: true })).toHaveCount(roles.includes("security_analyst") ? 1 : 0);
      await expect(nav.getByRole("link", { name: "Live Activity", exact: true })).toHaveCount(0);
      await expect(nav.getByRole("link", { name: "Live Guardrail", exact: true })).toHaveCount(roles.includes("security_analyst") ? 1 : 0);
      await expect(nav.getByRole("link", { name: "AI Agent Costs", exact: true })).toHaveCount(roles.includes("it_admin") || roles.includes("security_leadership") ? 1 : 0);
    }
    await member.goto("/administration/users");
    await expect(member.getByRole("table")).toBeVisible();
    expect((await page.request.patch(`/api/v1/users/${target.id}`, { headers, data: { roles: ["security_leadership"] } })).status()).toBe(200);
    await member.clock.fastForward(61_000);
    await expect(member.getByText("Access restricted", { exact: true })).toBeVisible();
    await expect(member.getByRole("table")).toHaveCount(0);
    const requests: string[] = [];
    member.on("request", (request) => requests.push(new URL(request.url()).pathname));
    await member.goto("/evidence");
    await expect(member.getByText("Access restricted", { exact: true })).toBeVisible();
    expect(requests).not.toContain("/api/v1/events");
    await member.goto("/activity");
    await expect(member.getByText("Access restricted", { exact: true })).toBeVisible();
    expect(requests).not.toContain("/api/v1/events/live");
  } finally {
    await page.request.patch(`/api/v1/users/${target.id}`, { headers, data: { roles: ["security_leadership"] } });
    await context.close();
  }
});
