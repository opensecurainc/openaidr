// Exercise a disposable local deployment. Credentials stay in the environment.
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium, webkit, expect } from "@playwright/test";

const origin = process.env.OPENAIDR_TEST_URL || "http://localhost:8080";
const password = process.env.OPENAIDR_ADMIN_PASSWORD;
if (!password) throw new Error("Set OPENAIDR_ADMIN_PASSWORD for a disposable local workspace");
// Every page the navigation lists.
const paths = ["/", "/ai-inventory", "/ai-supply-chain", "/ai-skills", "/gateways/overview",
  "/user-risk", "/detections", "/evidence", "/detection-rules",
  "/guardrail/live", "/guardrail/history", "/guardrail/configuration", "/company-knowledge",
  "/costs/agents", "/costs/openaidr",
  "/administration/app", "/administration/server", "/administration/enrollment", "/administration/integrations",
  "/audit-logs", "/administration/users", "/administration/settings"];
// A fresh workspace has no Intelligence service, so model-backed pages say so.
const expectedAlert = /Intelligence|Assistant connection|not configured|unavailable|no model/i;
const screenshotDir = process.env.OPENAIDR_TEST_SCREENSHOT_DIR;
if (screenshotDir) mkdirSync(screenshotDir, { recursive: true });
for (const [name, engine] of [["chromium", chromium], ["webkit", webkit]]) {
  const browser = await engine.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1080 } });
    const errors = [], failedApis = [], unavailable = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("response", response => {
      const path = new URL(response.url()).pathname;
      if (!response.url().startsWith(origin + "/api/v1/")) return;
      // 503 is how model-backed routes report a missing Intelligence service.
      if (response.status() === 503) unavailable.push(path);
      else if (response.status() >= 500) failedApis.push(`${response.status()} ${path}`);
    });
    await page.goto(origin + "/login");
    await page.getByLabel("Email address").fill(process.env.OPENAIDR_ADMIN_EMAIL || "admin@localhost");
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.waitForURL(origin + "/");
    async function navigate(path) {
      if (new URL(page.url()).pathname !== path) {
        const link = page.locator(`nav a[href="${path}"]`).first();
        if (await link.count()) {
          await link.click();
          await page.waitForURL(origin + path);
        } else {
          await page.goto(origin + path);
        }
      }
      // Live pages keep polling, so wait for the page to settle instead of network idle.
      await page.waitForLoadState("domcontentloaded");
      await page.locator("main").waitFor();
      await page.waitForTimeout(1500);
    }
    async function unexpectedAlerts() {
      const texts = await page.locator('main [role="alert"]').allInnerTexts();
      return texts.filter(text => !expectedAlert.test(text));
    }
    async function screenshot(path, file) {
      if (name !== "chromium" || !screenshotDir) return;
      await navigate(path);
      await page.screenshot({ path: join(screenshotDir, file), fullPage: true });
    }
    for (const path of paths) {
      await navigate(path);
      await expect(page.locator("main")).toBeVisible();
      assert.deepEqual(await unexpectedAlerts(), [], path);
      console.log(`${name}: ${path}`);
    }

    // Hook modes and manual rules live in Guardrail Configuration; Live Guardrail shows decisions only.
    await navigate("/guardrail/live");
    assert.equal(await page.getByRole("radio", { name: "Enforce", exact: true }).count(), 0, "live guardrail hook mode");
    await navigate("/guardrail/configuration");
    await page.getByRole("radio", { name: "Enforce", exact: true }).click();
    await expect(page.getByText("Apply backend decisions at supported hooks.", { exact: true })).toBeVisible();
    await page.getByRole("radio", { name: "Shadow", exact: true }).click();
    await expect(page.getByText("Record decisions and allow actions.", { exact: true })).toBeVisible();
    // Manual rules: replace the policy through its API, then read it back in the Fixed rules table.
    const current = await (await page.request.get(origin + "/api/v1/response/policy")).json();
    assert.ok(Array.isArray(current.rules), "policy rules are readable");
    const ruleName = `Browser verification ${name}`;
    const ruleId = `browser-verification-${name}`;
    // Replace the rule from an earlier run so repeated checks do not accumulate rules or collide on ids.
    const rules = current.rules.filter(rule => rule.id !== ruleId);
    rules.push({ id: ruleId, name: ruleName, enabled: true, action: "deny", reason: "Browser verification rule",
      match: { kinds: ["command"], command_regex: `^echo browser-verification-${name}$` } });
    const saved = await page.request.put(origin + "/api/v1/response/policy",
      { data: { rules }, headers: { "X-OpenAIDR-CSRF": "1", Origin: origin } });
    assert.equal(saved.status(), 200, "policy save");
    await navigate("/ai-inventory");
    await navigate("/guardrail/configuration");
    await expect(page.getByText(ruleName, { exact: true })).toBeVisible();
    assert.deepEqual(await unexpectedAlerts(), [], "rule save");

    await navigate("/administration/enrollment");
    await page.getByRole("button", { name: "Create enrollment link", exact: true }).first().click();
    await page.getByLabel("Label (optional)").fill(`Browser verification ${name}`);
    await page.getByRole("dialog").getByRole("button", { name: "Create enrollment link", exact: true }).click();
    await expect(page.getByLabel("Enrollment link", { exact: true })).toHaveValue(/\/enroll#/);
    await page.getByRole("button", { name: "Done", exact: true }).click();
    await navigate("/administration/settings");
    await expect(page.getByRole("heading", { name: "Intelligence service" })).toBeVisible();

    await screenshot("/", "overview.png");
    await screenshot("/detections", "detections.png");
    await screenshot("/guardrail/configuration", "guardrail-configuration.png");
    await screenshot("/administration/settings", "administration-settings.png");
    await screenshot("/administration/enrollment", "administration-enrollment.png");

    await navigate("/costs/agents");
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(1000);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "mobile page overflow");
    assert.deepEqual(errors, []);
    assert.deepEqual(failedApis, []);
    const sorted = [...new Set(unavailable)].sort();
    console.log(`${name}: all ${paths.length} pages, hook modes, manual rule save, enrollment, and mobile layout passed; ` +
      `${sorted.length} routes reported the Intelligence service as unavailable${sorted.length ? ": " + sorted.join(", ") : ""}`);
  } finally { await browser.close(); }
}
