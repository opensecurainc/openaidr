import { test, expect } from "@playwright/test";

const user = {
  id: "00000000-0000-7000-8000-000000000001",
  name: "Test operator",
  email: "operator@example.invalid",
  roles: ["it_admin", "security_analyst", "security_leadership"],
  tenant: { id: "00000000-0000-7000-8000-000000000002", name: "Test workspace", slug: "test" },
};

const capabilities = {
  url_reputation: "configured", package_vulnerabilities: "configured", guardrail: "configured", application_research: "configured",
  assistant: "configured", rule_generation: "configured", overview_summaries: "configured", session_summaries: "configured",
  skill_assessment: "configured", investigations: "configured",
};
const verification = (origin: string) => ({origin, tenant_id: user.tenant.id, build: "2026.10.29+1234567",
  checked_at: "2026-10-29T20:30:00Z", capabilities});

test("production-only settings verify the connection and replace its key", async ({ page }, info) => {
  const origin = "https://api.opensecura.ai", secret = "synthetic-production-key";
  const writes: unknown[] = [];
  let version = 0;
  const routing = () => ({ mode: "intelligence", origin, version, tenant_id: user.tenant.id,
    credential_configured: true, credential_management: true, trust: "system",
    environments: [{ origin, label: "Production", credential_configured: true, saved_key: version > 0 }] });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") return route.fulfill({ json: { user } });
    if (path === "/api/v1/settings/model-keys") return route.fulfill({ json: { routing: routing() } });
    if (path === "/api/v1/settings/intelligence/check") return route.fulfill({ json: verification(origin) });
    if (path === "/api/v1/settings/intelligence/key") {
      writes.push(route.request().postDataJSON()); version++;
      return route.fulfill({ json: { routing: routing(), verification: verification(origin) } });
    }
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Intelligence service" });
  await expect(card.getByRole("group")).toHaveCount(1);
  await expect(card.getByRole("group", { name: "Production environment" }).getByText("Active", { exact: true })).toBeVisible();
  await card.getByRole("button", { name: "Check connection", exact: true }).click();
  await expect(card.getByText(/Service authenticated for Production/)).toBeVisible();
  await card.getByRole("button", { name: "Replace Production key" }).click();
  await card.getByLabel("Production API key").fill(secret);
  await card.getByRole("button", { name: "Verify and update key" }).click();
  await expect(card.getByLabel("Production API key")).toHaveCount(0);
  expect(writes).toEqual([{ origin, api_key: secret, version: 0, activate: true }]);
  await expect(card.getByLabel("Intelligence service origin")).toHaveText(origin);
  await card.evaluate((element) => element.scrollIntoView({ block: "center" }));
  await card.screenshot({ path: info.outputPath("production-only.png"), animations: "disabled" });
});

test("switching an available environment verifies it and preserves the active environment on failure", async ({ page }) => {
  const testOrigin = "https://intelligence.example.test", production = "https://api.opensecura.ai";
  let origin = testOrigin, version = 0, failed = false;
  let release: (() => void) | undefined;
  const writes: unknown[] = [];
  const routing = () => ({ mode: "intelligence", origin, version, credential_configured: true, trust: "system",
    capability_status: "unverified", environments: [{ origin: testOrigin, label: "Test", credential_configured: true },
      { origin: production, label: "Production", credential_configured: true }] });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") return route.fulfill({ json: { user } });
    if (path === "/api/v1/settings/model-keys") return route.fulfill({ json: { routing: routing() } });
    if (path === "/api/v1/settings/intelligence") {
      const body = route.request().postDataJSON(); writes.push(body);
      expect(route.request().method()).toBe("PUT");
      if (failed) return route.fulfill({ status: 503, json: { error: { message: "Unable to verify Test. Check the service connection and try again." } } });
      await new Promise<void>((resolve) => { release = resolve; });
      origin = body.origin; version++;
      return route.fulfill({ json: { routing: routing(), verification: verification(origin) } });
    }
    if (path === "/api/v1/settings/intelligence/check") return route.fulfill({ json: verification(origin) });
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Intelligence service" });
  const testGroup = card.getByRole("group", { name: "Test environment" });
  const productionGroup = card.getByRole("group", { name: "Production environment" });
  const checkButton = card.getByRole("button", { name: "Check connection", exact: true });
  await expect(testGroup.getByText("Active", {exact: true})).toBeVisible();
  await checkButton.click();
  await expect(card.getByText(/Service authenticated for Test/)).toBeVisible();
  await card.getByRole("button", { name: "Use Production" }).click();
  await expect(card.getByText("Verifying service...")).toBeVisible();
  await expect(card.getByRole("button", { name: "Use Production" })).toBeDisabled();
  await expect(checkButton).toBeDisabled();
  release!();
  await expect(productionGroup.getByText("Active", {exact: true})).toBeVisible();
  await expect(testGroup.getByText("Available", {exact: true})).toBeVisible();
  await expect(card.getByText(/Service authenticated for Production/)).toBeVisible();
  await expect(card.getByText(/Service authenticated for Test/)).toHaveCount(0);
  expect(writes).toEqual([{ origin: production, version: 0 }]);
  await page.reload();
  await expect(productionGroup.getByText("Active", {exact: true})).toBeVisible();
  failed = true;
  await card.getByRole("button", { name: "Use Test" }).click();
  await expect(card.getByRole("alert")).toContainText("Unable to switch to Test");
  await expect(productionGroup.getByText("Active", {exact: true})).toBeVisible();
  await expect(card.getByLabel("Intelligence service origin")).toHaveText(production);
  failed = false;
  await card.getByRole("button", { name: "Use Test" }).click();
  await expect(card.getByText("Verifying service...")).toBeVisible();
  release!();
  await expect(testGroup.getByText("Active", {exact: true})).toBeVisible();
  await expect(card.getByRole("alert")).toHaveCount(0);
  expect(writes).toEqual([{ origin: production, version: 0 }, { origin: testOrigin, version: 1 }, { origin: testOrigin, version: 1 }]);
});

for (const profile of ["local", "hosted"] as const) {
  test(`${profile} Intelligence checks show capability limits without provider key controls`, async ({ page, browserName }) => {
    const origin = profile === "local" ? `https://${"internal-".repeat(5)}intelligence.example:8443` : "https://api.opensecura.ai";
    let available = true;
    let responseOrigin = origin;
    const checks: string[] = [];
    const writes: string[] = [];
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/v1/auth/me") return route.fulfill({ json: { user } });
      if (path === "/api/v1/settings/intelligence/check") {
        checks.push(route.request().method());
        expect(route.request().postDataJSON()).toEqual({});
        return available ? route.fulfill({ json: { origin: responseOrigin, build: "2026.10.27+1234567", checked_at: "2026-10-27T06:00:00Z",
          provider_access: "not_checked", investigation_worker: "not_checked", capabilities: {
            url_reputation: profile === "local" ? "provider_unconfigured" : "configured", package_vulnerabilities: "configured",
            guardrail: "configured", application_research: "configured", assistant: "configured", rule_generation: "configured",
            overview_summaries: "configured", session_summaries: "configured", skill_assessment: "configured",
            investigations: profile === "local" ? "runtime_unavailable" : "configured",
          } } }) : route.fulfill({ status: 503, json: { error: { message: "Unable to verify the selected Intelligence service. Check its connection and tenant credential." } } });
      }
      if (path === "/api/v1/settings/model-keys") {
        if (route.request().method() !== "GET") writes.push(route.request().method());
        return route.fulfill({ json: {
          guardrail: { configured: true, masked: "retained-key********", updated_at: null },
          detection: { configured: false, masked: "", updated_at: null },
          sync: { enabled: true, active: false, available: true, version: 2, last_synced_at: null, last_error: "" },
          routing: { mode: "intelligence", origin, trust: profile === "local" ? "private_ca" : "system",
            credential_configured: true, capability_status: "unverified" },
        } });
      }
      return route.fulfill({ status: 404, json: {} });
    });
    await page.goto("/administration/settings");
    const card = page.getByRole("region", { name: "Intelligence service" });
    await expect(card).toBeVisible();
    await expect(card.getByLabel("Intelligence service origin")).toHaveText(origin);
    await expect(card.getByText("Capability availability has not been verified.")).toBeVisible();
    await expect(card.getByText(profile === "local" ? /Private certificate authority\./ : /System certificate authorities\./)).toBeVisible();
    await expect(card.getByLabel("New API key")).toHaveCount(0);
    await expect(card.getByRole("radiogroup")).toHaveCount(0);
    await expect(card.getByText(/Provider usage charges may apply/)).toHaveCount(0);
    await expect(card.getByText(/The service manages provider credentials/)).toBeVisible();
    expect(checks).toEqual([]);
    await card.getByRole("button", { name: "Check connection", exact: true }).click();
    await expect(card.getByRole("status")).toContainText("Service authenticated. Checked");
    await card.getByText("Service details", {exact: true}).click();
    await expect(card.getByText("Service build: 2026.10.27+1234567")).toBeVisible();
    const capabilities = card.getByLabel("Intelligence capability configuration");
    await expect(capabilities.locator("dt")).toHaveCount(10);
    await expect(capabilities.getByText("Guardrail", { exact: true })).toBeVisible();
    await expect(card.getByText(/Provider access, quota and investigation worker liveness are not tested/)).toBeVisible();
    if (profile === "local") {
      await expect(capabilities.getByText("Provider not configured")).toBeVisible();
      await expect(capabilities.getByText("Runtime unavailable")).toBeVisible();
    } else {
      await expect(capabilities.getByText("Configured", { exact: true })).toHaveCount(10);
    }
    for (const width of [1440, 768, 400]) {
      await page.setViewportSize({ width, height: 720 });
      await card.scrollIntoViewIfNeeded();
      expect(await card.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
      const bounds = await card.boundingBox();
      expect(bounds!.x).toBeGreaterThanOrEqual(0);
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
      const button = card.getByRole("button", { name: "Check connection", exact: true });
      await button.scrollIntoViewIfNeeded();
      await expect(button).toBeInViewport();
      await capabilities.getByText("Investigations", { exact: true }).scrollIntoViewIfNeeded();
      await expect(capabilities.getByText("Investigations", { exact: true })).toBeInViewport();
    }
    if (process.env.OPENAIDR_MODEL_SERVICE_SCREENSHOTS) {
      await page.setViewportSize({ width: 1440, height: 1080 });
      await card.evaluate((element) => {
        element.scrollIntoView({ block: "start" });
        window.scrollBy(0, -72);
      });
      await card.screenshot({ path: `${process.env.OPENAIDR_MODEL_SERVICE_SCREENSHOTS}/${profile}-${browserName}.png` });
    }
    available = false;
    await card.getByRole("button", { name: "Check connection", exact: true }).click();
    await expect(card.getByText(/Unable to verify the selected Intelligence service/)).toBeVisible();
    await expect(card.getByLabel("Intelligence capability configuration")).toHaveCount(0);
    await expect(card.getByText(/Service authenticated/)).toHaveCount(0);
    await expect(card.getByLabel("New API key")).toHaveCount(0);
    available = true;
    responseOrigin = "https://changed.intelligence.example";
    await card.getByRole("button", { name: "Check connection", exact: true }).click();
    await expect(card.getByText("The service connection changed. Reload Settings before checking again.")).toBeVisible();
    await expect(card.getByLabel("Intelligence capability configuration")).toHaveCount(0);
    expect(checks).toEqual(["POST", "POST", "POST"]);
    expect(writes).toEqual([]);
  });
}

test("an unconfigured service shows an actionable status without provider controls", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") return route.fulfill({ json: { user } });
    if (path === "/api/v1/settings/model-keys") return route.fulfill({ json: {
      guardrail: { configured: false, masked: "", updated_at: null },
      detection: { configured: false, masked: "", updated_at: null },
      routing: { mode: "intelligence", origin: "", trust: "system", credential_configured: false, capability_status: "unavailable" },
    } });
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Intelligence service" });
  await expect(card.getByText("The Intelligence service is unavailable for this workspace. Ask an administrator to configure its connection.")).toBeVisible();
  await expect(card.getByLabel("New API key")).toHaveCount(0);
  await expect(card.getByRole("radiogroup")).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Check connection", exact: true })).toHaveCount(0);
});

test("a viewer cannot see the service configuration", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") return route.fulfill({ json: { user: { ...user, roles: ["security_leadership"] } } });
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto("/administration/settings");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Intelligence service" })).toHaveCount(0);
});

test("connect guides key creation, retains failed input and verifies and activates in one action", async ({ page }, info) => {
  const testOrigin = "https://intelligence.example.test", production = "https://api.opensecura.ai";
  let selected = testOrigin, version = 0, saved = false, attempts = 0, checks = 0;
  let release: (() => void) | undefined;
  const secret = "oasc_" + "c".repeat(32) + "." + "d".repeat(43);
  const routing = () => ({ mode: "intelligence", origin: selected, version, tenant_id: user.tenant.id,
    credential_management: true, credential_configured: true, trust: "system", capability_status: "unverified",
    environments: [{ origin: testOrigin, label: "Test", credential_configured: true, saved_key: false },
      { origin: production, label: "Production", credential_configured: saved, saved_key: saved }] });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") return route.fulfill({ json: { user } });
    if (path === "/api/v1/settings/model-keys") return route.fulfill({ json: { routing: routing() } });
    if (path === "/api/v1/settings/intelligence/key") {
      attempts++;
      const body = route.request().postDataJSON();
      expect(body.origin).toBe(production); expect(body.version).toBe(version); expect(body.activate).toBe(true);
      if (body.api_key !== secret) return route.fulfill({ status: 400, json: { error: { message: "This is a legacy key. Create a new key for current OpenAIDR." } } });
      await new Promise<void>((resolve) => { release = resolve; });
      saved = true; selected = production; version++;
      return route.fulfill({ json: { routing: routing(), verification: verification(production) } });
    }
    if (path === "/api/v1/settings/intelligence/check") { checks++; return route.fulfill({json: verification(selected)}); }
    if (path === "/api/v1/settings/intelligence") throw new Error("Connect must not need a separate activation request");
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Intelligence service" });
  const productionGroup = card.getByRole("group", {name: "Production environment"});
  await expect(productionGroup.getByText("Not connected", {exact: true})).toBeVisible();
  await expect(card.getByLabel("Production API key", {exact: true})).toHaveCount(0);
  await card.getByRole("button", {name: "Connect Production", exact: true}).click();
  const input = card.getByLabel("Production API key", { exact: true });
  await expect(input).toHaveAttribute("type", "password");
  await expect(card.getByRole("link", {name: "Create Production key (opens in a new tab)"})).toHaveAttribute("href", production + "/admin/?tenant_id=" + user.tenant.id);
  await input.fill("oati_legacy");
  await card.getByRole("button", {name: "Verify and use Production"}).click();
  await expect(card.getByRole("alert")).toContainText("legacy key");
  await expect(input).toHaveValue("oati_legacy");
  await expect(card.getByRole("group", {name: "Test environment"}).getByText("Active", {exact: true})).toBeVisible();
  await input.fill(secret);
  await expect(card.getByRole("alert")).toHaveCount(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({width, height: 760});
    await card.getByRole("button", {name: "Verify and use Production"}).scrollIntoViewIfNeeded();
    await expect(card.getByRole("button", {name: "Verify and use Production"})).toBeInViewport();
    expect(await card.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.setViewportSize({width, height: Math.ceil((await card.boundingBox())!.height) + 220});
    await card.evaluate(element => element.scrollIntoView({block: "center"}));
    await card.screenshot({path: info.outputPath(`connect-production-${width}.png`), animations: "disabled"});
  }
  await card.getByRole("button", {name: "Verify and use Production"}).click();
  await expect(card.getByRole("button", {name: "Verifying connection..."})).toBeDisabled();
  await expect(input).toBeDisabled();
  release!();
  await expect(card.getByText("Production is active. New requests use this environment.")).toBeVisible();
  await expect(productionGroup.getByText("Active", {exact: true})).toBeVisible();
  await expect(card.getByText(/Service authenticated for Production/)).toBeVisible();
  await expect(input).toHaveCount(0);
  await page.setViewportSize({width: 390, height: Math.ceil((await card.boundingBox())!.height) + 220});
  await card.evaluate(element => element.scrollIntoView({block: "center"}));
  await card.screenshot({path: info.outputPath("production-connected.png"), animations: "disabled"});
  await page.reload();
  await expect(productionGroup.getByText("Active", {exact: true})).toBeVisible();
  await card.getByRole("button", {name: "Replace Production key"}).click();
  await expect(input).toHaveValue("");
  await expect(card.getByRole("button", {name: "Verify and update key"})).toBeDisabled();
  await input.fill("cancelled-key");
  await card.getByRole("button", {name: "Cancel", exact: true}).click();
  await card.getByRole("button", {name: "Replace Production key"}).click();
  await expect(input).toHaveValue("");
  expect(await page.evaluate(() => JSON.stringify([localStorage, sessionStorage]))).not.toContain(secret);
  expect(attempts).toBe(2); expect(checks).toBe(0);
});
