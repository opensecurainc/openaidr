import { test, expect } from "@playwright/test";

test("benchmark pages are absent while detection navigation remains available", async ({ page }, info) => {
  const benchmarkRequests: string[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path.includes("benchmarks")) benchmarkRequests.push(path);
    if (path === "auth/me") {
      return route.fulfill({ json: { user: {
        id: "operator", name: "Test operator", email: "operator@example.invalid",
        roles: ["it_admin", "security_analyst", "security_leadership"],
        tenant: { id: "tenant", name: "Test tenant", slug: "test" },
      } } });
    }
    if (path === "detections/rules") {
      return route.fulfill({ json: { items: [] } });
    }
    if (path === "response/session-detection") {
      return route.fulfill({ json: {
        enabled: false, version: 1, detector_config_version: 1, selection_policy: "risk_budget",
        investigation_percent: 1, history_days: 30, action_risk_threshold: 60,
        urgent_risk_threshold: 90, session_high_risk_actions: 3, user_high_risk_actions: 5,
      } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto("/detection-rules");
  await expect(page.locator("main h1")).toHaveText("Detection Rules");
  const desktop = page.getByRole("navigation", { name: "Workspace navigation" });
  await expect(desktop.getByRole("link", { name: "Detection Queue", exact: true })).toBeVisible();
  await expect(desktop.getByRole("link", { name: "Live Guardrail", exact: true })).toBeVisible();
  await expect(desktop.locator('a[href="/guardrail/benchmarks"], a[href="/detection-quality"]')).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: "Enable session investigations" })).toBeVisible();
  await expect(page.getByRole("alert").filter({ hasText: "Unable to load data" })).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("benchmark-pages-removed-desktop.png"), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  const mobile = page.getByRole("dialog", { name: "Workspace navigation" });
  await expect(mobile.getByRole("link", { name: "Detection Rules", exact: true })).toBeVisible();
  await expect(mobile.locator('a[href="/guardrail/benchmarks"], a[href="/detection-quality"]')).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("benchmark-pages-removed-mobile.png") });
  await page.keyboard.press("Escape");
  await expect(mobile).toBeHidden();

  for (const path of ["/guardrail/benchmarks", "/detection-quality"]) {
    const response = await page.goto(path);
    expect(response?.status()).toBe(404);
    await expect(page.getByRole("heading", { name: "404", exact: true })).toBeVisible();
  }
  expect(benchmarkRequests).toEqual([]);
});
