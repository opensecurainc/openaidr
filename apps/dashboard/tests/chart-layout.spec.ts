import { test as base, expect, type Locator } from "@playwright/test";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mockChartData } from "./fixtures/chart-layout";

export type ChartOptions = { zoom: number; zoomMode: "browser" | "css"; scrollbar: number };

const test = base.extend<ChartOptions & {
  resizeWindow: (width: number) => Promise<void>;
  openPage: (url: string) => Promise<void>;
}>({
  zoom: [1.5, { option: true }],
  zoomMode: ["css", { option: true }],
  scrollbar: [15, { option: true }],
  context: async ({ playwright, browserName, baseURL, zoom, zoomMode }, use) => {
    expect(["chromium", "webkit"]).toContain(browserName);
    if (browserName === "webkit") {
      const browser = await playwright.webkit.launch();
      const context = await browser.newContext({ baseURL });
      try { await use(context); } finally { await browser.close(); }
      return;
    }
    // A fresh Chrome profile sets actual browser zoom, not CSS or pinch zoom.
    // Chromium stores zoom as log(factor) / log(1.2), under the default partition.
    const profile = await mkdtemp(path.join(tmpdir(), "openaidr-chart-"));
    await mkdir(path.join(profile, "Default"));
    await writeFile(path.join(profile, "Default", "Preferences"), JSON.stringify({
      partition: { default_zoom_level: { x: zoomMode === "browser" ? Math.log(zoom) / Math.log(1.2) : 0 } },
    }));
    try {
      const context = await playwright.chromium.launchPersistentContext(profile, {
        channel: "chromium", baseURL, viewport: null, headless: true,
        // Playwright's default hides the scrollbars that caused the regression.
        ignoreDefaultArgs: ["--hide-scrollbars"],
        args: ["--window-size=1440,900", "--force-device-scale-factor=1"],
      });
      // The test's page fixture opens its own tab.
      await context.pages()[0].close();
      try { await use(context); } finally { await context.close(); }
    } finally {
      await rm(profile, { recursive: true, force: true });
    }
  },
  resizeWindow: async ({ page, browserName }, use) => {
    if (browserName === "webkit") {
      await use(async (width) => { await page.setViewportSize({ width, height: 900 }); });
      return;
    }
    // Resizing the real window preserves browser zoom. Viewport emulation does not.
    const session = await page.context().newCDPSession(page);
    const { windowId } = await session.send("Browser.getWindowForTarget");
    await use(async (width) => {
      await session.send("Browser.setWindowBounds", { windowId, bounds: { width, height: 900 } });
      await expect.poll(() => page.evaluate(() => outerWidth)).toBe(width);
    });
    await session.detach();
  },
  openPage: async ({ page, browserName, zoom, zoomMode, scrollbar }, use, info) => {
    await mockChartData(page);
    await page.addInitScript(({ scrollbar, cssZoom }) => {
      document.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.textContent = `::-webkit-scrollbar { width: ${scrollbar}px; height: ${scrollbar}px; }` +
          (cssZoom ? `body { zoom: ${cssZoom}; }` : "");
        document.head.append(style);
      });
    }, { scrollbar, cssZoom: zoomMode === "css" ? zoom : 0 });
    await use(async (url) => {
      await page.goto(url);
      // Check the browser itself before trusting a passing layout test.
      const environment = await page.evaluate(() => {
        const probe = document.createElement("div");
        probe.style.cssText = "position:fixed;width:100px;height:100px;overflow:scroll;";
        document.body.append(probe);
        const gutter = probe.offsetWidth - probe.clientWidth;
        probe.remove();
        return { platform: navigator.platform, dpr: devicePixelRatio, cssZoom: getComputedStyle(document.body).zoom, gutter, userAgent: navigator.userAgent };
      });
      await info.attach("browser-environment", { body: JSON.stringify({ ...environment, browserName, zoom, zoomMode, scrollbar }), contentType: "application/json" });
      if (browserName === "chromium") expect(environment.dpr).toBeCloseTo(zoomMode === "browser" ? zoom : 1, 2);
      expect(Number(environment.cssZoom)).toBe(zoomMode === "css" ? zoom : 1);
      if (scrollbar === 0) expect(environment.gutter).toBe(0);
      else expect(environment.gutter).toBeGreaterThan(0);
    });
  },
});

async function expectStable(charts: Locator) {
  const frames = await charts.evaluateAll(async (elements) => {
    const nodes = new Set<Element>();
    for (const element of elements) {
      // Include scrollable ancestors so a stable SVG cannot conceal a moving card.
      for (let node: Element | null = element; node; node = node.parentElement) nodes.add(node);
    }
    const frames = [];
    for (let frame = 0; frame < 90; frame++) {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      if (frame < 30) continue;
      frames.push([...nodes].map((node) => {
        const box = node.getBoundingClientRect();
        return [box.x, box.y, box.width, box.height, node.clientWidth, node.clientHeight, node.scrollWidth, node.scrollHeight];
      }));
    }
    return frames;
  });
  const layouts = [...new Set(frames.map((frame) => JSON.stringify(frame)))];
  if (layouts.length > 1) await test.info().attach("unstable-layout", {
    body: JSON.stringify(layouts.slice(0, 5).map((layout) => JSON.parse(layout))), contentType: "application/json",
  });
  expect(layouts.length, "Layout must settle and stay fixed across consecutive frames").toBe(1);
}

for (const [url, count] of [
  ["/guardrail/history", 4],
  ["/administration/app", 3], // Sensor CPU, memory, and telemetry activity.
  ["/administration/server", 5], // CPU, memory, disk, disk I/O, and CPU by service.
  ["/costs/agents", 1],
  ["/costs/openaidr", 1],
] as const) {
  test(`${url} charts stay stable when resized`, async ({ page, openPage, resizeWindow }, info) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await openPage(url);
    const charts = page.locator("main .recharts-surface");
    await expect(charts).toHaveCount(count);
    await page.evaluate(() => document.fonts.ready);
    for (const width of [1920, 1440, 1365, 800]) {
      await test.step(`${width}px window`, async () => {
        await resizeWindow(width);
        await expectStable(charts);
        const overflow = await charts.evaluateAll((elements) => elements.flatMap((element, index) => {
          const box = element.getBoundingClientRect();
          const issues: string[] = [];
          if (box.width <= 0 || box.height <= 0) issues.push(`Chart ${index} is empty`);
          if (!element.querySelector(".recharts-line-curve, .recharts-area-area, .recharts-bar-rectangle path"))
            issues.push(`Chart ${index} has no plotted data`);
          if (box.left < -1 || box.right > innerWidth + 1) issues.push(`Chart ${index} extends outside the viewport`);
          for (let node = element.parentElement; node; node = node.parentElement) {
            const css = getComputedStyle(node);
            if (/(auto|scroll)/.test(css.overflowX) && node.scrollWidth > node.clientWidth + 1)
              issues.push(`Chart ${index} causes horizontal overflow in ${node.className}`);
          }
          return issues;
        }));
        expect(overflow).toEqual([]);
      });
    }
    expect(errors).toEqual([]);
    await page.screenshot({ path: info.outputPath("charts.png"), fullPage: true });
  });
}

for (const url of ["/", "/guardrail/live"]) {
test(`${url} activity flow stays stable and its horizontal scrolling remains usable`, async ({ page, openPage, resizeWindow }, info) => {
  await openPage(url);
  const diagram = page.getByRole("region", { name: "Activity flow diagram", exact: true });
  await expect(diagram.locator('[data-slot="flow-node"]').first()).toBeVisible();
  await expect(diagram.locator("svg path").first()).toBeAttached();
  await page.evaluate(() => document.fonts.ready);
  for (const width of [1920, 1440, 1365, 800]) {
    await resizeWindow(width);
    await expectStable(diagram.locator('[data-slot="flow-node"]'));
    const bounds = await diagram.boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(await page.evaluate(() => innerWidth) + 1);
  }
  expect(await diagram.evaluate((node) => node.scrollWidth - node.clientWidth)).toBeGreaterThan(0);
  const last = diagram.locator('[data-slot="flow-node"]').last();
  await last.scrollIntoViewIfNeeded();
  await expect(last).toBeInViewport();
  expect(await diagram.evaluate((node) => node.scrollLeft)).toBeGreaterThan(0);
  await last.click();
  await page.screenshot({ path: info.outputPath("flow.png"), fullPage: true });
});
}
