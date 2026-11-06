import { test, expect } from "@playwright/test";
import { mockChartData } from "./fixtures/chart-layout";

test("cost pages align their headings and stack descriptions below titles", async ({ page }, info) => {
  await mockChartData(page);
  for (const width of [1440, 1024, 390]) {
    await page.setViewportSize({ width, height: 900 });
    const headings = [];
    for (const [path, title, description] of [
      ["/costs/agents", "AI Agent Costs", "Track AI spend over time and by user, model, project, activity, and reasoning effort."],
      ["/costs/openaidr", "Credits & Usage", "Track your credit balance and usage by feature."],
    ]) {
      await page.goto(path);
      const heading = page.getByRole("heading", { name: title, exact: true });
      const subtitle = page.locator("main").getByText(description, { exact: true });
      await expect(heading).toBeVisible();
      await expect(subtitle).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      const headingBox = (await heading.boundingBox())!;
      const subtitleBox = (await subtitle.boundingBox())!;
      expect(subtitleBox.y).toBeGreaterThanOrEqual(headingBox.y + headingBox.height);
      expect(subtitleBox.x).toBeCloseTo(headingBox.x, 0);
      expect(subtitleBox.x + subtitleBox.width).toBeLessThanOrEqual(width);
      headings.push(headingBox);
      await page.screenshot({ path: info.outputPath(`${path.split("/").at(-1)}-heading-${width}.png`) });
    }
    expect(headings[1].x).toBeCloseTo(headings[0].x, 0);
    expect(headings[1].y).toBeCloseTo(headings[0].y, 0);
  }
});

test("cost navigation fits on one line and retains the full page heading", async ({ page }, info) => {
  await mockChartData(page);
  for (const width of [1440, 1024, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/costs/agents");
    await expect(page.locator("main h1")).toHaveText("AI Agent Costs");
    const mobile = width < 1024;
    if (mobile) await page.getByRole("button", { name: "Open navigation" }).click();
    const container = mobile ? page.getByRole("dialog", { name: "Workspace navigation" }) : page.locator("aside");
    const nav = container.getByRole("navigation", { name: "Workspace navigation" });
    const link = nav.locator('a[href="/costs/openaidr"]');
    for (const active of [false, true]) {
      await link.scrollIntoViewIfNeeded();
      await page.evaluate(() => document.fonts.ready);
      const label = link.locator("span");
      const layout = await label.evaluate((node) => {
        const text = document.createRange();
        text.selectNodeContents(node);
        const bounds = text.getBoundingClientRect();
        return {
          lines: text.getClientRects().length,
          left: bounds.left,
          right: bounds.right,
          linkRight: node.parentElement!.getBoundingClientRect().right,
        };
      });
      expect(layout.lines).toBe(1);
      expect(layout.left).toBeGreaterThanOrEqual(0);
      expect(layout.right).toBeLessThanOrEqual(layout.linkRight);
      expect(await nav.evaluate((node) => node.scrollWidth - node.clientWidth)).toBe(0);
      if (active) {
        await expect(link).toHaveAttribute("aria-current", "page");
        await expect(label).toHaveText("Credits & Usage");
      } else {
        await link.click();
        await expect(page).toHaveURL(/\/costs\/openaidr$/);
        await expect(page.locator("main h1")).toHaveText("Credits & Usage");
        if (mobile) {
          await expect(container).toBeHidden();
          await page.getByRole("button", { name: "Open navigation" }).click();
        }
      }
    }
    await nav.locator("div").filter({ has: page.getByText("Cost Management", { exact: true }) }).screenshot({
      path: info.outputPath(`cost-navigation-${width}.png`),
    });
    if (mobile) await page.keyboard.press("Escape");
  }
});
