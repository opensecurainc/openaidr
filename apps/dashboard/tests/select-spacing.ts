import { expect, type Locator } from "@playwright/test";

export async function expectSelectSpacing(selects: Locator) {
  expect(await selects.count()).toBeGreaterThan(0);
  for (const select of await selects.all()) {
    await expect(select).toHaveCSS("appearance", "none");
    const arrow = select.locator("..").locator("svg");
    await expect(arrow).toBeVisible();
    await expect(arrow).toHaveCSS("pointer-events", "none");
    await expect(async () => {
      const spacing = await select.evaluate((node) => {
        const style = getComputedStyle(node);
        const control = node.getBoundingClientRect();
        const icon = node.parentElement!.querySelector("svg")!.getBoundingClientRect();
        const textRight = control.right - parseFloat(style.borderRightWidth) - parseFloat(style.paddingRight);
        return {
          inset: control.right - icon.right,
          gap: icon.left - textRight,
          verticalOffset: Math.abs(control.y + control.height / 2 - icon.y - icon.height / 2),
        };
      });
      expect(spacing.inset).toBeCloseTo(12, 2);
      expect(spacing.gap).toBeGreaterThanOrEqual(7.99);
      expect(spacing.verticalOffset).toBeLessThanOrEqual(1);
    }).toPass({ timeout: 5_000 });
  }
}
