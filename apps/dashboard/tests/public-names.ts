import { expect, type Locator, type Page } from "@playwright/test";

/** Check rendered text and labels, including tooltips and screen-reader text. */
export async function expectPublicNames(page: Page, scope: Locator = page.locator("body")) {
  expect(await scope.innerText()).not.toMatch(/jev/i);
  const labels = await scope.locator("[title], [aria-label], [aria-description], img[alt]").evaluateAll(
    (elements) => elements.flatMap((element) =>
      ["title", "aria-label", "aria-description", "alt"].map((name) => element.getAttribute(name) ?? ""),
    ),
  );
  expect(labels.join("\n")).not.toMatch(/jev/i);
}
