import type { Page } from "@playwright/test";

/** Clipboard permissions differ by browser; mock the operating-system boundary. */
export async function mockClipboard(page: Page) {
  await page.evaluate(() => {
    let value = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (text: string) => { value = text; },
        readText: async () => value,
      },
    });
  });
}
