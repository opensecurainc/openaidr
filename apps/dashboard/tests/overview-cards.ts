import { expect, type Locator } from "@playwright/test";

/** AI Supply Chain and AI Skills render four summary cards with identical type and spacing. */
export async function expectOverviewCards(overview: Locator, primary = true) {
  const cards = overview.locator('[data-slot="card"]');
  await expect(cards).toHaveCount(4);
  const styles = await cards.evaluateAll(nodes => nodes.map(card => {
    const css = (node: Element | null) => {
      if (!node) return null;
      const style = getComputedStyle(node);
      return `${style.fontFamily}|${style.fontSize}|${style.fontWeight}|${style.lineHeight}|${style.fontVariantNumeric}`;
    };
    const [title, value, detail] = card.children;
    return { padding: getComputedStyle(card).padding, title: css(title), value: css(value?.firstElementChild ?? null), detail: css(detail), figure: Boolean(card.querySelector(".figure")) };
  }));
  const family = styles[0].title!.split("|")[0];
  // Peer category cards stay neutral; headline summaries use the primary fill.
  const backgrounds = await cards.evaluateAll(nodes => {
    const probe = document.body.appendChild(document.createElement("div"));
    probe.className = "bg-primary";
    const primary = getComputedStyle(probe).backgroundColor;
    probe.remove();
    return nodes.map(card => getComputedStyle(card).backgroundColor === primary);
  });
  expect(backgrounds).toEqual([primary, false, false, false]);
  for (const style of styles) {
    expect(style.padding).toBe("16px");
    expect(style.title).toBe(`${family}|14px|500|20px|normal`);
    expect(style.detail).toBe(`${family}|12px|400|16px|normal`);
    expect(style.value).toBe(style.figure ? `${family}|28px|600|32px|proportional-nums` : `${family}|16px|600|24px|normal`);
  }
}
