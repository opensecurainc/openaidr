export type PageContext = {
  path: string;
  title: string;
  text: string;
  truncated: boolean;
};

const MAX_PAGE_CHARS = 20_000;
const EXCLUDED =
  'script, style, noscript, template, input, textarea, select, iframe, canvas, [hidden], [inert], [aria-hidden="true"], [contenteditable], [data-page-chat-exclude], .sr-only';

/** Read rendered page text, never React state, attributes, form values, or API caches. */
export function capturePageContext(path: string, title: string): PageContext {
  const root = document.getElementById("main-content");
  if (!root || document.hidden)
    throw new Error("Open a page before asking a question.");
  if (root.closest(EXCLUDED))
    throw new Error("Close the overlay before asking about this page.");
  const parts: string[] = [];
  let length = 0;

  function append(text: string) {
    if (length > MAX_PAGE_CHARS) return;
    const part = text.slice(0, MAX_PAGE_CHARS + 1 - length);
    parts.push(part);
    length += part.length;
  }

  function visit(element: Element) {
    if (length > MAX_PAGE_CHARS || element.matches(EXCLUDED)) return;
    const style = getComputedStyle(element);
    if (
      style.display === "none" ||
      style.visibility !== "visible" ||
      style.opacity === "0" ||
      style.contentVisibility === "hidden" ||
      style.clipPath !== "none" ||
      style.clip !== "auto"
    )
      return;
    if (
      element instanceof HTMLElement &&
      ((["hidden", "clip"].includes(style.overflowX) &&
        element.scrollWidth > element.clientWidth + 1) ||
        (["hidden", "clip"].includes(style.overflowY) &&
          element.scrollHeight > element.clientHeight + 1))
    ) {
      append(
        "\n[Clipped text omitted; expand it on the page to include it.]\n",
      );
      return;
    }
    // Closed disclosures remain in the DOM but are not displayed.
    const nodes = element.matches("details:not([open])")
      ? [...element.children].filter((child) => child.tagName === "SUMMARY")
      : [...element.childNodes];
    const block = !["inline", "inline-block", "contents"].includes(
      style.display,
    );
    if (block) append("\n");
    for (const node of nodes) {
      if (node instanceof Element) visit(node);
      else if (node.nodeType === Node.TEXT_NODE && node.textContent?.trim()) {
        const range = document.createRange();
        range.selectNodeContents(node);
        if (
          [...range.getClientRects()].some(
            (rect) => rect.width > 0 && rect.height > 0,
          )
        ) {
          append(node.textContent.replace(/\s+/g, " "));
        }
      }
      if (length > MAX_PAGE_CHARS) break;
    }
    append(block ? "\n" : " ");
  }

  visit(root);
  const text = parts
    .join("")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (!text) throw new Error("There is no visible page text to share yet.");
  return {
    path,
    title,
    text: text.slice(0, MAX_PAGE_CHARS).replace(/[\uD800-\uDBFF]$/, ""),
    truncated: length > MAX_PAGE_CHARS,
  };
}
