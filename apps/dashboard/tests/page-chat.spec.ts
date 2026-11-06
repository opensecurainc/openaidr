import { test, expect, type Page, type Request } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";

let backend: ChildProcess;
let output = "";
const fixtureUrl = `http://127.0.0.1:${process.env.OPENAIDR_CHAT_TEST_API_PORT || "8773"}`;

async function releaseStreams() {
  const response = await fetch(`${fixtureUrl}/__test__/streams/release`, {
    method: "POST",
  });
  expect(response.ok).toBe(true);
}

async function expectStreamsClosed() {
  await expect
    .poll(async () => {
      const response = await fetch(`${fixtureUrl}/__test__/streams`);
      return (await response.json()).pending;
    })
    .toEqual([]);
}

test.beforeAll(async () => {
  if (!process.env.OPENAIDR_TEST_DATABASE_URL)
    throw new Error(
      "Set OPENAIDR_TEST_DATABASE_URL to a disposable PostgreSQL database.",
    );
  backend = spawn(
    process.env.OPENAIDR_TEST_PYTHON || "python3",
    ["tests/fixtures/page-chat-server.py"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  backend.stdout!.on("data", (chunk) => {
    output += chunk.toString();
  });
  backend.stderr!.on("data", (chunk) => {
    output += chunk.toString();
  });
  const port = process.env.OPENAIDR_CHAT_TEST_API_PORT || "8773";
  await expect
    .poll(
      async () => {
        if (backend.exitCode !== null || backend.signalCode !== null)
          throw new Error(output);
        try {
          return (await fetch(`http://127.0.0.1:${port}/api/v1/auth/me`))
            .status;
        } catch {
          return 0;
        }
      },
      { timeout: 30_000 },
    )
    .toBe(401);
});
test.afterAll(async () => {
  if (backend && backend.exitCode === null) {
    const closed = once(backend, "close");
    backend.kill("SIGTERM");
    const [code] = await closed;
    expect(code, output).toBe(0);
  }
});

test.beforeEach(async () => {
  await expectStreamsClosed();
  const response = await fetch(`${fixtureUrl}/__test__/reset-admission`, { method: "POST" });
  expect(response.ok).toBe(true);
});

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email address").fill("viewer@chat.example.invalid");
  await page
    .getByLabel("Password", { exact: true })
    .fill("page-chat-test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login$/);
  await page.goto("/ai-skills");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "AI Skills",
  );
  await page.getByRole("button", { name: "Ask about this page" }).click();
  await expect(page.getByLabel("Your question", { exact: true })).toBeFocused();
}

async function ask(page: Page, question: string) {
  const request = page.waitForRequest((request) =>
    request.url().endsWith("/api/v1/chat"),
  );
  await page.getByLabel("Your question", { exact: true }).fill(question);
  await page.getByRole("button", { name: "Send", exact: true }).click();
  const payload = (await request).postDataJSON();
  await expect(
    page.getByRole("button", { name: "Send", exact: true }),
  ).toBeVisible();
  return payload;
}

test("composer and message bubbles fit desktop and phones with long text", async ({
  page,
}, info) => {
  await signIn(page);
  const disclosure = page.getByText("Questions and page text go to the OpenAIDR Intelligence service.", { exact: true });
  await expect(disclosure).toBeVisible();
  await expect(page.getByText("Questions and page text go to OpenAI.", { exact: true })).toHaveCount(0);
  const question = page.getByLabel("Your question", { exact: true });
  const send = page.getByRole("button", { name: "Send", exact: true });
  for (const viewport of [
    { width: 1440, height: 1080 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport);
    await question.fill("Summarize this page");
    const inputBox = (await question.boundingBox())!;
    const sendBox = (await send.boundingBox())!;
    expect(Math.abs(inputBox.height - sendBox.height)).toBeLessThanOrEqual(1);
    expect(Math.abs(inputBox.y - sendBox.y)).toBeLessThanOrEqual(1);
    expect(sendBox.x).toBeGreaterThanOrEqual(inputBox.x + inputBox.width);

    await question.press("End");
    await question.press("Shift+Enter");
    await question.pressSequentially("Explain the risks.");
    await expect(question).toHaveValue("Summarize this page\nExplain the risks.");
    expect((await question.boundingBox())!.height).toBeGreaterThan(
      inputBox.height,
    );
    await expect(send).toBeEnabled();
    await expect(disclosure).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`assistant-service-${viewport.width}.png`), fullPage: true });

    await question.fill("Explain this line.\n".repeat(30));
    expect(
      await question.evaluate((node) => node.scrollHeight > node.clientHeight),
    ).toBe(true);
    await expect(send).toBeInViewport();
    await page.getByRole("button", { name: "New chat", exact: true }).click();
    expect((await question.boundingBox())!.height).toBe(inputBox.height);
    await expect(send).toBeDisabled();
  }
  const identifier = "0123456789abcdef".repeat(20);
  const prompt = `Repeat this identifier: ${identifier}`;
  await ask(page, prompt);
  const log = page.getByRole("log");
  const userMessage = log.getByText(prompt, { exact: true });
  const assistantMessage = log.getByText(identifier, { exact: true });
  await expect(assistantMessage).toBeVisible();
  for (const viewport of [
    { width: 1440, height: 1080 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport);
    const userBox = (await userMessage.boundingBox())!;
    const assistantBox = (await assistantMessage.boundingBox())!;
    expect(userBox.x).toBeGreaterThan(assistantBox.x);
    for (const element of [log, userMessage, assistantMessage]) {
      expect(
        await element.evaluate((node) => node.scrollWidth <= node.clientWidth),
      ).toBe(true);
    }
  }
  await page.getByRole("button", { name: "New chat", exact: true }).click();
  // Exercise the real JSON endpoint to represent an older backend at rollout.
  await page.route("**/api/v1/chat", (route) =>
    route.continue({
      headers: { ...route.request().headers(), accept: "application/json" },
    }),
  );
  const literal = "/usr/local/bin/jev --url https://JEV.example/api";
  const questionText = `Repeat this identifier: ${literal}`;
  const payload = await ask(page, questionText);
  expect(payload.messages.at(-1).content).toBe(questionText);
  await expect(log.getByText(questionText, { exact: true })).toBeVisible();
  await expect(log.getByText(literal, { exact: true })).toBeVisible();
  await page.goto("/costs/agents");
  await page.getByRole("button", { name: "Ask about this page" }).click();
  const panel = page.getByRole("complementary", { name: "OpenAIDR Assistant" });
  await expect(
    panel.getByRole("heading", { name: "OpenAIDR Assistant" }),
  ).toBeVisible();
  await expect(
    panel.getByText("Current page: AI Agent Costs", { exact: true }),
  ).toBeVisible();
});

test("starter questions send once on click or keyboard activation", async ({
  page, browserName,
}) => {
  const sent: Request[] = [];
  page.on("request", (request) => {
    if (request.url().endsWith("/api/v1/chat")) sent.push(request);
  });
  await signIn(page);
  const suggestions = page.getByRole("group", { name: "Suggested questions" });
  const question = page.getByLabel("Your question", { exact: true });
  await expect(suggestions.getByRole("button")).toHaveText([
    "Summarize this page",
    "What needs my attention?",
    "Explain the key numbers",
  ]);
  expect(sent).toHaveLength(0);
  await question.fill("An unsent custom draft");
  let resume!: () => void;
  const held = new Promise<void>((resolve) => {
    resume = resolve;
  });
  // Hold the real request so pending-state assertions never race the response.
  await page.route("**/api/v1/chat", async (route) => {
    await held;
    await route.continue();
  });
  try {
    await suggestions
      .getByRole("button", { name: "What needs my attention?" })
      .evaluate((button: HTMLButtonElement) => {
        button.click();
        button.click();
      });
    await expect(question).toBeDisabled();
    await expect(question).toHaveValue("");
    await expect(suggestions).toHaveCount(0);
    await expect(
      page.getByRole("log").getByText("You", { exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("log")).toContainText("What needs my attention?");
    await expect(
      page.getByRole("button", { name: "Cancel", exact: true }),
    ).toBeVisible();
  } finally {
    resume();
  }
  await expect(page.getByRole("log")).toContainText(
    "Visible page: AI Skills.",
  );
  await expect(question).toBeFocused();
  expect(sent).toHaveLength(1);
  const payload = sent[0].postDataJSON();
  expect(payload.messages).toEqual([
    { role: "user", content: "What needs my attention?" },
  ]);
  expect(payload.page.path).toBe("/ai-skills");
  expect(payload.page.text).not.toContain("What needs my attention?");
  expect(payload.page.text).not.toContain("An unsent custom draft");
  await expect(
    page.getByRole("log").getByText("OpenAIDR Assistant", { exact: true }),
  ).toBeVisible();
  await page.unroute("**/api/v1/chat");

  for (const key of ["Enter", "Space"]) {
    await page.getByRole("button", { name: "New chat", exact: true }).click();
    await expect(suggestions).toBeVisible();
    await expect(question).toHaveValue("");
    await expect(question).toBeFocused();
    await question.press(browserName === "webkit" && process.platform === "darwin" ? "Alt+Shift+Tab" : "Shift+Tab");
    await expect(
      suggestions.getByRole("button", { name: "Explain the key numbers" }),
    ).toBeFocused();
    await page.keyboard.press(key);
    await expect(page.getByRole("log")).toContainText(
      "Visible page: AI Skills.",
    );
    await expect(question).toBeFocused();
    await expect(suggestions).toHaveCount(0);
  }
  expect(sent).toHaveLength(3);
  expect(sent.slice(1).map((request) => request.postDataJSON().messages)).toEqual(
    Array(2).fill([{ role: "user", content: "Explain the key numbers" }]),
  );
  await question.fill("Explain the key numbers shown here.");
  const request = page.waitForRequest((request) =>
    request.url().endsWith("/api/v1/chat"),
  );
  await question.press("Enter");
  expect((await request).postDataJSON().messages.at(-1)).toEqual({
    role: "user",
    content: "Explain the key numbers shown here.",
  });
  await expect(question).toBeEnabled();
  expect(sent).toHaveLength(4);
});

test("only rendered page text is shared; page updates preserve prior turns", async ({
  page,
}, info) => {
  await signIn(page);
  await page.getByRole("button", { name: "Close OpenAIDR Assistant" }).click();
  const launcher = page.getByRole("button", { name: "Ask about this page" });
  await expect(launcher).toHaveText("");
  await expect(launcher).toHaveAttribute("aria-expanded", "false");
  await expect(
    page.getByRole("complementary", { name: "OpenAIDR Assistant" }),
  ).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("page-chat-closed.png") });
  await launcher.click();
  await page.evaluate(() => {
    const scope = document.createElement("section");
    scope.id = "chat-fixture";
    scope.innerHTML = `
      <h2>Visible summary</h2><p id="visible-value">Open alerts: 7</p>
      <p hidden>hidden-attribute-marker</p>
      <p style="display:none">hidden-css-marker</p>
      <p style="visibility:hidden">hidden-visibility-marker</p>
      <div style="opacity:0"><p>hidden-opacity-marker</p></div>
      <p aria-hidden="true">hidden-aria-marker</p>
      <p class="sr-only">hidden-accessibility-marker</p>
      <p data-page-chat-exclude>excluded-marker</p>
      <input value="input-secret-marker"><textarea>textarea-secret-marker</textarea>
      <select><option>unselected-option-marker</option></select>
      <div contenteditable>editable-secret-marker</div>
      <script type="application/json">{"secret":"hydration-marker"}</script>
      <details><summary>More context</summary><p>collapsed-detail-marker</p></details>
      <pre style="max-height:20px;overflow:hidden">Shown line\nclipped-line-marker\nAnother line</pre>
    `;
    document.getElementById("main-content")!.append(scope);
    sessionStorage.setItem("unrelated-cache", "storage-secret-marker");
  });
  const firstRequest = page.waitForRequest((request) =>
    request.url().endsWith("/api/v1/chat"),
  );
  await page
    .getByLabel("Your question", { exact: true })
    .fill("Summarize the visible alerts.");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  const first = (await firstRequest).postDataJSON();
  await expect(
    page.getByRole("log").getByText("Visible page:", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("log")).not.toContainText(
    "Visible page: AI Skills.",
  );
  await expect(
    page.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Your question", { exact: true })).toBeDisabled();
  await page
    .getByRole("complementary", { name: "OpenAIDR Assistant" })
    .screenshot({ path: info.outputPath("page-chat-streaming.png") });
  await releaseStreams();
  await expect(page.getByLabel("Your question", { exact: true })).toBeEnabled();
  expect(first.page.path).toBe("/ai-skills");
  expect(first.page.text).toContain("Open alerts: 7");
  expect(first.page.text).toContain("More context");
  expect(first.page.text).not.toMatch(
    /marker|Test viewer|Page chat test|OpenAIDR Assistant|Your question/,
  );
  expect(first.messages).toEqual([
    { role: "user", content: "Summarize the visible alerts." },
  ]);
  await expect(page.getByRole("log")).toContainText(
    "Visible page: AI Skills.",
  );
  const second = await ask(page, "Explain that again.");
  expect(second.messages).toHaveLength(3);
  await page.locator("#chat-fixture summary").click();
  await page.locator("#visible-value").evaluate((node) => {
    node.textContent = "Open alerts: 3";
  });
  const third = await ask(page, "How many are visible now?");
  expect(third.page.text).toContain("Open alerts: 3");
  expect(third.page.text).toContain("collapsed-detail-marker");
  expect(third.page.text).not.toContain("Open alerts: 7");
  expect(third.messages).toEqual([
    ...second.messages,
    { role: "assistant", content: "Visible page: AI Skills." },
    { role: "user", content: "How many are visible now?" },
  ]);
  await expect(page.getByRole("log")).toContainText(
    "Summarize the visible alerts.",
  );
  await expect(page.getByRole("log")).toContainText("Explain that again.");
  await page.locator("#chat-fixture").evaluate((node) => node.remove());
  await page.getByRole("button", { name: "New chat", exact: true }).click();
  const restarted = page.waitForRequest((request) =>
    request.url().endsWith("/api/v1/chat"),
  );
  await page
    .getByRole("button", { name: "Summarize this page", exact: true })
    .click();
  expect((await restarted).postDataJSON().messages).toEqual([
    { role: "user", content: "Summarize this page" },
  ]);
  await expect(page.getByRole("log")).toContainText(
    "Visible page: AI Skills.",
  );
  await page.screenshot({ path: info.outputPath("page-chat-desktop.png") });
});

test("cancel restores the draft without resending and navigation clears the previous page", async ({
  page,
}) => {
  await signIn(page);
  let attempts = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/api/v1/chat")) attempts += 1;
  });
  const question = page.getByLabel("Your question", { exact: true });
  await question.fill("simulate slow reply");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(question).toBeDisabled();
  await expect(
    page.getByRole("log").getByText("Visible page:", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expectStreamsClosed();
  await expect(
    page.getByRole("log").getByText("Visible page:", { exact: true }),
  ).toHaveCount(0);
  await expect(question).toHaveValue("simulate slow reply");
  await expect(question).toBeFocused();
  expect(attempts).toBe(1);
  await ask(page, "Summarize this page.");
  const started = page.waitForRequest((request) =>
    request.url().endsWith("/api/v1/chat"),
  );
  await page
    .getByLabel("Your question", { exact: true })
    .fill("simulate slow reply");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await started;
  await expect(
    page.getByRole("log").getByText("Visible page:", { exact: true }),
  ).toBeVisible();
  const cancelled = page.waitForEvent("requestfailed", {
    predicate: (request) => request.url().endsWith("/api/v1/chat"),
  });
  await page
    .getByRole("link", { name: "AI Supply Chain", exact: true })
    .click();
  await cancelled;
  await expectStreamsClosed();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "AI Supply Chain",
  );
  await expect(
    page.getByRole("complementary", { name: "OpenAIDR Assistant" }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Ask about this page" }).click();
  const next = await ask(page, "What is available here?");
  expect(next.page.path).toBe("/ai-supply-chain");
  expect(next.page.text).not.toContain("AI Skills");
  expect(next.messages).toHaveLength(1);
  await expect(page.getByRole("log")).toContainText(
    "Visible page: AI Supply Chain.",
  );
  await expect(page.getByRole("log")).not.toContainText(
    "Visible page: AI Skills.",
  );
});

test("errors preserve history and Markdown streams safely on desktop and phones", async ({
  page,
}, info) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  await ask(page, "simulate failure");
  await expect(page.getByRole("log").getByRole("alert")).toHaveText(
    "OpenAIDR Assistant is unavailable. Please try again.",
  );
  await expect(page.getByLabel("Your question", { exact: true })).toHaveValue(
    "simulate failure",
  );
  const retry = await ask(page, "Summarize this page.");
  expect(retry.messages).toHaveLength(1);
  await expect(page.getByRole("log").getByRole("alert")).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("page-chat-mobile.png") });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  const log = page.getByRole("log");
  await page.getByRole("button", { name: "New chat", exact: true }).click();
  const markdownQuestion = "Summarize the **visible activity**.";
  await page.getByLabel("Your question", { exact: true }).fill(markdownQuestion);
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(
    log.getByRole("heading", { name: "Summary", level: 3 }),
  ).toBeVisible();
  await expect(log.locator("strong").first()).toHaveText("7 open alerts");
  // The service is held before the closing fence, so formatting is checked mid-stream.
  await expect(log.locator("pre code")).toContainText("openaidr-server --help");
  await expect(log.getByRole("table")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeVisible();
  await releaseStreams();
  await expect(page.getByLabel("Your question", { exact: true })).toBeEnabled();
  const userMessage = log.getByText(markdownQuestion, { exact: true });
  await expect(userMessage).toBeVisible();
  await expect(userMessage.locator("strong")).toHaveCount(0);
  await expect(log.locator("ul > li")).toHaveCount(2);
  await expect(log.locator("ol > li")).toHaveCount(2);
  await expect(log.locator("em")).toHaveText("high");
  await expect(log.locator("li code")).toHaveText("server.log");
  await expect(log.locator("blockquote")).toHaveText(
    "Based only on the current page.",
  );
  await expect(log.getByRole("table").getByRole("row")).toHaveCount(3);
  await expect(
    log.getByRole("columnheader", { name: "Count", exact: true }),
  ).toHaveCSS("text-align", "right");
  const panel = page.getByRole("complementary", { name: "OpenAIDR Assistant" });
  for (const viewport of [
    { width: 1440, height: 1080 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport);
    await log.evaluate((node) => {
      node.scrollTop = 0;
    });
    await panel.screenshot({
      path: info.outputPath(`page-chat-markdown-${viewport.width}.png`),
    });
    for (const element of [panel, log]) {
      expect(
        await element.evaluate((node) => node.scrollWidth <= node.clientWidth),
      ).toBe(true);
    }
  }
  for (const element of [
    log.locator("pre"),
    log.getByRole("region", { name: "Table in assistant reply" }),
  ]) {
    expect(
      await element.evaluate((node) => node.scrollWidth > node.clientWidth),
    ).toBe(true);
    await element.focus();
    await expect(element).toBeFocused();
  }
  expect(
    await log.evaluate((node) => node.scrollWidth <= node.clientWidth),
  ).toBe(true);
  await page
    .getByLabel("Your question", { exact: true })
    .fill("simulate interrupted reply");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(
    page.getByRole("log").getByText("Visible page:", { exact: true }),
  ).toBeVisible();
  await releaseStreams();
  await expect(page.getByRole("log").getByRole("alert")).toContainText(
    "incomplete answer",
  );
  await expect(page.getByLabel("Your question", { exact: true })).toHaveValue(
    "simulate interrupted reply",
  );
  await expect(log.locator("strong").first()).toHaveText("7 open alerts");
  await expect(
    page.getByRole("log").getByText("Visible page:", { exact: true }),
  ).toHaveCount(0);
  await expectStreamsClosed();
  const externalRequests: string[] = [];
  const dialogs: string[] = [];
  page.on("dialog", async (dialog) => {
    dialogs.push(dialog.message());
    await dialog.dismiss();
  });
  page.on("request", (request) => {
    if (request.url().includes("example.invalid/"))
      externalRequests.push(request.url());
  });
  const afterInterruption = await ask(page, "simulate markup");
  expect(afterInterruption.messages).toHaveLength(3);
  expect(afterInterruption.messages[1].content).toContain("**7 open alerts**");
  expect(afterInterruption.messages[1].content).toContain(
    "```sh\nopenaidr-server --help\n",
  );
  expect(
    afterInterruption.messages.map((message: { content: string }) => message.content),
  ).not.toContain("simulate interrupted reply");
  await expect(page.getByRole("log")).toContainText(
    '<img src="https://example.invalid/tracker-html"',
  );
  await expect(page.getByRole("log").locator("img")).toHaveCount(0);
  await expect(log.locator("script, iframe")).toHaveCount(0);
  await expect(log.getByText("Image description", { exact: true })).toBeVisible();
  await expect(log.getByRole("link")).toHaveCount(1);
  const safeLink = log.getByRole("link", { name: "Safe link", exact: true });
  await expect(safeLink).toHaveAttribute("href", "https://example.invalid/details");
  await expect(safeLink).toHaveAttribute("target", "_blank");
  await expect(safeLink).toHaveAttribute("rel", "noopener noreferrer");
  await expect(safeLink).toHaveCSS("text-decoration-line", "underline");
  expect(externalRequests).toEqual([]);
  expect(dialogs).toEqual([]);
  await page.getByLabel("Your question", { exact: true }).press("Escape");
  await expect(
    page.getByRole("button", { name: "Ask about this page" }),
  ).toBeFocused();
  await expect(
    page.getByRole("complementary", { name: "OpenAIDR Assistant" }),
  ).toHaveCount(0);
});

test("long pages are bounded and explicitly marked as partial context", async ({
  page,
}) => {
  await signIn(page);
  await page.evaluate(() => {
    const text = document.createElement("p");
    text.textContent = "Visible row 🧪. ".repeat(2000) + "beyond-context-limit";
    document.getElementById("main-content")!.append(text);
  });
  const sent = await ask(page, "Summarize this page.");
  expect(sent.page.text.length).toBeLessThanOrEqual(20_000);
  expect(() => encodeURIComponent(sent.page.text)).not.toThrow();
  expect(sent.page.truncated).toBe(true);
  expect(sent.page.text).not.toContain("beyond-context-limit");
  await expect(page.getByRole("log")).toContainText(
    "Only its first 20,000 characters are shared",
  );
});
