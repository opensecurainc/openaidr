import { test, expect, type Page } from "@playwright/test";
import { LATEST_INSTALLERS, desktopInstallerUrl, detectDesktopPlatform, installerUrl } from "../src/lib/desktop-downloads";
import { desktopInstallCommand } from "../src/lib/install-command";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

for (const platform of ["mac", "linux", "windows"] as const) {
test(`${platform} install commands isolate the enrollment secret and reject unsafe inputs`, () => {
  const link = "https://tenant.example/enroll#token=oaet_" + "a".repeat(43);
  const command = desktopInstallCommand(link, "https://dashboard.example", platform)!;
  const asset = { mac: "install-macos.js", windows: "install-windows.ps1", linux: "install-linux.py" }[platform];
  expect(command).toContain(`'https://dashboard.example/${asset}'`);
  if (platform === "windows") {
    expect(command).toContain("-MaximumRedirection 0");
    expect(command).toContain(`& ([scriptblock]::Create($script)) -EnrollmentLink '${link}'`);
    expect(command).not.toMatch(/ExecutionPolicy|powershell.exe|pwsh.exe/);
  } else {
    expect(command).toContain("--proto '=https' --proto-redir '=https'");
    expect(command).toContain(`--enrollment-stdin <<'OPENAIDR_LINK'\n${link}\nOPENAIDR_LINK`);
    const syntax = spawnSync("/bin/bash", ["-n"], { input: command, encoding: "utf8" });
    expect(syntax.status, syntax.stderr).toBe(0);
  }
  expect(command.match(/oaet_/g)).toHaveLength(1);
  expect(command).not.toContain("curl " + link);
  for (const invalid of [
    link + "\nOPENAIDR_LINK\necho injected", link.replace("https:", "http:"),
    link.replace("tenant.example", "user:password@tenant.example"), link.replace("#token=", "?token="),
    link.replace("/enroll#", "/other#"), link + "&extra=value", link.replace("oaet_", "bad_"),
    link.replace("tenant.example", "tenant.example\\evil"),
  ]) expect(desktopInstallCommand(invalid, "https://dashboard.example", platform)).toBeNull();
  for (const origin of ["http://dashboard.example", "https://user@dashboard.example", "file:///tmp"]) {
    expect(desktopInstallCommand(link, origin, platform)).toBeNull();
  }
});

}

test("Mac MDM commands use explicit unattended mode and keep the link on standard input", () => {
  const link = "https://tenant.example/enroll#token=oaet_" + "a".repeat(43);
  const command = desktopInstallCommand(link, "https://dashboard.example", "mac", "mdm")!;
  expect(command).toMatch(/^#!\/bin\/bash\n/);
  expect(command).toContain('"$installer" --mdm --enrollment-stdin');
  expect(command).toContain(`<<'OPENAIDR_LINK'\n${link}\nOPENAIDR_LINK`);
  expect(command.match(/oaet_/g)).toHaveLength(1);
  expect(command).toContain("--proto '=https' --proto-redir '=https'");
  const syntax = spawnSync("/bin/bash", ["-n"], { input: command, encoding: "utf8" });
  expect(syntax.status, syntax.stderr).toBe(0);
  expect(desktopInstallCommand(link, "https://dashboard.example", "mac")).not.toContain("--mdm");
  for (const platform of ["windows", "linux"] as const) {
    expect(desktopInstallCommand(link, "https://dashboard.example", platform, "mdm")).toBeNull();
  }
  expect(desktopInstallCommand(link + "\nOPENAIDR_LINK", "https://dashboard.example", "mac", "mdm")).toBeNull();
  if (process.platform === "darwin") {
    const directory = mkdtempSync(join(tmpdir(), "openaidr-mdm-compat-"));
    try {
      const legacy = join(directory, "legacy.js");
      writeFileSync(legacy, "function run() { return 'Usage: install-macos.js [--enrollment-stdin]'; }");
      const guard = command.slice(command.indexOf("if [ "), command.indexOf("\nfi") + 3);
      for (const [installer, expected] of [[resolve(__dirname, "../public/install-macos.js"), 0], [legacy, 1]] as const) {
        const result = spawnSync("/bin/bash", ["-c", guard], {
          env: { ...process.env, installer }, encoding: "utf8", timeout: 10_000,
        });
        expect(result.status, result.stderr).toBe(expected);
        if (expected) expect(result.stderr).toContain("does not support silent Mac installation");
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

const userAgents = {
  mac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
  windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
  linux: "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
  unknown: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
} as const;

const platforms = {
  mac: { label: "Mac", installers: [
    ["Mac", process.env.OPENAIDR_DESKTOP_MAC_ARM64_URL, LATEST_INSTALLERS.macArm64],
  ] },
  windows: { label: "Windows", installers: [["Windows", process.env.OPENAIDR_DESKTOP_WINDOWS_X64_URL, LATEST_INSTALLERS.windowsX64]] },
  linux: { label: "Linux", installers: [["Linux", process.env.OPENAIDR_DESKTOP_LINUX_X64_URL, LATEST_INSTALLERS.linuxX64]] },
} as const;
type Platform = keyof typeof platforms;
const platformNames = Object.keys(platforms) as Platform[];

async function expectInstallers(page: Page, platform: Platform) {
  for (const [name, configured, latest] of platforms[platform].installers) {
    // An approved administrator URL wins; otherwise the latest public installer.
    const link = page.getByRole("link", { name: `Download for ${name}`, exact: true });
    await expect(link).toHaveAttribute("href", desktopInstallerUrl(configured) ?? latest);
    await expect(link).toHaveAttribute("rel", "noreferrer");
    await expect(link).toHaveAttribute("referrerpolicy", "no-referrer");
  }
  await expect(page.getByText(/approved OpenAIDR installer/)).toHaveCount(0);
}

test("installer links allow HTTPS and reject unsafe configuration", () => {
  for (const url of [
    "https://downloads.example/OpenAIDR-aarch64.dmg",
    "https://downloads.example:8443/OpenAIDR-aarch64.dmg?download=1",
    "https://downloads.example/api/OpenAIDR-aarch64.dmg",
    "https://downloads.example/ingest/OpenAIDR-aarch64.dmg",
    "https://xn--bcher-kva.example/app.dmg",
    "https://192.0.2.1/app.dmg", "https://[2001:db8::1]:8443/app.dmg",
  ]) expect(desktopInstallerUrl(url)).toBe(url);

  for (const url of [
    undefined, "", "not a URL", "/OpenAIDR.dmg", "//downloads.example/OpenAIDR.dmg",
    "http://downloads.example/OpenAIDR.dmg", "javascript:alert(1)",
    "data:text/plain,installer", "https:downloads.example/OpenAIDR.dmg",
    "https://user:password@downloads.example/OpenAIDR.dmg",
    "https://user@downloads.example/OpenAIDR.dmg",
    "https://downloads.example/OpenAIDR.dmg#token=secret",
    "https://downloads.example/OpenAIDR.dmg#",
    "https://downloads.example/\nOpenAIDR.dmg",
    "https://downloads.example/\\OpenAIDR.dmg",
    "https://downloads.example/" + "x".repeat(2048),
    "https://999.999.999.999/app.dmg", "https://exa%mple.com/app.dmg",
    "https://downloads.123/app.dmg", "https://downloads.0x10/app.dmg",
    "https://downloads.0x/app.dmg",
    "https://[fe80::1%25en0]/app.dmg", "https://[::1]junk/app.dmg",
    "https://downloads.example/﻿app.dmg", "https://downloads.example/app.dmg?channel=﻿stable",
  ]) expect(desktopInstallerUrl(url), String(url)).toBeNull();

  const unicodeUrl = "https://downloads.example/" + "😀".repeat(1011);
  expect(desktopInstallerUrl(unicodeUrl)).not.toBeNull();
  expect(desktopInstallerUrl(unicodeUrl + "a")).toBeNull();

  // Missing or unsafe administrator URLs fall back to the fixed latest links.
  for (const latest of Object.values(LATEST_INSTALLERS)) {
    expect(desktopInstallerUrl(latest)).toBe(latest);
    expect(installerUrl(undefined, latest)).toBe(latest);
    expect(installerUrl("http://downloads.example/app.dmg", latest)).toBe(latest);
    expect(installerUrl("https://downloads.example/app.dmg", latest)).toBe("https://downloads.example/app.dmg");
  }
});

test("operating system detection picks the installer shown first", () => {
  for (const [userAgent, expected] of [
    [userAgents.mac, "mac"],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", "mac"],
    [userAgents.windows, "windows"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0", "windows"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0", "windows"],
    [userAgents.linux, "linux"],
    ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", "linux"],
    ["Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "linux"],
    [userAgents.unknown, null],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", null],
    ["Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36", null],
    ["curl/8.9.1", null], ["", null], [null, null],
  ] as const) expect(detectDesktopPlatform(userAgent), String(userAgent)).toBe(expected);
});

for (const detected of platformNames) {
  test(`enrollment shows the ${detected} installer first and keeps the others reachable`, async ({ browser }) => {
    const context = await browser.newContext({ userAgent: userAgents[detected] });
    const page = await context.newPage();
    await page.goto(`/enroll#token=oaet_${"a".repeat(43)}`);
    await expect(page.getByRole("heading", { name: `1. Install OpenAIDR for ${platforms[detected].label}`, exact: true })).toBeVisible();
    await expectInstallers(page, detected);

    const others = platformNames.filter((platform) => platform !== detected);
    for (const other of others) {
      await expect(page.getByRole("heading", { name: `OpenAIDR for ${platforms[other].label}` })).toHaveCount(0);
    }
    const summary = `Installing on ${others.map((other) => platforms[other].label).join(" or ")}?`;
    await page.getByText(summary, { exact: true }).click();
    for (const other of others) {
      await expect(page.getByRole("heading", { name: `OpenAIDR for ${platforms[other].label}`, exact: true })).toBeVisible();
      await expectInstallers(page, other);
    }
    await context.close();
  });
}

test("enrollment lists every installer when the operating system is unknown", async ({ browser }, info) => {
  const context = await browser.newContext({ userAgent: userAgents.unknown, viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  await page.goto(`/enroll#token=oaet_${"a".repeat(43)}`);
  await expect(page.getByRole("heading", { name: "1. Install OpenAIDR", exact: true })).toBeVisible();
  await expect(page.getByText(/^Installing on /)).toHaveCount(0);
  for (const platform of platformNames) {
    await expect(page.getByRole("heading", { name: `OpenAIDR for ${platforms[platform].label}`, exact: true })).toBeVisible();
    await expectInstallers(page, platform);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("enrollment-install-all-platforms.png"), fullPage: true });
  await context.close();
});

test.describe("on a Mac", () => {
  test.use({ userAgent: userAgents.mac });

  test("public enrollment guides installation without exposing the enrollment code", async ({ page, context }, info) => {
    const code = "oaet_" + "a".repeat(43);
    const requests: {url: string; body: string}[] = [];
    page.on("request", (request) => requests.push({url: request.url(), body: request.postData() || ""}));
    const response = await page.goto(`/enroll#token=${code}`);
    expect(response!.headers()["referrer-policy"]).toBe("no-referrer");
    await expect(page.getByRole("heading", { name: "Connect your device" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "1. Install OpenAIDR for Mac" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "2. Connect to your organization" })).toBeVisible();
    await expect(page.locator("main")).toContainText("Open OpenAIDR and paste this full enrollment link");
    await expect(page.locator("main")).toContainText("Opening this page leaves the link available");
    await expect(page.locator("main")).toContainText("Your administrator sets the use limit and expiration.");
    await expect(page.locator("main")).not.toContainText("It works once");
    await expect(page.locator("main")).toContainText("copy OpenAIDR to Applications");
    // The public release is universal; an administrator's installer may not be.
    await expect(page.locator("main")).toContainText(desktopInstallerUrl(process.env.OPENAIDR_DESKTOP_MAC_ARM64_URL)
      ? "if it does not open on an Intel Mac, ask them for a current release"
      : "The installer works on Apple Silicon and Intel Macs.");
    await expect(page.locator("main")).not.toContainText("Intel Macs are not supported");
    await expect(page.getByRole("link", { name: "Download for Intel", exact: true })).toHaveCount(0);
    await expect(page.getByRole("link", { name: /^Download for / })).toHaveCount(1);

    await page.getByText("Installing on Windows or Linux?", { exact: true }).click();
    const downloadUrl = platformNames
      .flatMap((platform) => platforms[platform].installers.map(([, value, latest]) => installerUrl(value, latest)))
      .find(Boolean);
    if (downloadUrl) {
      await page.route(downloadUrl, (route) => route.fulfill({ status: 204 }));
      const [request] = await Promise.all([
        page.waitForRequest(downloadUrl),
        page.locator(`a[href="${downloadUrl}"]`).first().click(),
      ]);
      expect(request.headers().referer).toBeUndefined();
      await expect(page).toHaveURL(new RegExp(`/enroll#token=${code}$`));
    }

    const help = page.locator("details", { hasText: "Need help installing or connecting?" });
    await page.getByText("Need help installing or connecting?", { exact: true }).click();
    await expect(help).toContainText("Keep certificate verification enabled");
    await expect(help).toContainText("public CA certificate file");
    await expect(help).toContainText("Private server certificate (optional)");
    await expect(help).toContainText("For older apps without this option");
    await expect(help).toContainText("Open Anyway");
    await expect(help).toContainText("SmartScreen");
    await page.reload();
    await expect(page.getByRole("heading", { name: "Connect your device" })).toBeVisible();
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    expect(await context.cookies()).toEqual([]);
    expect(requests.some((request) => (request.url + request.body).includes(code))).toBe(false);
    const dashboardOrigin = new URL(page.url()).origin;
    expect(requests.some((request) => {
      const url = new URL(request.url);
      return url.origin === dashboardOrigin && /^\/(ingest|api)\//.test(url.pathname);
    })).toBe(false);

    await page.getByText("Installing on Windows or Linux?", { exact: true }).click();
    await page.getByText("Need help installing or connecting?", { exact: true }).click();
    await page.screenshot({ path: info.outputPath("enrollment-install-desktop.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("enrollment-install-mobile.png"), fullPage: true });
  });
});
