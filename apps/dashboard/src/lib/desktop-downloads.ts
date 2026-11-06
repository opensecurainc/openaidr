export type DesktopPlatform = "mac" | "windows" | "linux";

// Fixed links to the newest published installers, maintained by
// scripts/desktop_rollout.py. Recipients' browsers download them directly;
// the dashboard server never fetches them.
const LATEST = "https://releases.opensecura.ai/openaidr/latest/";
export const LATEST_INSTALLERS = {
  macArm64: LATEST + "OpenAIDR-aarch64.dmg",
  windowsX64: LATEST + "OpenAIDR-windows-x64.zip",
  linuxX64: LATEST + "OpenAIDR-linux-amd64.deb",
} as const;

// An approved administrator URL wins; otherwise offer the latest public installer.
export function installerUrl(configured: string | undefined, latest: string): string {
  return desktopInstallerUrl(configured) ?? latest;
}

export function desktopInstallerUrl(value: string | undefined): string | null {
  if (!value || value.length > 2048 || /[\s\u0000-\u001f\u007f\\#]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (!value.startsWith("https://") || !url.hostname || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

// Only chooses which installer is shown first; every installer stays reachable.
// Browsers keep the operating system token in reduced user agents, but not a
// reliable processor architecture, so architecture is left to the recipient.
export function detectDesktopPlatform(userAgent: string | null | undefined): DesktopPlatform | null {
  if (!userAgent) return null;
  if (/\b(Android|iPhone|iPod|CrOS)\b/.test(userAgent)) return null;
  if (/\bWindows NT\b/.test(userAgent)) return "windows";
  if (/\bMacintosh\b/.test(userAgent)) return "mac";
  if (/\bLinux\b/.test(userAgent)) return "linux";
  return null;
}
