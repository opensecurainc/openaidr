import type { DesktopPlatform } from "./desktop-downloads";

// Supply the token in the current PowerShell process or a quoted stdin block.
// Never include it in a download request or a child process argument.
export function desktopInstallCommand(link: string, dashboardOrigin: string, platform: DesktopPlatform, mode: "interactive" | "mdm" = "interactive"): string | null {
  if (mode === "mdm" && platform !== "mac") return null;
  if (link.length > 4096 || /[\s\\\u0000-\u001f\u007f]/.test(link)) return null;
  try {
    const enrollment = new URL(link);
    if (enrollment.protocol !== "https:" || enrollment.username || enrollment.password ||
        enrollment.pathname !== "/enroll" || link.includes("?") ||
        !/^#token=oaet_[A-Za-z0-9_-]{43}$/.test(enrollment.hash)) return null;
    const dashboard = new URL(dashboardOrigin);
    const local = dashboard.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(dashboard.hostname);
    if ((!local && dashboard.protocol !== "https:") || dashboard.username || dashboard.password) return null;
    const asset = { mac: "install-macos.js", windows: "install-windows.ps1", linux: "install-linux.py" }[platform];
    const url = new URL(`/${asset}`, dashboard.origin).href;
    if (platform === "windows") {
      return `& {
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 60 -Uri '${url.replace(/'/g, "''")}'
$script = [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
& ([scriptblock]::Create($script)) -EnrollmentLink '${link.replace(/'/g, "''")}'
}`;
    }
    const bootstrap = url.replace(/'/g, "'\"'\"'");
    const protocols = local ? "=https,http" : "=https";
    const temporary = platform === "mac" ? "mktemp -t openaidr-install" : "mktemp -t openaidr-install.XXXXXXXX";
    const runner = platform === "mac" ? '/usr/bin/osascript -l JavaScript "$installer"' : 'python3 "$installer"';
    const compatibility = mode === "mdm" ? `if [ "$(${runner} --mdm-version)" != '1' ]; then
  printf '%s\\n' 'This dashboard does not support silent Mac installation. Update the dashboard and create a new script.' >&2
  exit 1
fi
` : "";
    return `${mode === "mdm" ? "#!/bin/bash\n" : ""}/bin/bash <<'OPENAIDR_INSTALL'
set -eu
umask 077
installer=$(${temporary})
trap 'rm -f "$installer"' EXIT
/usr/bin/curl --fail --silent --show-error --location --proto '${protocols}' --proto-redir '=https' --connect-timeout 20 --max-time 60 '${bootstrap}' --output "$installer"
${compatibility}${runner}${mode === "mdm" ? " --mdm" : ""} --enrollment-stdin <<'OPENAIDR_LINK'
${link}
OPENAIDR_LINK
OPENAIDR_INSTALL`;
  } catch {
    return null;
  }
}
