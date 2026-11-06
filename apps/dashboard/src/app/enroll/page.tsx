import type { ReactNode } from "react";
import { headers } from "next/headers";
import { buttonVariants } from "@/components/ui/button";
import { PageNotice } from "@/components/page-layout";
import { type DesktopPlatform, LATEST_INSTALLERS, detectDesktopPlatform, installerUrl } from "@/lib/desktop-downloads";

// Installer locations are deployment settings, read when the page is requested.
export const dynamic = "force-dynamic";

type PlatformGuide = {
  label: string;
  installers: { name: string; url: string | null }[];
  before: ReactNode;
  after: ReactNode;
};

const platforms: DesktopPlatform[] = ["mac", "windows", "linux"];

function platformGuides(): Record<DesktopPlatform, PlatformGuide> {
  return {
    mac: {
      label: "Mac",
      installers: [
        { name: "Apple Silicon", url: installerUrl(process.env.OPENAIDR_DESKTOP_MAC_ARM64_URL, LATEST_INSTALLERS.macArm64) },
      ],
      before: (
        <>
          OpenAIDR requires an Apple Silicon Mac. Intel Macs are not supported.
          Choose Apple menu &gt; About This Mac and check that it lists an Apple chip.
        </>
      ),
      after: (
        <>
          Open the downloaded disk image and copy OpenAIDR to Applications
          or the Applications folder in your home folder. Open the installed
          app. Automatic updates need an app and Applications folder that
          your account can change. On a managed Mac, your administrator may
          need to install and update the app.
        </>
      ),
    },
    windows: {
      label: "Windows",
      installers: [
        { name: "Windows", url: installerUrl(process.env.OPENAIDR_DESKTOP_WINDOWS_X64_URL, LATEST_INSTALLERS.windowsX64) },
      ],
      before: <>The installer is for 64-bit Windows.</>,
      after: (
        <>
          Open the downloaded zip file and run the OpenAIDR setup program
          inside it, or run the setup program directly if your administrator
          supplied one. It installs OpenAIDR for your Windows account without
          administrator approval. Open OpenAIDR from the Start
          menu. Automatic updates are not yet available on Windows; ask your
          administrator for later versions.
        </>
      ),
    },
    linux: {
      label: "Linux",
      installers: [
        { name: "Linux", url: installerUrl(process.env.OPENAIDR_DESKTOP_LINUX_X64_URL, LATEST_INSTALLERS.linuxX64) },
      ],
      before: <>The package is for 64-bit Ubuntu or Debian on an Intel or AMD processor.</>,
      after: (
        <>
          In a terminal, go to the folder that contains the download and run{" "}
          <code className="whitespace-nowrap rounded-sm bg-muted px-1 font-mono">sudo apt-get install ./</code>{" "}
          followed by the downloaded file name. Installing needs administrator
          (sudo) rights. Open OpenAIDR from your applications menu or run{" "}
          <code className="rounded-sm bg-muted px-1 font-mono">openaidr-desktop</code>.
          Automatic updates are not yet available on Linux; ask your
          administrator for later versions.
        </>
      ),
    },
  };
}

function PlatformInstall({ guide, heading }: { guide: PlatformGuide; heading?: ReactNode }) {
  const missing = guide.installers.filter((installer) => !installer.url);
  return (
    <div className="space-y-3">
      {heading}
      <p className="text-sm text-muted-foreground">{guide.before}</p>
      {missing.length < guide.installers.length && (
        <div className="flex flex-wrap gap-3">
          {guide.installers.filter((installer) => installer.url).map((installer) => (
            <a
              key={installer.name}
              href={installer.url!}
              className={buttonVariants({ variant: "outline", size: "lg" })}
              rel="noreferrer"
              referrerPolicy="no-referrer"
            >
              Download for {installer.name}
            </a>
          ))}
        </div>
      )}
      {missing.length > 0 && (
        <p className="text-sm text-muted-foreground">
          Ask your administrator for the approved OpenAIDR installer for{" "}
          {missing.map((installer) => installer.name).join(" or ")}.
        </p>
      )}
      <p className="text-sm text-muted-foreground">{guide.after}</p>
    </div>
  );
}

function PlatformHeading({ guide }: { guide: PlatformGuide }) {
  return <h3 className="text-sm font-semibold">OpenAIDR for {guide.label}</h3>;
}

export default async function EnrollmentLink() {
  const guides = platformGuides();
  const detected = detectDesktopPlatform((await headers()).get("user-agent"));
  const others = platforms.filter((platform) => platform !== detected);

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <section className="w-full max-w-xl space-y-6 rounded-lg border bg-card p-6">
        <div className="flex items-center gap-3">
          <img src="/icon.svg" alt="" width={28} height={28} />
          <span className="text-base font-semibold">OpenAIDR</span>
        </div>
        <h1 className="text-display font-semibold">Connect your device</h1>
        <ol className="space-y-6">
          <li className="space-y-3">
            <h2 className="text-base font-semibold">
              1. Install OpenAIDR{detected && ` for ${guides[detected].label}`}
            </h2>
            {detected ? (
              <PlatformInstall guide={guides[detected]} />
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  Choose the installer for this computer&apos;s operating system.
                </p>
                <div className="space-y-6">
                  {others.map((platform) => (
                    <PlatformInstall
                      key={platform}
                      guide={guides[platform]}
                      heading={<PlatformHeading guide={guides[platform]} />}
                    />
                  ))}
                </div>
              </>
            )}
            <p className="text-sm text-muted-foreground">
              Already installed? Continue to step 2.
            </p>
            {detected && (
              <PageNotice
                collapsible
                title={`Installing on ${others.map((platform) => guides[platform].label).join(" or ")}?`}
              >
                <div className="space-y-6 pt-1">
                  {others.map((platform) => (
                    <PlatformInstall
                      key={platform}
                      guide={guides[platform]}
                      heading={<PlatformHeading guide={guides[platform]} />}
                    />
                  ))}
                </div>
              </PageNotice>
            )}
          </li>
          <li className="space-y-3">
            <h2 className="text-base font-semibold">2. Connect to your organization</h2>
            <p className="text-sm text-muted-foreground">
              Open OpenAIDR and paste this full enrollment link from the address
              bar into the main window. Review the organization, then choose Connect.
              Follow the setup guidance and restart your coding agents when asked.
            </p>
          </li>
        </ol>
        <PageNotice collapsible title="Need help installing or connecting?">
          <p>
            If macOS blocks the app, confirm that your administrator supplied it.
            They can confirm whether to use System Settings &gt; Privacy &amp;
            Security &gt; Open Anyway. Your Mac may require administrator approval.
          </p>
          <p>
            If Microsoft Defender SmartScreen stops the Windows installer, confirm
            that your administrator supplied it. They can confirm whether to choose
            More info &gt; Run anyway.
          </p>
          <p>
            If OpenAIDR cannot verify your organization&apos;s server certificate,
            ask your administrator for its public CA certificate file. After
            pasting the enrollment link in OpenAIDR, expand Private server
            certificate (optional) and choose that PEM file. Keep certificate
            verification enabled. For older apps without this option, ask your
            administrator to configure the trusted certificate with the sensor CLI.
            For a Linux server without a desktop, ask for your organization&apos;s
            sensor CLI instructions.
          </p>
        </PageNotice>
        <p className="text-sm text-muted-foreground">
          Opening this page leaves the link available. Each device enrollment uses
          one of the allowed uses. Your administrator sets the use limit and expiration.
        </p>
      </section>
    </main>
  );
}
