import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { TimeZoneProvider } from "@/components/time-zone-context";
import "./globals.css";
export const metadata: Metadata = {
  title: { default: "OpenAIDR", template: "%s · OpenAIDR" },
  description: "Your organization’s agent telemetry, in one place.",
  icons: { icon: "/icon.svg" },
  robots: { index: false, follow: false },
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    // next/font serves Geist from this build and preloads it; nothing loads
    // from a CDN. The classes define --font-geist-sans and --font-geist-mono.
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <TimeZoneProvider>{children}</TimeZoneProvider>
      </body>
    </html>
  );
}
