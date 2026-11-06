"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Building2,
  ChevronRight,
  LoaderCircle,
  LogOut,
  Menu,
  RefreshCw,
  SlidersHorizontal,
  TriangleAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Status } from "@/components/ui/status";
import { navigation, findNavigationPage, type NavigationPage } from "@/lib/navigation";
import { api } from "@/lib/api";
import { canAccessPage, roleNames } from "@/lib/roles";
import { PageNotice } from "@/components/page-layout";
import { InventoryTutorial } from "@/components/inventory-tutorial";
import { cn } from "@/lib/utils";
import { useDashboard } from "./dashboard-context";
import { PageChat } from "./page-chat";
import { ContactSupport } from "./support";
import { useTimeZone } from "./time-zone-context";
import { TimeZoneControl } from "./ui/time-zone-control";

const BUILD_COMMIT = process.env.NEXT_PUBLIC_BUILD_COMMIT ?? "";
const BUILD_VERSION = process.env.NEXT_PUBLIC_BUILD_VERSION ?? "";
const BUILD_TIME = process.env.NEXT_PUBLIC_BUILD_TIME ?? "";

/** Display source identity; the tooltip preserves the actual build timestamp. */
function BuildInfo() {
  const { timeZone, localZone } = useTimeZone();
  const built = new Date(BUILD_TIME);
  // The provider resolves the browser zone after hydration.
  const date = localZone && !Number.isNaN(built.getTime())
    ? built.toLocaleString(undefined, {
        timeZone,
        dateStyle: "medium",
        timeStyle: "long",
      })
    : BUILD_TIME;
  if (!date && !BUILD_COMMIT) return null;
  return (
    <p
      data-slot="build-info"
      className="hidden text-xs whitespace-nowrap text-muted-foreground xl:block"
      title={[BUILD_TIME && `Built ${BUILD_TIME}`, BUILD_COMMIT && `commit ${BUILD_COMMIT}`]
        .filter(Boolean)
        .join(", ")}
    >
      OpenAIDR {BUILD_VERSION}
      {date && <> · Built {date}</>}
    </p>
  );
}

function SidebarContents({
  activePath,
  onNavigate,
}: {
  activePath?: string;
  onNavigate?: () => void;
}) {
  const { user, logout } = useDashboard();
  if (!user) return null;
  return (
    <>
      <div className="shrink-0 border-b border-white/10 px-4 pb-3 pt-4">
        <Link
          href="/"
          onClick={onNavigate}
          className="flex items-center gap-3 rounded-md px-1 focus-visible:outline-2 focus-visible:outline-white"
        >
          <img src="/icon-dark.svg" alt="" width={32} height={32} />
          <span className="text-base font-semibold text-white">OpenAIDR</span>
        </Link>
        <div className="mt-3 flex items-center gap-2 px-1 text-xs text-sidebar-foreground">
          <Building2 aria-hidden="true" className="size-3.5 shrink-0 opacity-70" />
          <span className="truncate font-medium" title={user.tenant.name}>
            {user.tenant.name}
          </span>
        </div>
      </div>
      <nav
        aria-label="Workspace navigation"
        className="sidebar-navigation min-h-0 flex-1 space-y-3 overflow-y-auto overscroll-contain px-3 py-3"
      >
        {navigation.map((group) => ({ ...group, pages: group.pages.filter((page) => canAccessPage(user, page.path)) })).filter((group) => group.pages.length).map((group) => (
          <div key={group.title}>
            <p className="mb-1 px-3 text-xs font-semibold leading-5 text-sidebar-foreground/75">
              {group.title}
            </p>
            <ul>
              {group.pages.map(({ path, title, navTitle, icon: Icon }: NavigationPage) => (
                <li key={path}>
                  <Link
                    href={path}
                    onClick={onNavigate}
                    aria-current={activePath === path ? "page" : undefined}
                    className={cn(
                      "relative flex min-h-10 items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-white lg:min-h-7 lg:py-1",
                      activePath === path
                        ? "bg-white/10 font-semibold text-white before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-full before:bg-white"
                        : "text-sidebar-foreground hover:bg-white/5 hover:text-white",
                    )}
                  >
                    <Icon
                      aria-hidden="true"
                      className={cn(
                        "size-4 shrink-0",
                        activePath === path ? "text-white" : "opacity-70",
                      )}
                      strokeWidth={1.7}
                    />
                    <span>{navTitle ?? title}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <div className="flex shrink-0 items-center gap-3 border-t border-white/10 bg-sidebar px-4 py-2.5">
        <span
          aria-hidden="true"
          className="flex size-8 shrink-0 items-center justify-center rounded-full bg-white/10 text-xs font-semibold text-white"
        >
          {(user.name || user.email).slice(0, 2).toUpperCase()}
        </span>
        <div className="min-w-0">
          <p
            className="truncate text-xs font-medium text-white"
            title={user.name || user.email}
          >
            {user.name || user.email}
          </p>
          <p className="text-xs text-sidebar-foreground/75">
            {roleNames(user.roles)}
          </p>
        </div>
        <button
          onClick={() => void logout()}
          title="Sign out"
          aria-label="Sign out"
          className="ml-auto flex size-8 shrink-0 items-center justify-center rounded-md text-sidebar-foreground hover:bg-white/10 hover:text-white focus-visible:outline-2 focus-visible:outline-white"
        >
          <LogOut className="size-4" />
        </button>
      </div>
    </>
  );
}

/** Use only where range and service filters apply to native telemetry. */
export function TelemetryFilters() {
  const { range, service, setRange, setService, data } = useDashboard();
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SlidersHorizontal
        aria-hidden="true"
        size={16}
        className="mr-1 text-muted-foreground"
      />
      <Select value={range} onValueChange={setRange}>
        <SelectTrigger
          aria-label="Time range"
          className="w-40"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="24h">Last 24 hours</SelectItem>
          <SelectItem value="7d">Last 7 days</SelectItem>
          <SelectItem value="30d">Last 30 days</SelectItem>
        </SelectContent>
      </Select>
      <Select
        value={service ? "service:" + service : "all"}
        onValueChange={(value) =>
          setService(value === "all" ? "" : value.slice(8))
        }
      >
        <SelectTrigger
          aria-label="Service filter"
          className="w-48"
        >
          <SelectValue placeholder="All services" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All services</SelectItem>
          {[
            ...new Set([
              ...(data?.available_services || []),
              ...(service ? [service] : []),
            ]),
          ].map((name) => (
            <SelectItem key={name} value={`service:${name}`}>
              {name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {service && (
        <Button variant="ghost" onClick={() => setService("")}>
          Clear filter
        </Button>
      )}
    </div>
  );
}

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const { mode, setMode, localZone, timeZone } = useTimeZone();
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);
  const { user, authLoading, error, data, loading, refresh, updated } =
    useDashboard();
  const current = findNavigationPage(pathname);
  const activePath = pathname.startsWith("/gateways/instances/") ? "/gateways/overview" : current?.page.path;
  const allowed = canAccessPage(user, pathname);
  const lastVisit = useRef("");
  const pagePath = current?.page.path;
  const userId = user?.id;
  const tenantId = user?.tenant.id;
  useEffect(() => {
    const path = pathname.replace(/\/$/, "") || "/";
    if (!allowed || authLoading || !userId || !tenantId || pagePath !== path) {
      lastVisit.current = "";
      return;
    }
    const visit = `${tenantId}:${userId}:${path}`;
    if (lastVisit.current === visit) return;
    lastVisit.current = visit;
    // Navigation reports are best effort, with no retries or query-string capture.
    void api("audit/page-views", {
      method: "POST",
      body: JSON.stringify({ path }),
      keepalive: true,
      signal: AbortSignal.timeout(5000),
    }).catch(() => {});
  }, [allowed, authLoading, userId, tenantId, pagePath, pathname]);
  const title = current?.page.title || "Page not found";
  const compactHeading = pathname === "/ai-supply-chain";
  const showFilters = allowed && current?.page.telemetryFilters === true;
  const showTelemetry =
    allowed && (showFilters || current?.page.telemetryStatus === true);
  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);
  useEffect(() => {
    const viewport = window.matchMedia("(min-width: 1024px)");
    const close = () => {
      if (viewport.matches) setMenuOpen(false);
    };
    viewport.addEventListener("change", close);
    return () => viewport.removeEventListener("change", close);
  }, []);
  if (authLoading)
    return (
      <div
        role="status"
        className="flex min-h-screen items-center justify-center gap-3 text-sm text-muted-foreground"
      >
        <LoaderCircle className="animate-spin" size={20} />
        Loading workspace…
      </div>
    );
  if (!user)
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-5 p-8">
        <h1 className="text-base font-semibold">
          {error ? "Workspace unavailable" : "Opening sign in…"}
        </h1>
        {error && (
          <>
            <p
              role="alert"
              className="max-w-md text-center text-sm text-muted-foreground"
            >
              {error}
            </p>
            <Button onClick={() => window.location.reload()}>Try again</Button>
            <Link href="/login" className="text-sm text-primary underline">
              Go to sign in
            </Link>
          </>
        )}
      </div>
    );
  return (
    <div className="min-h-screen">
      <a
        href="#main-content"
        className="sr-only z-50 rounded-md bg-card p-3 text-sm focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col bg-sidebar text-sidebar-foreground lg:flex">
        <SidebarContents activePath={activePath} />
      </aside>
      <div className="min-w-0 lg:ml-64">
        <header className="sticky top-0 z-20 flex min-h-14 items-center justify-between gap-3 border-b bg-card px-4 py-2 sm:min-h-12 sm:py-1.5 md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <Dialog open={menuOpen} onOpenChange={setMenuOpen}>
              <DialogTrigger asChild>
                <Button
                  variant="ghost"
                  size="header-icon"
                  className="shrink-0 lg:hidden"
                  aria-label="Open navigation"
                >
                  <Menu className="size-5" />
                </Button>
              </DialogTrigger>
              <DialogContent className="left-0 top-0 flex h-dvh w-[min(340px,calc(100%-2rem))] max-w-none translate-x-0 translate-y-0 flex-col gap-0 rounded-none border-0 bg-sidebar p-0 text-sidebar-foreground shadow-overlay sm:max-w-[340px]">
                <DialogTitle className="sr-only">
                  Workspace navigation
                </DialogTitle>
                <DialogDescription className="sr-only">
                  Choose a page or sign out of your account.
                </DialogDescription>
                <SidebarContents
                  activePath={activePath}
                  onNavigate={() => setMenuOpen(false)}
                />
              </DialogContent>
            </Dialog>
            <nav aria-label="Breadcrumb" className="min-w-0 text-sm">
              <ol className="flex items-center gap-2">
                {current && current.group !== title && (
                  <>
                    <li className="hidden shrink-0 text-muted-foreground sm:block">{current.group}</li>
                    <li aria-hidden="true" className="hidden shrink-0 sm:block">
                      <ChevronRight
                        size={12}
                        className="text-muted-foreground"
                      />
                    </li>
                  </>
                )}
                <li aria-current="page" className="min-w-0 truncate font-medium" title={title}>
                  {title}
                </li>
              </ol>
            </nav>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <TimeZoneControl value={mode} onChange={setMode} localZone={localZone} />
            {allowed && <PageChat
              key={`${user.tenant.id}:${user.id}:${roleNames(user.roles)}:${pathname}`}
              path={pathname}
              title={title}
            />}
            <div className="hidden flex-col items-end gap-0.5 sm:flex">
              {showTelemetry && (
                <Status tone={error ? "warning" : updated ? "ok" : "neutral"}>
                  {error ? "Data delayed" : updated ? "Connected" : "Connecting"}
                </Status>
              )}
              <BuildInfo />
            </div>
            <span aria-hidden="true" className="hidden h-6 border-l sm:block" />
            <ContactSupport key={`${user.tenant.id}:${user.id}:${roleNames(user.roles)}`} />
          </div>
        </header>
        <main
          id="main-content"
          data-overview={pathname === "/" || undefined}
          tabIndex={-1}
          className={`mx-auto max-w-[1560px] px-4 outline-none md:px-6 ${compactHeading ? "py-3" : "pb-8 pt-5"}`}
        >
          <div className={`flex flex-wrap items-end justify-between gap-4 ${compactHeading ? "mb-2" : "mb-4"}`}>
            <div className={compactHeading ? "flex min-w-0 flex-wrap items-baseline gap-x-4 gap-y-1" : "min-w-0"}>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-display font-semibold">
                  {title}
                </h1>
                {allowed && current?.page.path === "/ai-inventory" && (
                  <InventoryTutorial />
                )}
              </div>
              {current && (
                <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
                  {current.page.description}
                </p>
              )}
            </div>
            {showFilters && (
              <Button variant="outline" onClick={refresh} disabled={loading}>
                <RefreshCw className={loading ? "animate-spin" : ""} />
                {loading ? "Refreshing" : "Refresh"}
              </Button>
            )}
          </div>
          {showFilters && (
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <TelemetryFilters />
              <p className="text-xs text-muted-foreground">
                {updated
                  ? `Updated ${updated.toLocaleTimeString([], { timeZone, hour: "2-digit", minute: "2-digit" })} · refreshes every 30s`
                  : "Waiting for telemetry overview"}
              </p>
            </div>
          )}
          {showTelemetry && error && (
            <div
              role="alert"
              className="mb-4 flex items-start gap-3 rounded-md border-l-4 border-status-warning bg-status-warning/10 px-4 py-3 text-sm"
            >
              <TriangleAlert
                aria-hidden="true"
                className="mt-0.5 size-4 shrink-0 text-status-warning"
              />
              <div>
                <strong className="font-semibold">
                  Unable to refresh telemetry.
                </strong>{" "}
                {error}
                {data && <span> Showing the last successful response.</span>}
                <button
                  onClick={refresh}
                  className="ml-2 font-medium text-primary underline underline-offset-2"
                >
                  Retry
                </button>
              </div>
            </div>
          )}
          {allowed ? (
            <div key={`${user.tenant.id}:${user.id}:${user.roles.join(",")}`} className="fade-in min-w-0">{children}</div>
          ) : (
            <PageNotice title="Access restricted">
              <p>Your assigned roles do not include access to this page. Contact an IT Admin to change your roles.</p>
              <Link href="/" className="text-primary underline">Go to Overview</Link>
            </PageNotice>
          )}
        </main>
      </div>
    </div>
  );
}
