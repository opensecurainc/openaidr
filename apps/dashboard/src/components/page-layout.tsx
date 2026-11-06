"use client";

import { useId, type ReactNode } from "react";
import {
  ChevronRight,
  Info,
  Inbox,
  RefreshCw,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

/** Section headings are h2: the shared shell already owns the page's h1. */
export function PageSection({
  title,
  titleAction,
  description,
  action,
  children,
  className,
}: {
  title: string;
  titleAction?: ReactNode;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={className}>
      <Card className="overflow-hidden">
        {/* Actions sit beside the title while it keeps at least 240px, and
            wrap below it on narrow cards. */}
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="min-w-60 flex-1">
            <div className="flex items-center gap-2">
              <h2 id={id} className="text-base font-semibold">
                {title}
              </h2>
              {titleAction}
            </div>
            {description && (
              <p className="mt-0.5 text-sm text-muted-foreground">
                {description}
              </p>
            )}
          </div>
          {action && (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              {action}
            </div>
          )}
        </CardHeader>
        <CardContent data-slot="section-body">{children}</CardContent>
      </Card>
    </section>
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
}: {
  title: string;
  description: string;
  icon?: LucideIcon;
  action?: ReactNode;
}) {
  return (
    <div className="flex min-h-32 flex-col items-center justify-center px-4 py-6 text-center">
      <Icon aria-hidden="true" className="mb-2 size-5 text-muted-foreground" />
      <p className="text-sm font-semibold">{title}</p>
      <p className="mt-1 max-w-lg text-sm text-muted-foreground">
        {description}
      </p>
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function PageNotice({
  title,
  children,
  collapsible = false,
}: {
  title: string;
  children: ReactNode;
  collapsible?: boolean;
}) {
  if (collapsible) {
    return (
      <details className="group min-w-0 text-sm">
        <summary className="flex min-h-10 w-fit max-w-full cursor-pointer list-none items-center gap-2 rounded-md py-1 text-left font-medium text-muted-foreground outline-none hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring focus-visible:ring-offset-2 sm:min-h-8 [&::-webkit-details-marker]:hidden">
          <Info aria-hidden="true" className="size-4 shrink-0" />
          <span className="min-w-0">{title}</span>
          <ChevronRight aria-hidden="true" className="size-3.5 shrink-0 group-open:rotate-90" />
        </summary>
        <div className="mt-1 max-w-3xl space-y-2 pl-6 text-foreground">
          {children}
        </div>
      </details>
    );
  }
  return (
    <aside className="flex gap-3 rounded-md border-l-4 border-status-info/50 bg-status-info/5 px-4 py-3">
      <Info
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-status-info"
      />
      <div className="min-w-0 text-sm">
        <p className="font-semibold">{title}</p>
        <div className="mt-1 text-muted-foreground">{children}</div>
      </div>
    </aside>
  );
}

export function LoadingState({ label = "Loading data…" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <p className="text-sm text-muted-foreground">{label}</p>
      <div aria-hidden="true" className="space-y-2 py-4">
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-7 w-full" />
        <Skeleton className="h-7 w-11/12" />
        <Skeleton className="h-7 w-full" />
      </div>
    </div>
  );
}

export function ErrorState({
  title = "Unable to load data",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-start gap-3 rounded-md border-l-4 border-status-warning bg-status-warning/10 px-4 py-3 text-foreground"
    >
      <TriangleAlert
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-status-warning"
      />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold">{title}</p>
        <p className="mt-1 text-sm">{message}</p>
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" />
          Retry
        </Button>
      )}
    </div>
  );
}

export function PageToolbar({
  children,
  action,
}: {
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
        {children}
      </div>
      {action && (
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {action}
        </div>
      )}
    </div>
  );
}

/** Put the existing Table primitive inside this keyboard-scrollable boundary. */
export function TableLayout({
  children,
  footer,
}: {
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    // Inside a PageSection the table runs edge to edge, so the card border is
    // the only frame; elsewhere it keeps its own border.
    <div
      data-slot="table-layout"
      className="min-w-0 overflow-hidden rounded-md border [&_:is(th,td):first-child]:pl-4 [&_:is(th,td):last-child]:pr-4 in-data-[slot=section-body]:-mx-4 in-data-[slot=section-body]:rounded-none in-data-[slot=section-body]:border-x-0 in-data-[slot=section-body]:last:-mb-4 in-data-[slot=section-body]:last:border-b-0"
    >
      <div
        tabIndex={0}
        role="region"
        aria-label="Scrollable data table"
        className="overflow-x-auto focus-visible:outline-2 focus-visible:outline-ring [&_[data-slot=table-container]]:overflow-visible"
      >
        {children}
      </div>
      {footer && (
        <div className="border-t px-4 py-2 text-xs text-muted-foreground">
          {footer}
        </div>
      )}
    </div>
  );
}

export function SettingsLayout({ children }: { children: ReactNode }) {
  return (
    <div className="grid min-w-0 grid-cols-1 items-start gap-4 xl:grid-cols-2">
      {children}
    </div>
  );
}

export function CollectionFooter({
  count,
  hasMore,
  busy,
  onLoadMore,
  label = "items",
}: {
  count: number;
  hasMore: boolean;
  busy: boolean;
  onLoadMore: () => void;
  label?: string;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
      <p>
        {count.toLocaleString()} {label} loaded
      </p>
      {hasMore && (
        <Button
          variant="outline"
          size="sm"
          disabled={busy}
          onClick={onLoadMore}
        >
          {busy ? "Loading…" : "Load more"}
        </Button>
      )}
    </div>
  );
}
