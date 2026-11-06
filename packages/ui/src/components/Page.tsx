import type { ReactNode } from "react";
import { Link } from "react-router";
import { Button } from "./Form";
import { errorMessage } from "../api/client";

export function PageHeader({ title, description, actions, crumbs }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; crumbs?: { label: string; to?: string }[] }) {
  return (
    <div>
      {crumbs && crumbs.length > 0 && (
        <nav className="breadcrumbs" aria-label="Breadcrumb">
          {crumbs.map((c, i) => <span key={i}>{c.to ? <Link to={c.to}>{c.label}</Link> : c.label}{i < crumbs.length - 1 && <span aria-hidden="true"> / </span>}</span>)}
        </nav>
      )}
      <div className="page-header">
        <div><h1>{title}</h1>{description && <p>{description}</p>}</div>
        {actions && <div className="page-header__actions">{actions}</div>}
      </div>
    </div>
  );
}

export function Card({ title, sub, actions, children, flush, footer, className }: { title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; footer?: ReactNode; className?: string }) {
  return (
    <section className={`card${className ? ` ${className}` : ""}`}>
      {(title || actions) && (
        <div className="card__header">
          <div><h2 className="card__title">{title}</h2>{sub && <p className="card__sub">{sub}</p>}</div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={`card__body${flush ? " card__body--flush" : ""}`}>{children}</div>
      {footer && <div className="card__footer">{footer}</div>}
    </section>
  );
}

export function Tabs<T extends string>({ value, tabs, onChange }: { value: T; tabs: { value: T; label: string; count?: number }[]; onChange: (v: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.value} role="tab" type="button" aria-selected={t.value === value} onClick={() => onChange(t.value)}>
          {t.label}{t.count !== undefined && <span className="muted"> {t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><strong>{title}</strong>{children}</div>;
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return <div className="error-state" role="alert"><span>{errorMessage(error)}</span>{onRetry && <Button size="sm" onClick={onRetry}>Retry</Button>}</div>;
}

export function Skeleton({ rows = 5, height = 14 }: { rows?: number; height?: number }) {
  return <div className="stack" style={{ gap: 10, padding: 12 }} aria-busy="true" aria-label="Loading">{Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" style={{ height, width: `${70 + ((i * 13) % 30)}%` }} />)}</div>;
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return <dl className="kv">{items.map(([k, v]) => <div key={k} style={{ display: "contents" }}><dt>{k}</dt><dd>{v ?? <span className="muted">none</span>}</dd></div>)}</dl>;
}

export function Callout({ tone, children }: { tone?: "warn" | "danger" | "success"; children: ReactNode }) {
  return <div className={`callout${tone ? ` callout--${tone}` : ""}`}>{children}</div>;
}
