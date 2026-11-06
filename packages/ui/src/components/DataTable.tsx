import { useMemo, useState, type ReactNode } from "react";
import { Button } from "./Form";
import { EmptyState, ErrorState, Skeleton } from "./Page";
import { IconArrowDown, IconArrowUp } from "./icons";

export interface Column<T> {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  /** Value used for client-side sorting. Omit to disable sorting on this column. */
  sortValue?: (row: T) => string | number | null | undefined;
  align?: "left" | "right";
  width?: string | number;
  className?: string;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  loading?: boolean;
  stale?: boolean;
  error?: unknown;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyBody?: ReactNode;
  onRowClick?: (row: T) => void;
  rowHref?: (row: T) => string;
  expanded?: (row: T) => ReactNode;
  /** Cursor pagination: called with the next cursor. */
  nextCursor?: string;
  onNext?: (cursor: string) => void;
  onPrev?: () => void;
  hasPrev?: boolean;
  compact?: boolean;
  defaultSort?: { key: string; dir: "asc" | "desc" };
  caption?: string;
  footer?: ReactNode;
}

export function DataTable<T>({ columns, rows, rowKey, loading, stale, error, onRetry, emptyTitle = "Nothing here", emptyBody, onRowClick, expanded, nextCursor, onNext, onPrev, hasPrev, compact, defaultSort, caption, footer }: DataTableProps<T>) {
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" } | undefined>(defaultSort);
  const [open, setOpen] = useState<Set<string>>(new Set());

  const sorted = useMemo(() => {
    if (!rows || !sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const sv = col.sortValue;
    return [...rows].sort((a, b) => {
      const va = sv(a) ?? "", vb = sv(b) ?? "";
      const r = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
      return sort.dir === "asc" ? r : -r;
    });
  }, [rows, sort, columns]);

  const toggleSort = (key: string) => setSort((s) => (s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  const toggleOpen = (k: string) => setOpen((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (loading && !rows) return <Skeleton rows={6} />;

  const activate = (row: T) => {
    if (expanded) toggleOpen(rowKey(row));
    onRowClick?.(row);
  };
  const clickable = !!(onRowClick || expanded);

  return (
    <div className={stale ? "is-stale" : undefined}>
      <div className="table-wrap">
        <table className={`table${compact ? " table--compact" : ""}`}>
          {caption && <caption className="visually-hidden">{caption}</caption>}
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={c.align === "right" ? "num" : c.className} style={{ width: c.width }} aria-sort={sort?.key === c.key ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}>
                  {c.sortValue ? (
                    <button type="button" onClick={() => toggleSort(c.key)}>
                      {c.header}{sort?.key === c.key && (sort.dir === "asc" ? <IconArrowUp width={12} height={12} /> : <IconArrowDown width={12} height={12} />)}
                    </button>
                  ) : c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted && sorted.length === 0 && (
              <tr><td colSpan={columns.length}><EmptyState title={emptyTitle}>{emptyBody}</EmptyState></td></tr>
            )}
            {sorted?.map((row) => {
              const k = rowKey(row);
              const isOpen = expanded ? open.has(k) : false;
              return (
                <RowGroup key={k}>
                  <tr
                    className={clickable ? "is-clickable" : undefined}
                    tabIndex={clickable ? 0 : undefined}
                    aria-expanded={expanded ? isOpen : undefined}
                    onClick={clickable ? () => activate(row) : undefined}
                    onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(row); } } : undefined}
                  >
                    {columns.map((c) => <td key={c.key} className={c.align === "right" ? "num" : c.className}>{c.render(row)}</td>)}
                  </tr>
                  {expanded && isOpen && <tr className="table__expand"><td colSpan={columns.length}>{expanded(row)}</td></tr>}
                </RowGroup>
              );
            })}
          </tbody>
        </table>
      </div>
      {(footer || onNext || onPrev) && (
        <div className="table__toolbar">
          <span>{footer ?? (sorted ? `${sorted.length} row${sorted.length === 1 ? "" : "s"}` : "")}</span>
          {(onNext || onPrev) && (
            <span className="row">
              {onPrev && <Button size="sm" onClick={onPrev} disabled={!hasPrev}>Previous</Button>}
              {onNext && <Button size="sm" onClick={() => nextCursor && onNext(nextCursor)} disabled={!nextCursor}>Next</Button>}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function RowGroup({ children }: { children: ReactNode }) { return <>{children}</>; }

/** Keeps a cursor history so tables can page back without server support. */
export function useCursorPager(current: string, setCursor: (c: string | undefined) => void) {
  const [history, setHistory] = useState<string[]>([]);
  return {
    onNext: (next: string) => { setHistory((h) => [...h, current]); setCursor(next); },
    onPrev: () => { setHistory((h) => { const prev = h[h.length - 1]; setCursor(prev || undefined); return h.slice(0, -1); }); },
    hasPrev: history.length > 0 || !!current,
    reset: () => setHistory([]),
  };
}
