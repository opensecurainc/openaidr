import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardTitle } from "@/components/ui/card";

/* The AI Inventory, AI Supply Chain and AI Skills pages share these summary
   cards so their type, spacing and states match when moving between pages. */
export function OverviewGrid({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section aria-label={label} className="grid min-w-0 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {children}
    </section>
  );
}

export function OverviewCard({ title, value, detail, icon: Icon, primary = false, onSelect, children }: {
  title: string;
  /** A count renders as a large figure; any other text, such as "Unavailable", renders as a status. */
  value: string;
  detail: string;
  icon: LucideIcon;
  primary?: boolean;
  onSelect?: () => void;
  children?: ReactNode;
}) {
  const muted = primary ? "" : "text-muted-foreground";
  return (
    <Card role="group" aria-label={title}
      className={`min-w-0 gap-2 p-4 ${primary ? "border-transparent bg-primary text-primary-foreground" : ""}`}>
      <CardTitle className="flex items-center justify-between gap-2 text-sm font-medium">
        {onSelect ? (
          <button className="text-left underline-offset-4 hover:underline focus-visible:outline focus-visible:outline-2" onClick={onSelect}>
            {title}
          </button>
        ) : title}
        <Icon aria-hidden="true" className={`size-4 shrink-0 ${muted}`} />
      </CardTitle>
      <p className="flex min-h-8 items-center">
        {/^[\d,.]+[%+]?$/u.test(value)
          ? <span className="figure number text-display font-semibold">{value}</span>
          : <span className={`text-base font-semibold ${muted}`}>{value}</span>}
      </p>
      <p className={`text-xs ${muted}`}>{detail}</p>
      {children}
    </Card>
  );
}
