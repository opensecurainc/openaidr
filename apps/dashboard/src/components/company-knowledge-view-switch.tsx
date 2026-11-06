import Link from "next/link";
import { cn } from "@/lib/utils";

const views = [
  ["current", "/company-knowledge", "Current"],
  ["policy", "/company-knowledge/preview/policy", "Policy preview"],
  ["guardrails", "/company-knowledge/preview/guardrails", "Guardrail preview"],
] as const;

export type CompanyKnowledgeView = (typeof views)[number][0];

/** Switches between Company Policy and Knowledge and its sample-data layout previews. */
export function CompanyKnowledgeViewSwitch({ view }: { view: CompanyKnowledgeView }) {
  return (
    <nav aria-label="Company Policy and Knowledge view" className="flex justify-end">
      <div className="inline-flex h-10 rounded-md border border-input bg-card p-[3px] text-xs font-medium sm:h-8 sm:text-sm">
        {views.map(([id, href, label]) => (
          <Link
            key={id}
            href={href}
            aria-current={id === view ? "page" : undefined}
            className={cn(
              "flex items-center rounded-sm px-3 outline-none focus-visible:ring-[3px] focus-visible:ring-ring",
              id === view
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
