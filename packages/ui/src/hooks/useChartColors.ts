import { useEffect, useState } from "react";

export interface ChartColors { cat: string[]; grid: string; muted: string; text: string; textMuted: string; surface: string; sev: Record<string, string>; accent: string }

function read(): ChartColors {
  const cs = getComputedStyle(document.documentElement);
  const v = (name: string) => cs.getPropertyValue(name).trim();
  return {
    cat: [1, 2, 3, 4, 5, 6, 7].map((i) => v(`--cat-${i}`)),
    grid: v("--chart-grid"), muted: v("--chart-muted"), text: v("--text"), textMuted: v("--text-muted"), surface: v("--surface"), accent: v("--accent"),
    sev: { critical: v("--sev-critical"), high: v("--sev-high"), medium: v("--sev-medium"), low: v("--sev-low"), info: v("--sev-info") },
  };
}

/** Resolves chart color tokens from CSS and follows theme changes. */
export function useChartColors(): ChartColors {
  const [c, setC] = useState<ChartColors>(read);
  useEffect(() => {
    const update = () => setC(read());
    const mo = new MutationObserver(update);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", update);
    return () => { mo.disconnect(); mq.removeEventListener("change", update); };
  }, []);
  return c;
}
