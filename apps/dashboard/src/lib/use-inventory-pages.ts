"use client";

import { usePagedResource } from "@/lib/use-resource";

export const inventorySources = {
  "osquery-npm-packages": "npm packages",
  "osquery-python-packages": "Python packages",
  "openaidr-mcp-servers": "MCP servers",
  "openaidr-plugins": "Plugins",
  "openaidr-skills": "Skills",
};
export type InventorySource = keyof typeof inventorySources;
export const supplyChainSources = ["osquery-npm-packages", "osquery-python-packages", "openaidr-mcp-servers", "openaidr-plugins"] as const;
export type SupplyChainSource = typeof supplyChainSources[number];

/** Each category retains its own opaque cursor and failure state. */
export function useInventoryPages<T extends { id: string }>(
  resource: "components" | "roots",
  source: InventorySource | "all",
  filters: URLSearchParams,
) {
  const path = (category: InventorySource | null) => category
    ? `inventory/${resource}?${new URLSearchParams({ ...Object.fromEntries(filters), source: category })}`
    : null;
  const first = usePagedResource<T>(path(source === "all" ? "osquery-npm-packages" : source));
  const python = usePagedResource<T>(path(source === "all" ? "osquery-python-packages" : null));
  const mcp = usePagedResource<T>(path(source === "all" ? "openaidr-mcp-servers" : null));
  const plugins = usePagedResource<T>(path(source === "all" ? "openaidr-plugins" : null));
  const bySource: Partial<Record<InventorySource, ReturnType<typeof usePagedResource<T>>>> = source === "all"
    ? { "osquery-npm-packages": first, "osquery-python-packages": python, "openaidr-mcp-servers": mcp, "openaidr-plugins": plugins }
    : { [source]: first };
  if (source !== "all") return { ...first, bySource };
  const pages = [first, python, mcp, plugins];
  const labels = ["npm packages", "Python packages", "MCP servers", "Plugins"];
  const items = [...new Map(pages.flatMap((page) => page.items).map((item) => [item.id, item])).values()];
  return {
    bySource,
    items,
    // Only a presence marker: each hook sends its own backend cursor.
    nextCursor: pages.some((page) => page.nextCursor) ? "more" : "",
    loading: pages.some((page) => page.loading),
    loadingMore: pages.some((page) => page.loadingMore),
    error: pages.flatMap((page, index) => page.error ? [`${labels[index]}: ${page.error}`] : []).join("; "),
    loadMore: () => pages.forEach((page) => page.loadMore()),
    reload: () => pages.forEach((page) => page.reload()),
    updated: pages.every((page) => page.updated) ? first.updated : null,
  };
}
