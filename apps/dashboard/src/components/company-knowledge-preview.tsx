"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { CompanyKnowledgeViewSwitch, type CompanyKnowledgeView } from "@/components/company-knowledge-view-switch";
import { ErrorState, LoadingState, PageNotice } from "@/components/page-layout";

/**
 * Embeds a self-contained layout preview with its own illustrative sample
 * data. The preview reads no tenant data and makes no API requests.
 */
export function CompanyKnowledgePreview({
  view,
  src,
  name,
}: {
  view: Exclude<CompanyKnowledgeView, "current">;
  src: string;
  name: string;
}) {
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError("");
    fetch(src, { signal: controller.signal, cache: "no-store" })
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`The preview could not be loaded (HTTP ${response.status}).`);
        const preview = new DOMParser().parseFromString(await response.text(), "text/html");
        const base = preview.createElement("base");
        // srcDoc otherwise resolves relative assets against the dashboard route.
        base.href = response.url;
        preview.head.prepend(base);
        return `<!doctype html>\n${preview.documentElement.outerHTML}`;
      })
      .then(setHtml)
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        setError(reason instanceof Error ? reason.message : "The preview could not be loaded.");
      });
    return () => controller.abort();
  }, [src, attempt]);

  return (
    <div className="space-y-4">
      <CompanyKnowledgeViewSwitch view={view} />
      <PageNotice title="Sample data">
        <p>
          This preview shows a proposed {name} layout with illustrative sample
          data. It does not reflect your organization&apos;s policies or guardrails.{" "}
          <Link href="/company-knowledge" className="text-primary underline underline-offset-2">
            Open Company Policy and Knowledge
          </Link>
        </p>
      </PageNotice>
      {error ? (
        <ErrorState message={error} onRetry={() => setAttempt((value) => value + 1)} />
      ) : html === null ? (
        <LoadingState label="Loading preview…" />
      ) : (
        // srcDoc keeps the document same-origin without framing a URL, so the
        // console's X-Frame-Options policy stays unchanged.
        <iframe
          title={`${name} preview with sample data`}
          srcDoc={html}
          className="block w-full rounded-lg border bg-background"
          style={{ height: "calc(100dvh - 7rem)", minHeight: 560 }}
        />
      )}
    </div>
  );
}
