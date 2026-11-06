"use client";

import { useEffect, useState } from "react";
import { ErrorState, LoadingState, PageNotice } from "@/components/page-layout";

// A self-contained page with its own illustrative sample data. It reads no
// tenant data and makes no API requests.
const PREVIEW_URL = "/previews/ai-skills.html";

export default function AISkillsPage() {
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError("");
    fetch(PREVIEW_URL, { signal: controller.signal, cache: "no-store" })
      .then((response) => {
        if (!response.ok)
          throw new Error(`The preview could not be loaded (HTTP ${response.status}).`);
        return response.text();
      })
      .then(setHtml)
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        setError(reason instanceof Error ? reason.message : "The preview could not be loaded.");
      });
    return () => controller.abort();
  }, [attempt]);

  return (
    <div className="space-y-4">
      <PageNotice title="Sample data">
        <p>
          This preview shows a proposed AI Skills layout with
          illustrative sample data, including example review signals. It does
          not reflect your organization&apos;s inventory.
        </p>
      </PageNotice>
      {error ? (
        <ErrorState message={error} onRetry={() => setAttempt((value) => value + 1)} />
      ) : html === null ? (
        <LoadingState label="Loading preview…" />
      ) : (
        // srcDoc keeps the document same-origin without framing a URL, so the
        // console's X-Frame-Options policy stays unchanged. The preview scrolls
        // inside the frame so its dialogs and drawers stay in view.
        <iframe
          title="AI Skills preview with sample data"
          srcDoc={html}
          className="block w-full rounded-lg border bg-background"
          style={{ height: "calc(100dvh - 7rem)", minHeight: 560 }}
        />
      )}
    </div>
  );
}
