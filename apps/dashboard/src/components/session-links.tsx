import Link from "next/link";
import { findingSessionHref, isUuid, sessionHref, type FindingSessionReference } from "@/lib/session";

/** Only receiver session IDs belong in operator routes; native IDs are not interchangeable. */
export function SessionArchiveLink({ sessionId }: { sessionId: string | null | undefined }) {
  return isUuid(sessionId) ? <Link href={sessionHref(sessionId)} className="text-sm font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring">View session details</Link> : null;
}

export function FindingSessionLink({ finding }: { finding: FindingSessionReference }) {
  const href = findingSessionHref(finding);
  if (!href) return finding.investigation_job_id ? <p className="text-sm text-muted-foreground">Retained investigation reference is unavailable.</p> : null;
  return <div className="space-y-1 text-sm" data-page-chat-exclude>
    <Link href={href} className="font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring">
      {finding.investigation_job_id ? "View retained session investigation" : "View session details"}
    </Link>
    {finding.investigation_job_id && <p className="text-xs text-muted-foreground">Open the exact report attempt and retained snapshot, including evidence no longer present in live event storage.</p>}
  </div>;
}
