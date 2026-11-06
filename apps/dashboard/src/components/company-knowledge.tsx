"use client";

import type { EventRisk } from "@/lib/api";
export { CompanyKnowledge } from "./company-knowledge-library";

const lookupStatus = {
  matched: "Company context matched the operation and resource.",
  partial: "Only partial company context was available.",
  no_match: "No matching company context was available.",
  disabled: "Company context lookup was disabled.",
  unavailable: "Company context lookup was unavailable.",
};
const contextCoverage = {
  exact: "Exact alias match", lexical: "Text candidates only", ambiguous: "Ambiguous",
  unknown: "Unknown", overflow: "Too many candidates", missing: "No match",
};
const contextGaps: Record<string, string> = {
  missing_scope: "Execution scope is unknown.",
  unresolved_resource: "Resource identity could not be resolved.",
  unresolved_identity: "Operation and resource identities could not be resolved.",
  query_terms_truncated: "Some lookup terms were omitted.",
  operation_lexical_only: "Text matches do not establish operation identity.",
  resource_lexical_only: "Text matches do not establish resource identity.",
  operation_candidate_overflow: "Too many operation candidates matched.",
  resource_candidate_overflow: "Too many resource candidates matched.",
  no_operation_match: "No operation reference matched.",
  no_resource_match: "No resource reference matched.",
  ambiguous_operation: "Operation identity is ambiguous.",
  ambiguous_resource: "Resource identity is ambiguous.",
  evidence_truncated: "Some reference passages were omitted.",
  evidence_redacted: "Reference evidence was redacted.",
  evidence_omitted: "Reference evidence did not fit in the assessment.",
  retrieval_unavailable: "The reference lookup could not complete.",
  retrieval_deadline: "The reference lookup exceeded its time budget.",
  target_evidence_incomplete: "The captured action is incomplete.",
};

export function KnowledgeEvidence({ risk }: { risk?: EventRisk | null }) {
  const knowledge = risk?.knowledge;
  if (!knowledge) return null;
  return (
    <section aria-label="Company knowledge evidence" className="space-y-2 text-sm">
      <h3 className="font-semibold">Company knowledge at assessment</h3>
      <p className="text-xs text-muted-foreground">
        {knowledge.revision === null ? "Setting unknown" : knowledge.enabled ? "Enabled" : "Disabled"}
        {" · "}Revision {knowledge.revision ?? "unknown"}
        {" · "}Lookup {knowledge.retrieval_ms.toFixed(2)} ms
      </p>
      {knowledge.status && (
        <p className={knowledge.status === "unavailable" || knowledge.status === "partial" ? "text-status-warning" : undefined}>
          {lookupStatus[knowledge.status]}
        </p>
      )}
      {knowledge.category_coverage && (
        <p>
          Operation: {contextCoverage[knowledge.category_coverage.operation]}
          {" · "}Resource: {contextCoverage[knowledge.category_coverage.resource]}
        </p>
      )}
      {!!knowledge.gaps?.length && (
        <ul aria-label="Company context gaps" className="list-disc space-y-1 pl-5">
          {knowledge.gaps.map((gap) => <li key={gap}>{contextGaps[gap] ?? gap}</li>)}
        </ul>
      )}
      {!knowledge.enabled ? (
        <p>No company documents were supplied.</p>
      ) : (
        <>
          <p>{knowledge.documents.length ? "Matched context supplied to Guardrail:" : knowledge.status ? "No reference documents were supplied." : "No matching documents were supplied."}</p>
          {knowledge.documents.map((document) => (
            <div key={document.id} className="space-y-1 border-t pt-2 break-words">
              <p className="font-medium">{document.title}</p>
              <p className="text-xs text-muted-foreground">
                {document.kind === "command" ? "Command behavior" : document.kind === "resource" ? "Resource impact" : "Reference"}
                {" · "}Matched: {document.matched_keywords.join(", ")}
              </p>
              <p className="whitespace-pre-wrap">{document.text}</p>
            </div>
          ))}
          {knowledge.truncated && <p className="text-status-warning">Context limits omitted some matches or search terms.</p>}
          <p className="text-xs text-muted-foreground">{knowledge.coverage}</p>
        </>
      )}
    </section>
  );
}
