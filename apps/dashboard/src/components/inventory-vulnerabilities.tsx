"use client";

import type { Component } from "@/components/component-inventory";
import { Badge } from "@/components/ui/badge";
import { Status } from "@/components/ui/status";
import { useTimeZone } from "@/components/time-zone-context";
import { cvssBaseScore, highestCvssScore, type CvssScore } from "@/lib/cvss";

type Finding = {
  id: string;
  aliases: string[];
  source_ids: string[];
  summary: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  fixed_versions: string[];
  severity_vectors: { type: string; score: string }[];
};
export type VulnerabilityAssessment = {
  provider: "OSV";
  status: "pending" | "complete" | "stale" | "unavailable" | "not_assessed";
  reason: string;
  checked_at: string | null;
  findings: Finding[];
};

export function hasVulnerabilities(record: Component) {
  return Boolean(record.vulnerability?.findings.length);
}

function findingsFor(records: Component[]) {
  const groups: { finding: Finding; identities: Set<string>; records: Component[] }[] = [];
  const rank = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  for (const record of records) for (const finding of record.vulnerability?.findings || []) {
    const entry = { finding: { ...finding }, identities: new Set([finding.id, ...finding.aliases]), records: [record] };
    const overlaps = groups.filter((group) => [...entry.identities].some((id) => group.identities.has(id)));
    for (const group of overlaps) {
      group.identities.forEach((id) => entry.identities.add(id));
      entry.records.push(...group.records);
      entry.finding.fixed_versions = [...new Set([...entry.finding.fixed_versions, ...group.finding.fixed_versions])];
      entry.finding.source_ids = [...new Set([...entry.finding.source_ids, ...group.finding.source_ids])];
      entry.finding.severity_vectors = [...new Map([...entry.finding.severity_vectors, ...group.finding.severity_vectors]
        .map((vector) => [`${vector.type}:${vector.score}`, vector])).values()];
      if (rank[group.finding.severity] < rank[entry.finding.severity]) entry.finding.severity = group.finding.severity;
      groups.splice(groups.indexOf(group), 1);
    }
    entry.records = [...new Map(entry.records.map((value) => [value.id, value])).values()];
    entry.finding.id = [...entry.identities].sort((a, b) => Number(b.startsWith("CVE-")) - Number(a.startsWith("CVE-")) || a.localeCompare(b))[0];
    groups.push(entry);
  }
  return groups.sort((a, b) => rank[a.finding.severity] - rank[b.finding.severity] || a.finding.id.localeCompare(b.finding.id));
}

function CvssValue({ score, maximum = false, compact = false }: { score: CvssScore | null; maximum?: boolean; compact?: boolean }) {
  if (!score) return <span className="text-xs text-muted-foreground">CVSS unavailable</span>;
  return <div className="flex flex-wrap items-baseline gap-x-2" title={`CVSS v${score.version} · Base. Highest available score. Source vector: ${score.vector}`}>
    <span className="text-sm font-semibold">{maximum ? "Max CVSS" : "CVSS"} <span className="number">{score.score.toFixed(1)}</span></span>
    <span className={compact ? "sr-only" : "text-xs text-muted-foreground"}>v{score.version} · Base</span>
  </div>;
}

export function VulnerabilitySignals({ records, explain = false, compact = false }: { records: Component[]; explain?: boolean; compact?: boolean }) {
  const findings = findingsFor(records);
  const known = findings.length;
  const affected = records.filter(hasVulnerabilities).length;
  const unavailable = records.some((record) => record.vulnerability?.status === "unavailable");
  const stale = records.some((record) => record.vulnerability?.status === "stale");
  const pending = records.some((record) => record.vulnerability?.status === "pending");
  const unassessed = records.some((record) => !record.vulnerability || record.vulnerability.status === "not_assessed");
  const scored = findings.map(({ finding }) => highestCvssScore(finding.severity_vectors));
  const scoredCount = scored.filter((score) => score !== null).length;
  return <>
    {known > 0 && <CvssValue score={highestCvssScore(findings.flatMap(({ finding }) => finding.severity_vectors))} maximum compact={compact} />}
    {scoredCount > 0 && scoredCount < known && <span className="text-xs text-muted-foreground">Scores available for {scoredCount} of {known} vulnerabilities</span>}
    {known > 0 && <Status tone="critical">{known} known {known === 1 ? "vulnerability" : "vulnerabilities"}{explain && ` · ${affected} of ${records.length} records`}</Status>}
    {explain && known > 0 && <p className="line-clamp-2 break-words text-xs text-muted-foreground" title={findings[0].finding.summary || findings[0].finding.id}>
      {findings[0].finding.summary || "OSV advisory matches a reported package version."}
    </p>}
    {unavailable ? <Status tone="warning">Vulnerability check unavailable</Status>
      : stale ? <Status tone="warning">Vulnerability check outdated</Status>
      : pending ? <span className="text-xs text-muted-foreground">Vulnerability check pending</span>
      : unassessed ? <span className="text-xs text-muted-foreground">Vulnerabilities not assessed</span>
      : !known && <span className="text-xs text-muted-foreground">No known vulnerabilities at last check</span>}
  </>;
}

export function VulnerabilityDetails({ records }: { records: Component[] }) {
  const { dateTime } = useTimeZone();
  const findings = findingsFor(records);
  const checked = records.filter((record) => record.vulnerability?.status === "complete").length;
  return (
    <section aria-label="Vulnerability findings" className="min-w-0 space-y-3 border-b pb-4 text-sm">
      <div>
        <h3 className="font-semibold">Vulnerability findings</h3>
        <p className="text-xs text-muted-foreground">OSV assessments cover {checked} of {records.length} loaded records with a current result.</p>
      </div>
      <div className="flex flex-col items-start gap-1"><VulnerabilitySignals records={records} /></div>
      {findings.length > 0 && <p className="text-xs text-muted-foreground">Max CVSS is the highest available base score across loaded findings. Each advisory shows its highest base score; CVSS versions can differ. Missing scores are unavailable, not zero.</p>}
      {records.some((record) => record.vulnerability?.status === "unavailable" || record.vulnerability?.status === "stale") &&
        <p className="text-xs text-muted-foreground">Previous findings remain visible until a successful check replaces them. Checks retry automatically.</p>}
      {!findings.length && <p className="text-xs text-muted-foreground">
        {checked === records.length ? "No matching OSV advisories were returned. This does not establish that a component is safe."
          : "Missing package identity or versions cannot be assessed. Pending and unavailable checks do not establish that a component is safe."}
      </p>}
      <ul className="divide-y">
        {findings.map(({ finding, records: affected }) => {
          const devices = new Set(affected.map((record) => record.sensor_id)).size;
          const versions = [...new Set(affected.map((record) => record.version))].sort();
          const timestamps = affected.flatMap((record) => record.vulnerability?.checked_at ? [record.vulnerability.checked_at] : []).sort();
          return <li key={finding.id} className="min-w-0 space-y-2 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <a className="break-all font-mono text-sm font-normal text-primary underline underline-offset-4"
                href={`https://osv.dev/vulnerability/${encodeURIComponent(finding.source_ids[0] || finding.id)}`} target="_blank" rel="noreferrer noopener">{finding.id}</a>
              <Badge variant={finding.severity === "unknown" ? "outline" : finding.severity}>
                {finding.severity === "unknown" ? "Severity unknown" : `${finding.severity[0].toUpperCase()}${finding.severity.slice(1)}`}
              </Badge>
            </div>
            <CvssValue score={highestCvssScore(finding.severity_vectors)} />
            <p className="break-words">{finding.summary}</p>
            <p className="text-xs text-muted-foreground">{devices} affected {devices === 1 ? "device" : "devices"} · {affected.length} loaded {affected.length === 1 ? "record" : "records"}</p>
            <dl className="grid min-w-0 gap-3 sm:grid-cols-2">
              <div><dt className="text-xs text-muted-foreground">Affected reported versions</dt><dd className="break-all font-mono text-sm font-normal">{versions.join(", ")}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Reported fix versions</dt><dd className={finding.fixed_versions.length ? "break-all font-mono text-sm font-normal" : "text-sm"}>{finding.fixed_versions.join(", ") || "Not reported"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Oldest contributing check</dt><dd>{timestamps[0] ? dateTime(timestamps[0]) : "Not reported"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Source advisory IDs</dt><dd className="break-all font-mono text-sm font-normal">{finding.source_ids.join(", ")}</dd></div>
            </dl>
            {finding.severity_vectors.length > 0 && <details className="text-xs text-muted-foreground">
              <summary className="cursor-pointer">Source severity vectors</summary>
              {finding.severity_vectors.map((vector, index) => <div key={`${vector.type}-${index}`} className="mt-2 space-y-1">
                <CvssValue score={cvssBaseScore(vector)} />
                <p className="break-all font-mono text-sm font-normal">{vector.type}: {vector.score}</p>
              </div>)}
            </details>}
          </li>;
        })}
      </ul>
      {findings.length > 0 && <p className="text-xs text-muted-foreground">Confirm the applicable advisory and upgrade path before choosing a fix version. A package-name match does not establish provenance, reachability, or exploitation.</p>}
      <div className="space-y-1 text-xs text-muted-foreground">
        {records.map((record) => <p key={record.id} className="break-words">
          <span className={record.hostname ? "" : "font-mono text-sm font-normal"}>{record.hostname || record.sensor_id}</span> · <span className={record.version ? "font-mono text-sm font-normal" : ""}>{record.version || "Version not reported"}</span>: {record.vulnerability?.checked_at ? `Checked ${dateTime(record.vulnerability.checked_at)}` : record.vulnerability?.reason || "Not assessed"}
        </p>)}
      </div>
    </section>
  );
}
