import { Suspense } from "react";
import { ErrorState, LoadingState } from "@/components/page-layout";
import { SessionInvestigation } from "@/components/session-investigation";
import { isUuid, parseSessionSelection } from "@/lib/session";

type Props = {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

async function Content({ params, searchParams }: Props) {
  const [{ id }, query] = await Promise.all([params, searchParams]);
  const selection = parseSessionSelection({ ...query, investigation: id });
  if (!isUuid(id) || !selection) return <ErrorState message="The report reference is invalid. No alternate report was selected." />;
  return <SessionInvestigation key={`${id}:${selection.attempt ?? "latest"}`} sessionId={null} selection={{ ...selection, investigation: id.toLowerCase() }} />;
}

export default function InvestigationReportPage(props: Props) {
  return <Suspense fallback={<LoadingState label="Loading investigation report…" />}><Content {...props} /></Suspense>;
}
