import { Suspense } from "react";
import { LoadingState } from "@/components/page-layout";
import { SessionDetail } from "@/components/session-detail";
import { parseSessionSelection } from "@/lib/session";

type Props = {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

async function Content({ params, searchParams }: Props) {
  const [{ id }, query] = await Promise.all([params, searchParams]);
  return <SessionDetail key={id.toLowerCase()} sessionId={id.toLowerCase()} selection={parseSessionSelection(query)} />;
}

export default function SessionPage(props: Props) {
  return <Suspense fallback={<LoadingState label="Loading session…" />}><Content {...props} /></Suspense>;
}
