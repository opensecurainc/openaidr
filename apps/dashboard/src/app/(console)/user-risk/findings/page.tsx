import { Suspense } from "react";
import { LoadingState } from "@/components/page-layout";
import { UserFindingsPage } from "@/components/security-pages";

export default function Page() {
  return <Suspense fallback={<LoadingState label="Loading findings…" />}><UserFindingsPage /></Suspense>;
}
