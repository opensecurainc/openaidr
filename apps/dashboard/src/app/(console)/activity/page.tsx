import { redirect } from "next/navigation";

export default async function LiveActivityRedirect({ searchParams }: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { session } = await searchParams;
  const selected = Array.isArray(session) ? session[0] : session;
  const query = selected ? `?${new URLSearchParams({ session: selected })}` : "";
  redirect(`/guardrail/live${query}#live-activity`);
}
