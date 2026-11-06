import { redirect } from "next/navigation";

export default async function GatewayRequestsPage({ searchParams }: { searchParams: Promise<{ gateway_id?: string }> }) {
  const query = await searchParams;
  const target = new URLSearchParams({ source: "gateways" });
  if (typeof query.gateway_id === "string" && query.gateway_id) target.set("gateway_id", query.gateway_id);
  redirect(`/guardrail/history?${target}`);
}
