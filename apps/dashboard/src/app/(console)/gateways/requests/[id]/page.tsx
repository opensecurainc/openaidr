import { GatewayRequestView } from "@/components/gateway-requests";

export default async function GatewayRequestPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <GatewayRequestView id={id} />;
}
