import { GatewayInstance } from "@/components/gateway-instance";

export default async function GatewayInstancePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <GatewayInstance id={id} />;
}
