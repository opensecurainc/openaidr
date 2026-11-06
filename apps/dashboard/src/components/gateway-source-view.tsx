"use client";

import { type ReactNode } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { GatewayRequests } from "@/components/gateway-requests";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function GatewaySourceView({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const source = searchParams.get("source") === "gateways" ? "gateways" : "endpoints";
  const gatewayId = searchParams.get("gateway_id") || "";
  function setSource(value: string) {
    const query = new URLSearchParams(searchParams);
    query.set("source", value);
    router.replace(`${pathname}?${query}`, { scroll: false });
  }
  return <Tabs value={source} onValueChange={setSource} className="gap-4"><TabsList aria-label="Activity source"><TabsTrigger value="endpoints">Endpoints</TabsTrigger><TabsTrigger value="gateways">Gateways</TabsTrigger></TabsList><TabsContent value="endpoints">{children}</TabsContent><TabsContent value="gateways"><GatewayRequests key={gatewayId} gatewayId={gatewayId} /></TabsContent></Tabs>;
}
