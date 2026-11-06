import { Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { agentIcon } from "../../../../packages/ui/agent-icons/index.js";

/** Decorative mark beside the visible agent name. */
export function AgentLogo({ product }: { product: string }) {
  const icon = agentIcon(product);
  return icon ? (
    <img
      src={icon}
      alt=""
      aria-hidden="true"
      data-slot="agent-logo"
      width={20}
      height={20}
      className={cn("size-5 shrink-0 object-contain", icon.endsWith("/codex.png") && "rounded-sm bg-black")}
    />
  ) : <Terminal aria-hidden="true" data-slot="agent-logo" className="size-5 shrink-0" />;
}
