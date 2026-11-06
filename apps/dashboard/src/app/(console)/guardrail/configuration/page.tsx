import { FixedRules } from "@/components/fixed-rules";
import { HookPolicy } from "@/components/hook-policy";

export default function GuardrailConfigurationPage() {
  return (
    <div className="space-y-4">
      <HookPolicy />
      <FixedRules />
    </div>
  );
}
