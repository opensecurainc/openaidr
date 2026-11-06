import { DashboardProvider } from "@/components/dashboard-context";
import { DashboardShell } from "@/components/dashboard-shell";
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <DashboardProvider>
      <DashboardShell>{children}</DashboardShell>
    </DashboardProvider>
  );
}
