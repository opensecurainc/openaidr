"use client";
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { useDashboard } from "@/components/dashboard-context";
import { SensorMetricsPanel } from "@/components/sensor-metrics";
import { healthStatus } from "@/components/sensor-health";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/page-layout";
import { type Device, type DeviceHealth } from "@/lib/api";
import { useResource } from "@/lib/use-resource";
import {
  ActivityPanel,
  DeviceTable,
  ServicesPanel,
  StatCards,
} from "@/components/telemetry-panels";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
export default function AppHealthPage() {
  const { data, error, loading, user } = useDashboard();
  const health = useResource<{
    items: (Omit<DeviceHealth, "sensor_version"> & { version: string })[];
  }>(user ? "sensors/health" : null, 30000);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [healthFilter, setHealthFilter] = useState("all");
  const [sensorId, setSensorId] = useState("");
  const [resourceRange, setResourceRange] = useState("24h");
  const healthDevices = useMemo(() => health.data?.items.map(({ version, ...device }) => ({
    ...device, sensor_version: version,
  })), [health.data]);
  const devices = useMemo(() => {
    const activity = new Map(data?.devices.map((device) => [device.id, device]));
    return (healthDevices ?? data?.devices ?? []).map((device): DeviceHealth & Partial<Device> => ({
      ...(data ? {
        exports: activity.get(device.id)?.exports ?? 0,
        log_records: activity.get(device.id)?.log_records ?? 0,
        metric_points: activity.get(device.id)?.metric_points ?? 0,
        spans: activity.get(device.id)?.spans ?? 0,
        latest_export_at: activity.get(device.id)?.latest_export_at ?? null,
      } : {}),
      ...device,
    })).filter(
        (d) =>
          (status === "all" || d.status === status) &&
          (healthFilter === "all" || healthStatus(d) === healthFilter) &&
          `${d.hostname} ${d.label} ${d.os} ${d.id}`
            .toLowerCase()
            .includes(query.toLowerCase()),
      );
  }, [data, healthDevices, query, status, healthFilter]);
  const fleet = healthDevices ?? data?.devices ?? [];
  const attention = fleet.filter(device => healthStatus(device) === "needs_attention").length;
  const unknown = fleet.filter(device => healthStatus(device) === "unknown").length;
  useEffect(() => {
    if (devices.length && !devices.some((device) => device.id === sensorId)) {
      setSensorId(devices[0].id);
    }
  }, [devices, sensorId]);
  const haveDevices = Boolean(health.data || data);
  return (
    <>
      <StatCards data={data} health={healthDevices} healthLoading={health.loading} healthError={Boolean(health.error)} />
      {haveDevices && <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border bg-card px-4 py-3" role="status" aria-label="Fleet health">
        <p className="text-sm font-medium">{attention} {attention === 1 ? "device needs" : "devices need"} attention · {unknown} health unknown</p>
        <Button variant="outline" size="sm" onClick={() => {
          setHealthFilter(healthFilter === "needs_attention" ? "all" : "needs_attention");
          setStatus("all");
          setQuery("");
        }}>
          {healthFilter === "needs_attention" ? "Show all devices" : "Show devices needing attention"}
        </Button>
      </div>}
      {health.error && (
        <div className="mb-4">
          <ErrorState title="Unable to refresh app health" message={`${health.error} Showing previously received health when available.`} onRetry={health.reload} />
        </div>
      )}
      {!haveDevices && health.loading && <LoadingState label="Loading app health…" />}
      <p className="mb-3 text-sm text-muted-foreground">
        App health includes all enrolled devices. Time and service filters apply to telemetry totals.
      </p>
      <div className="mb-4 flex flex-wrap gap-2">
        <div className="relative w-full sm:w-80">
          <Search
            aria-hidden="true"
            className="absolute top-2 left-2.5 size-4 text-muted-foreground"
          />
          <Input
            aria-label="Search devices"
            placeholder="Search hostname, label, or operating system"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger aria-label="Device status" className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="online">Online</SelectItem>
            <SelectItem value="offline">Offline</SelectItem>
            <SelectItem value="disabled">Disabled</SelectItem>
          </SelectContent>
        </Select>
        <Select value={healthFilter} onValueChange={setHealthFilter}>
          <SelectTrigger aria-label="Device health" className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All health states</SelectItem>
            <SelectItem value="needs_attention">Needs attention</SelectItem>
            <SelectItem value="unknown">Health unknown</SelectItem>
            <SelectItem value="healthy">Healthy</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {haveDevices && <div className="mb-4">
        <DeviceTable devices={devices} onRefresh={health.reload} refreshing={health.loading} />
      </div>}
      {haveDevices && <SensorMetricsPanel
        devices={devices}
        sensorId={sensorId}
        onSensorChange={setSensorId}
        range={resourceRange}
        onRangeChange={setResourceRange}
      />}
      <div className="mb-4 grid items-stretch gap-4 xl:grid-cols-[2.1fr_1fr]">
        {data ? <>
          <ActivityPanel data={data} stale={Boolean(error)} />
          <ServicesPanel data={data} />
        </> : [
          { title: "Telemetry activity", description: "Records received over time" },
          { title: "Source services", description: "Share of records by service label" },
        ].map(({ title, description }) => (
          <Card key={title}>
            <CardHeader>
              <CardTitle>{title}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </CardHeader>
            <CardContent className="min-h-80">
              {error && !loading ? (
                <EmptyState title={`${title} unavailable`} description="Use Retry above to load telemetry." />
              ) : (
                <LoadingState label={`Loading ${title.toLowerCase()}…`} />
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}
