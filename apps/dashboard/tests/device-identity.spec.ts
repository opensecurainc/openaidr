import { test, expect } from "@playwright/test";

test.use({ timezoneId: "America/Los_Angeles" });

test("device inventory shows reported hardware identity and earlier enrollments", async ({ page }) => {
  const now = Date.parse("2026-10-15T05:00:00Z");
  await page.clock.setFixedTime(now);
  const base = {
    label: "",
    os: "macos",
    arch: "arm64",
    version: "2026.10.15+abc1234",
    host_kind: "workstation",
    last_heartbeat_at: new Date(now).toISOString(),
    telemetry_queue_depth: 0,
    queue_depth: 0,
    cpu_percent: 12,
    memory_rss_bytes: 40 * 1024 ** 2,
  };
  const items = [
    {
      ...base,
      id: "sensor-new",
      hostname: "pan-laptop",
      status: "online",
      device: { serial_number: "C02XYZ123", hardware_uuid: "A1B2C3D4-0000-1111-2222-333344445555", machine_id: "", source: "ioreg" },
      same_hardware: [
        { id: "sensor-old", label: "", hostname: "pan-laptop-old", enrolled_at: new Date(now - 86400000 * 30).toISOString(), status: "offline" },
        { id: "sensor-older", label: "Loaner", hostname: "loaner", enrolled_at: new Date(now - 86400000 * 90).toISOString(), status: "disabled" },
        { id: "sensor-oldest", label: "", hostname: "first-install", enrolled_at: new Date(now - 86400000 * 120).toISOString(), status: "offline" },
      ],
    },
    {
      ...base,
      id: "sensor-linux",
      hostname: "build-box",
      os: "linux",
      status: "online",
      device: { serial_number: "", hardware_uuid: "", machine_id: "0123456789abcdef0123456789abcdef", source: "machine-id" },
      same_hardware: [],
    },
    {
      ...base,
      id: "sensor-legacy",
      hostname: "legacy-host",
      status: "offline",
      last_heartbeat_at: new Date(now - 600000).toISOString(),
      device: { serial_number: "", hardware_uuid: "", machine_id: "", source: "" },
      same_hardware: [],
    },
    // An older backend omits the fields entirely.
    { ...base, id: "sensor-old-backend", hostname: "old-backend", status: "online" },
  ];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me"))
      return route.fulfill({ json: { user: {
        id: "u", name: "Operator", email: "test@example.invalid", roles: ["it_admin"],
        tenant: { id: "t", name: "Test tenant", slug: "test" },
      } } });
    if (url.pathname.endsWith("sensors/health")) return route.fulfill({ json: { items } });
    if (url.pathname.endsWith("telemetry/overview"))
      return route.fulfill({ status: 503, json: { error: { message: "Telemetry overview timed out" } } });
    if (url.pathname.endsWith("/metrics"))
      return route.fulfill({ json: {
        sensor_id: "sensor-new", range: "24h", generated_at: new Date(now).toISOString(),
        window_start: new Date(now - 86400000).toISOString(), bucket_seconds: 300,
        latest: { last_heartbeat_at: base.last_heartbeat_at, status: "online", cpu_percent: 12, memory_rss_bytes: base.memory_rss_bytes },
        samples: [],
      } });
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/app");
  const inventory = page.getByRole("region", { name: "Scrollable device inventory" });
  await expect(inventory.getByRole("columnheader", { name: "Hardware" })).toBeVisible();

  const laptop = inventory.getByRole("row", { name: /pan-laptop/ });
  await expect(laptop.getByText("C02XYZ123", { exact: true })).toBeVisible();
  await expect(laptop.getByText("Serial number", { exact: true })).toBeVisible();
  await expect(laptop.getByText("C02XYZ123", { exact: true })).toHaveAttribute(
    "title",
    "Serial number: C02XYZ123\nHardware UUID: A1B2C3D4-0000-1111-2222-333344445555\nSource: ioreg",
  );
  const matches = laptop.getByLabel("Same hardware as pan-laptop-old, Loaner, first-install");
  await expect(matches).toHaveText("Same hardware as pan-laptop-old, Loaner and 1 more");
  await expect(matches).toHaveAttribute("title", /Same hardware as:\npan-laptop-old · offline · enrolled .*\nLoaner · disabled · enrolled .*\nfirst-install · offline · enrolled /);

  const linux = inventory.getByRole("row", { name: /build-box/ });
  await expect(linux.getByText("0123456789abcdef0123456789abcdef", { exact: true })).toBeVisible();
  await expect(linux.getByText("OS installation ID", { exact: true })).toBeVisible();
  await expect(linux.getByText(/Same hardware/)).toHaveCount(0);

  for (const name of [/legacy-host/, /old-backend/]) {
    const row = inventory.getByRole("row", { name });
    await expect(row.getByText("Not reported", { exact: true }).first()).toBeVisible();
    await expect(row.getByText(/Same hardware/)).toHaveCount(0);
  }
  // The identity column never widens the page beyond its horizontal scroll region.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBe(0);
  expect(errors).toEqual([]);
});
