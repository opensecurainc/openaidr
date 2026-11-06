import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  server.closeAllConnections();
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

test("the dashboard forwards OTLP bodies, device headers, and backend responses", { timeout: 90_000 }, async (t) => {
  const received = [];
  const backend = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({ method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks) });
    response.writeHead(request.headers.authorization === "Bearer proxy-test-device" ? 200 : 401, {
      "Content-Type": "application/x-protobuf",
    });
    response.end(Buffer.from([0x0a, 0x00]));
  });
  const backendURL = await listen(backend);
  t.after(() => close(backend));
  const reservation = createServer();
  const frontendURL = await listen(reservation);
  await close(reservation);
  const frontend = spawn(process.execPath, ["node_modules/next/dist/bin/next", "dev", "--hostname", "127.0.0.1", "--port", new URL(frontendURL).port], {
    cwd: root,
    env: { ...process.env, NODE_ENV: "development", DASHBOARD_API_PROXY: backendURL },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  frontend.stdout.on("data", (chunk) => { output += chunk; });
  frontend.stderr.on("data", (chunk) => { output += chunk; });
  t.after(async () => {
    if (frontend.exitCode !== null || frontend.signalCode !== null) return;
    const closed = once(frontend, "close");
    frontend.kill("SIGTERM");
    const timeout = setTimeout(() => frontend.kill("SIGKILL"), 10_000);
    try { await closed; } finally { clearTimeout(timeout); }
  });
  const deadline = Date.now() + 60_000;
  while (true) {
    assert.equal(frontend.exitCode, null, output);
    assert.equal(frontend.signalCode, null, output);
    assert.ok(Date.now() < deadline, `Dashboard did not start: ${output}`);
    try {
      const response = await fetch(`${frontendURL}/healthz`, { signal: AbortSignal.timeout(1000) });
      await response.arrayBuffer();
      if (response.ok) break;
    } catch { /* The child has not started listening yet. */ }
    await delay(100);
  }

  for (const signal of ["logs", "metrics", "traces"]) {
    for (const authorization of ["Bearer proxy-test-device", "Bearer invalid", ""]) {
      const body = Buffer.from([0x0a, 0x03, 0x00, 0xff, 0x01]);
      const response = await fetch(`${frontendURL}/otlp/v1/${signal}`, {
        method: "POST",
        signal: AbortSignal.timeout(5000),
        headers: {
          "Content-Type": "application/x-protobuf",
          "X-OpenAIDR-Batch-Id": `proxy-test-${signal}`,
          ...(authorization ? { Authorization: authorization } : {}),
        },
        body,
      });
      assert.equal(response.status, authorization === "Bearer proxy-test-device" ? 200 : 401);
      assert.equal(response.headers.get("content-type"), "application/x-protobuf");
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), Buffer.from([0x0a, 0x00]));
      const forwarded = received.at(-1);
      assert.equal(forwarded.method, "POST");
      assert.equal(forwarded.url, `/otlp/v1/${signal}`);
      assert.equal(forwarded.headers.authorization, authorization || undefined);
      assert.equal(forwarded.headers["content-type"], "application/x-protobuf");
      assert.equal(forwarded.headers["x-openaidr-batch-id"], `proxy-test-${signal}`);
      assert.deepEqual(forwarded.body, body);
    }
  }
  assert.equal(received.length, 9);
});
