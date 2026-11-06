import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { agentIcon } from "../packages/ui/agent-icons/index.js";
import { syncAgentIcons } from "./sync-agent-icons.mjs";

const source = new URL("../packages/ui/agent-icons/", import.meta.url);

test("every supported event product has bundled publisher artwork", () => {
  const contract = readFileSync(new URL("../packages/common/src/openaidr_common/event.py", import.meta.url), "utf8");
  const products = contract.match(/PRODUCTS = \(([\s\S]*?)\n\)/)?.[1];
  assert.ok(products, "Event product contract must be present");
  for (const [, product] of products.matchAll(/"([^"]+)"/g)) {
    if (product === "unknown") continue;
    const url = agentIcon(product);
    assert.ok(url, `Missing artwork for ${product}`);
    assert.ok(existsSync(new URL(path.basename(url), source)), `Missing file for ${product}`);
  }
  assert.equal(agentIcon("codex"), agentIcon("codex-cli"));
  assert.equal(agentIcon("claude_code"), agentIcon("claude-code"));
  assert.equal(agentIcon("cowork"), agentIcon("claude-code"));
  assert.equal(agentIcon("claude-ai"), agentIcon("claude-code"));
  assert.equal(agentIcon("copilot"), agentIcon("github-copilot"));
  assert.equal(agentIcon("copilot-cli"), agentIcon("github-copilot"));
  assert.equal(agentIcon("workbuddy"), "/agent-icons/workbuddy.svg");
  for (const product of ["", "unknown", "future-agent", "__proto__"]) {
    assert.equal(agentIcon(product), undefined);
  }
});

test("app copies preserve publisher files and remove obsolete generated artwork", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "openaidr-agent-icons-"));
  try {
    const destination = path.join(directory, "agent-icons");
    syncAgentIcons(destination);
    writeFileSync(path.join(destination, "obsolete.png"), "obsolete");
    syncAgentIcons(destination);
    assert.equal(existsSync(path.join(destination, "obsolete.png")), false);
    for (const file of readdirSync(source).filter((file) => !file.endsWith(".d.ts"))) {
      assert.deepEqual(readFileSync(path.join(destination, file)), readFileSync(new URL(file, source)), file);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
