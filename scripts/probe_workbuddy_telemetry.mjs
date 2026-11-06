#!/usr/bin/env node
// Inspect installed native telemetry methods without launching WorkBuddy or a model.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const resources = process.argv[2] || '/Applications/WorkBuddy AI.app/Contents/Resources';
const source = await readFile(path.join(resources, 'app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs'), 'utf8');
const digest = createHash('sha256').update(source).digest('hex');
assert.equal(digest, 'af69dd4dc7b5184502cdf2db1687dccaef57f93e28171941e0219d1570c4bd1a',
  'Review extraction boundaries for another runtime build.');

function extract(start, end) {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first + start.length);
  assert(first >= 0 && last > first, `Missing extraction boundary: ${start}`);
  return source.slice(first, last);
}

const env = {};
const context = vm.createContext({process: {env}, Date, Object, Set, Number,
  t$: {wSP: {Env: 2000}}, rR: {pM: 'unrelated-reserved-key'},
  pa: {isTelemetryDisabled: () => false}, gp: {},
});
vm.runInContext(extract('let n="/v1/traces",s=new Set', '},33563('), context);
const readEnv = vm.runInContext('readOtelTraceEnv', context);
const Interceptor = vm.runInContext('(' + extract('let rI=class', ';env_interceptor_decorate').slice(7) + ')', context);
const Lifecycle = vm.runInContext('(' + extract('let NU=class', ';trace_initializer_decorate').slice(7) + ')', context);
const configured = {
  CODEBUDDY_CODE_ENABLE_TELEMETRY: '1', OTEL_TRACES_EXPORTER: 'otlp', OTEL_SERVICE_NAME: 'workbuddy',
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: 'http://127.0.0.1:4318/v1/traces',
  OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: 'http/protobuf',
  OTEL_EXPORTER_OTLP_TRACES_HEADERS: 'Authorization=Bearer%20synthetic', OTEL_SEMCONV: 'codebuddy',
};
const snapshots = [];
const lifecycle = new Lifecycle();
Object.assign(lifecycle, {
  logger: {warn() {}}, buildInitOptions: async () => ({}), doInitialize() {},
  traceService: {async init() { snapshots.push(readEnv()); }},
});
lifecycle.onStart();
await new Promise(resolve => setImmediate(resolve));
assert.equal(snapshots.length, 1);
assert.equal(snapshots[0].enabledByEnv, false);
const interceptor = new Interceptor();
interceptor.settingsManager = {get: async () => configured};
await interceptor.intercept({});
assert.equal(readEnv().enabledByEnv, true);
assert.equal(snapshots.length, 1, 'The turn interceptor does not reinitialize the startup exporter.');

// Run the actual desktop child-environment filter, isolated from native services.
const archive = await readFile(path.join(resources, 'app.asar'));
const header = JSON.parse(archive.subarray(16, 16 + archive.readUInt32LE(12)).toString());
const entry = header.files.main.files['cli-process-env.js'];
const offset = 8 + archive.readUInt32LE(4) + Number(entry.offset);
const hostSource = archive.subarray(offset, offset + entry.size).toString();
const host = vm.createContext({exports: {}, process: {env: {}}, require: () => ({a() {}, n() {}, r: () => false})});
vm.runInContext(hostSource, host);
const buildChildEnv = host.exports.n;
const filtered = buildChildEnv({}, configured);
assert.equal(filtered.CODEBUDDY_CODE_ENABLE_TELEMETRY, undefined);
assert.equal(filtered.OTEL_SERVICE_NAME, 'workbuddy');
const fallback = buildChildEnv({}, {...configured, CLAUDE_CODE_ENABLE_TELEMETRY: '1'});
assert.equal(readEnv(fallback).enabledByEnv, true);
assert.equal(readEnv(fallback).headers.Authorization, 'Bearer synthetic');

// The installed streaming parser strips cache details before the usage emitter.
const parser = vm.runInContext('({' + extract('parseSSEChunk(t,i=', 'normalizeStreamingToolCallIds(') + '})', context);
const raw = {prompt_tokens: 100, completion_tokens: 20, total_tokens: 120,
  cache_read_input_tokens: 0, cache_creation_input_tokens: 0};
const parsed = parser.parseSSEChunk('data: ' + JSON.stringify({usage: raw}) + '\n');
assert.equal(parsed.monitorUsage.prompt_tokens, 100);
assert.equal(parsed.monitorUsage.cache_read_input_tokens, undefined);
const emitted = [];
context.c = {Bw$: {getCacheReadTokens: value => value.cache_read_input_tokens || 0,
  getCacheCreationTokens: value => value.cache_creation_input_tokens || 0}};
context.emitCliExecutionEvent = (_session, name, options) => emitted.push({name, data: options.data});
vm.runInContext(extract('function emitCliModelUsageEvent(', '},23719('), context);
const emit = vm.runInContext('emitCliModelUsageEvent', context);
for (const rawUsage of [parsed.monitorUsage, raw]) {
  emit({}, {rawUsage, modelRequestId: 'synthetic-request', requestedModel: 'synthetic-model'});
}
assert.equal(emitted[0].data.cacheReadTokens, undefined);
assert.equal(emitted[0].data.cacheWriteTokens, undefined);
assert.equal(emitted[1].data.cacheReadTokens, 0);
assert.equal(emitted[1].data.cacheWriteTokens, 0);
console.log(JSON.stringify({runtime: '2.165.0', digest,
  settingsEnvAvailableAtStartup: snapshots[0].enabledByEnv,
  settingsEnvReinitializesExporter: snapshots.length > 1,
  inheritedCodebuddyEnableFlagSurvivesDesktopFilter: Boolean(filtered.CODEBUDDY_CODE_ENABLE_TELEMETRY),
  inheritedClaudeFallbackEnablesTelemetry: readEnv(fallback).enabledByEnv,
  streamingUsage: emitted[0], explicitZeroCacheUsage: emitted[1],
}, null, 2));
