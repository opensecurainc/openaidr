#!/usr/bin/env node
// Run the installed runtime's hook executor and tool gate with isolated services.
// This is a compatibility probe, not a full WorkBuddy desktop session test.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {StringDecoder} from 'node:string_decoder';
import vm from 'node:vm';

const cli = process.argv[2] || '/Applications/WorkBuddy AI.app/Contents/Resources/app.asar.unpacked/cli';
const output = path.resolve(process.argv[3] || 'build/workbuddy-hooks');
const source = await readFile(path.join(cli, 'dist/codebuddy-lite-wb.mjs'), 'utf8');
const packageInfo = JSON.parse(await readFile(path.join(cli, 'package.json'), 'utf8'));
const product = JSON.parse(await readFile(path.join(cli, 'product.json'), 'utf8'));
assert.equal(process.platform, 'darwin', 'This probe has only been prepared for macOS.');
assert.equal(packageInfo.version, '2.165.0', 'Review extraction boundaries for another runtime version.');
const digest = createHash('sha256').update(source).digest('hex');
assert.equal(digest, 'af69dd4dc7b5184502cdf2db1687dccaef57f93e28171941e0219d1570c4bd1a',
  'Review the installed runtime before executing changed vendor code.');
await mkdir(output, {recursive: true});
const home = path.join(output, 'home');
await mkdir(home, {recursive: true});

function extract(start, end) {
  const first = source.indexOf(start);
  assert(first >= 0, `Missing extraction start: ${start}`);
  const last = source.indexOf(end, first + start.length);
  assert(last > first, `Missing extraction end: ${end}`);
  return source.slice(first, last);
}

const logs = [];
const logger = Object.fromEntries(['debug', 'info', 'warn', 'error'].map(level =>
  [level, (...args) => logs.push({level, text: args.map(String).join(' ')})]));
const safeEnv = {
  HOME: home, PATH: '/usr/bin:/bin', TMPDIR: output,
  CODEBUDDY_CONFIG_DIR: home, WORKBUDDY_CONFIG_DIR: home,
};
const hookEvents = {PRE_TOOL_USE: 'PreToolUse', USER_PROMPT_SUBMIT: 'UserPromptSubmit',
  STOP: 'Stop', SUBAGENT_STOP: 'SubagentStop'};
let shell = '/bin/sh';
const children = new Set();
class ToolBlocked extends Error {
  constructor(tool, reason) { super(`${tool}: ${reason}`); this.name = 'ToolBlocked'; }
}
const globals = {
  process: {env: safeEnv, platform: process.platform, cwd: () => output},
  console: {error() {}}, setTimeout, clearTimeout, Error,
  ku: {getStore: () => ({environment: safeEnv, onSpawn(child) { children.add(child); }})},
  kd: {t7: async () => {}},
  kl: {Pz: ({baseEnv = safeEnv, env = {}}) => ({...baseEnv, ...env})},
  pf: {uF: () => false, vg: () => ({executable: shell, argsPrefix: ['-c']}), E5: () => ({})},
  pg: {spawn}, ks: {y: StringDecoder}, kp: 60000,
  registerHookPid() {}, unregisterHookPid() {},
  gp: {mb: hookEvents}, kc: {d: () => undefined},
  pn: {R40: {createHookMessage: (...args) => ({args})}},
  nq: {FqK: session => session.id, IRv: () => ({})},
  nQ: {mb: hookEvents, L3: {DEFER_EXECUTE: 'DeferExecuteTool'}},
  af: {PathUtils: {getWorkDir: () => output}},
  sg: {uN: async () => undefined},
  nr: {Ll: ToolBlocked, I8: {is: () => false}},
  sp: {Tr: async (_session, _call, callback) => callback()},
};
const context = vm.createContext(globals);
vm.runInContext(extract('function buildHookSpawnOptions(', 'function isPowerShellExecutable('), context);
vm.runInContext(extract('let uv="codebuddy.ai/approval"', 'let ub=class'), context);
const Executor = vm.runInContext('(' + extract('let kh=class', ';hook_executor_decorate').slice(7) + ')', context);
const executor = new Executor();
executor.logger = executor.debugService = logger;

function methods(parts) {
  return vm.runInContext('({' + parts.map(([start, end]) => extract(start, end)).join(',') + '})', context);
}
const manager = methods([
  ['async executeCommandHook(', 'deduplicateHooks('],
  ['aggregateSettledResults(t){', 'mergeMessages(t){'],
]);
manager.logger = logger;
manager.hookExecutor = executor;
manager.onceFired = new WeakSet();
const toolHooks = methods([['async executePreToolUseHooks(', 'async executePostToolUseHooks(']]);
toolHooks.logger = logger;
toolHooks.galileoSessionBridge = {addToolStartSpanEvent() {}};
toolHooks.hookManager = manager;
toolHooks.executePostToolUseHooks = async () => ({});
const toolManager = methods([['async doExecuteToolWithHooks(', 'async authorizeFinalToolAction(']]);
Object.assign(toolManager, {
  logger, toolHookManager: toolHooks,
  sessionStore: {getSessionFilePath: () => path.join(home, 'probe.jsonl')},
  getPlainToolInput: input => input, extractRawResponse: (_tool, result) => result,
});
for (const name of ['recordToolRiskBuiltinCall', 'checkIdeInputTransformation', 'authorizeFinalToolAction',
  'enforceInheritedRestrictionDeny', 'authorizeToolEgress', 'recordToolRiskExecutionStatus',
  'tryInterceptTool', 'createFileBackupBeforeExecute', 'reportMcpToolCapabilityCall',
  'injectConditionalRules', 'recordToolRiskBuiltinResult']) toolManager[name] = () => undefined;

const quote = text => "'" + text.replaceAll("'", "'\\''") + "'";
const decision = value => "printf '%s' " + quote(JSON.stringify({hookSpecificOutput: {
  hookEventName: 'PreToolUse', permissionDecision: value, permissionDecisionReason: 'Probe decision',
}}));
const cases = [
  {name: 'empty_success', commands: [':'], allowed: true},
  {name: 'backend_unavailable_silent_success', commands: ['exit 0'], allowed: true},
  {name: 'deny', commands: [decision('deny')], allowed: false},
  {name: 'ask', commands: [decision('ask')], allowed: true, decision: 'ask'},
  {name: 'allow', commands: [decision('allow')], allowed: true, decision: 'allow'},
  {name: 'malformed_success', commands: ["printf '%s' '{invalid'"], allowed: true},
  {name: 'nonzero_exit', commands: ['exit 1'], allowed: true},
  {name: 'blocking_exit', commands: ['exit 2'], allowed: false},
  {name: 'missing_command', commands: ['openaidr-probe-command-does-not-exist'], allowed: true},
  {name: 'shell_spawn_failure', commands: [':'], shell: '/missing/openaidr-probe-shell', allowed: false},
  {name: 'native_timeout', commands: ['exec /bin/sleep 10'], timeout: 0.2, allowed: false},
  {name: 'signal_exit', commands: ['kill -TERM $$'], allowed: false},
  {name: 'multiple_empty_and_deny', commands: [':', decision('deny')], allowed: false},
  {name: 'multiple_empty_and_timeout', commands: [':', 'exec /bin/sleep 10'], timeout: 0.2, allowed: false},
];
const results = [];
try {
  for (const item of cases) {
    shell = item.shell || '/bin/sh';
    let preTool, hookResults, executed = false;
    manager.executeHooks = async (event, input, details) => {
      const settled = await Promise.allSettled(item.commands.map(command => manager.executeCommandHook(
        {type: 'command', command, timeout: item.timeout || 3}, input, safeEnv, event, details)));
      hookResults = settled.map(result => {
        assert.equal(result.status, 'fulfilled', `${item.name}: unexpected hook rejection`);
        const {allowed, exitCode, blocking} = result.value;
        assert.equal(typeof exitCode, 'number', `${item.name}: executor did not finish`);
        return {allowed, exitCode, blocking: blocking || false};
      });
      return manager.aggregateSettledResults(settled);
    };
    const nativePreTool = toolHooks.executePreToolUseHooks;
    toolManager.toolHookManager = {
      executePreToolUseHooks: async (...args) => {
        preTool = await nativePreTool.apply(toolHooks, args);
        return preTool;
      },
      executePostToolUseHooks: async () => ({}),
    };
    const started = performance.now();
    let failure;
    try {
      await toolManager.doExecuteToolWithHooks({name: 'Probe', dispatchesModToolCall: true}, async () => {
        executed = true;
        return 'local probe tool executed';
      }, {}, {context: {id: item.name, inputSubject: {next() {}}}}, {toolCall: {callId: item.name}}, 'parsed');
    } catch (error) {
      assert(error instanceof ToolBlocked, `${item.name}: unexpected failure ${error.stack}`);
      failure = error.message;
    }
    assert.equal(preTool.allowed, item.allowed, item.name + ': ' + JSON.stringify(logs.slice(-5)));
    assert.equal(executed, item.allowed, `${item.name}: native tool gate`);
    if (item.decision) assert.equal(preTool.permissionDecision, item.decision, item.name);
    results.push({name: item.name, hookResults, allowed: preTool.allowed, toolExecuted: executed,
      permissionDecision: preTool.permissionDecision || null,
      failure: failure || null, durationMs: Math.round(performance.now() - started)});
  }
} finally {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}
const report = {
  date: new Date().toISOString(), platform: process.platform, arch: process.arch,
  nodeVersion: process.version,
  product: product.productName, desktopVersion: product.genieVersion,
  runtimeVersion: packageInfo.version, runtimeSha256: digest,
  boundary: 'Installed executor, command-hook adapter, result aggregator, pre-tool manager, and native tool execution gate; isolated environment and unrelated services.',
  limitations: ['Not a full desktop session.', 'Native approval UI not exercised; ask flag propagation only.',
    'No Windows runtime tested.', 'No real credentials, external model calls, or WorkBuddy settings used.'],
  failOpenCompatible: results.filter(result =>
    ['shell_spawn_failure', 'native_timeout', 'signal_exit', 'multiple_empty_and_timeout'].includes(result.name))
    .every(result => result.toolExecuted),
  results,
};
await writeFile(path.join(output, 'results.json'), JSON.stringify(report, null, 2) + '\n');
await writeFile(path.join(output, 'runtime-log.json'), JSON.stringify(logs, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
