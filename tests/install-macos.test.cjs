const assert = require('node:assert/strict');
const {readFileSync, mkdtempSync, mkdirSync, realpathSync, writeFileSync, rmSync} = require('node:fs');
const {resolve, join} = require('node:path');
const {tmpdir} = require('node:os');
const {spawnSync} = require('node:child_process');
const {test} = require('node:test');
const {runInNewContext} = require('node:vm');

const source = readFileSync(resolve(__dirname, '../apps/dashboard/public/install-macos.js'), 'utf8');
const script = {};
runInNewContext(source, script);
const link = 'https://tenant.example/enroll#token=oaet_' + 'a'.repeat(43);
const app = '/Applications/OpenAIDR.app';

function environment(options = {}) {
    const calls = [];
    const mac = {
        home: '/Users/test',
        exists: path => (options.installed && path === (options.app || app)) ||
            (options.removed && path.endsWith('/desktop-removal.json')) || path.endsWith('/Contents/MacOS/openaidr'),
        writable: () => options.writable !== false,
        useConsoleUser(callerUid) {
            calls.push({command: 'console-user', callerUid});
            if (options.noUser) throw new Error('No user is logged in');
        },
        sleep() { calls.push({command: 'sleep'}); },
        exec(command, args, input) {
            calls.push({command, args: Array.from(args), input});
            if (command === options.fail) throw new Error('Simulated failure');
            if (command === '/usr/bin/id') return options.root ? '0' : '501';
            if (command === '/usr/sbin/sysctl') return options.intel ? '0' : '1';
            if (command === '/usr/bin/sw_vers') return options.macos || '15.7';
            if (command === '/usr/bin/mktemp') {
                return args.includes('-t') ? '/private/tmp/installer' : '/Applications/.openaidr-install.test';
            }
            return '';
        },
        confirm(message, button) {
            calls.push({command: 'confirm', button, message});
            if (button === options.cancel) throw new Error('Cancelled');
        },
        enrollmentLink() { calls.push({command: 'prompt'}); return options.link || link; },
        bridge(sensor, action, params) {
            calls.push({command: action, params: JSON.parse(JSON.stringify(params))});
            if (action === options.fail) throw new Error('Simulated failure');
            if (action === 'status') return {
                enrolled: !!options.enrolled, server_url: 'https://saved.example', tenant_name: 'Saved Org',
                ...(calls.some(call => call.command === 'setup') ? options.laterStatus : {}),
            };
            if (action === 'setup') return {
                steps: [{step: 'service.install', ok: true}], enrolled: true, running: true,
                service: 'running', telemetry: {enabled: true, listening: true}, ...options.setup,
            };
            if (action === 'enrollment.preview') return {
                server_url: 'https://tenant.example', tenant: {id: 'tenant-id', name: 'Example Org'},
                auth_mode: 'mtls',
            };
            if (action === 'enrollment.connect') return {enrolled: true};
            throw new Error('Unexpected bridge action: ' + action);
        },
        move(source, destination) { calls.push({command: 'move', source, destination}); },
        quit(app) {
            calls.push({command: 'quit', app});
            if (options.fail === 'quit') throw new Error('Simulated failure');
        },
        resume(sensor, app) {
            calls.push({command: 'resume', sensor, app});
            mac.quit(app);
            if (options.fail === 'resume') throw new Error('Simulated failure');
        },
        cleanup(path) { calls.push({command: 'cleanup', path}); },
        progress(message) { calls.push({command: 'progress', message}); },
    };
    return {mac, calls};
}

test('fresh installation verifies before copying, confirms the organization, and enrolls once', () => {
    const {mac, calls} = environment();
    assert.match(script.install(mac), /enrolled/);
    const index = command => calls.findIndex(call => call.command === command);
    assert.ok(index('/usr/bin/codesign') < index('/usr/bin/ditto'));
    assert.ok(index('/usr/sbin/spctl') < index('/usr/bin/ditto'));
    assert.equal(calls.filter(call => call.command === '/usr/bin/codesign').length, 2);
    const signature = calls.find(call => call.command === '/usr/bin/codesign').args;
    assert.ok(signature.includes('--strict') && signature.includes('--deep'));
    assert.match(signature[signature.indexOf('-R') + 1], /^=anchor apple generic.*CLYZ4TV7UP/);
    const download = calls.find(call => call.command === '/usr/bin/curl').args;
    assert.equal(download[download.indexOf('--proto') + 1], '=https');
    assert.equal(download[download.indexOf('--proto-redir') + 1], '=https');
    assert.equal(calls.find(call => call.command === 'move').destination, app);
    const confirmation = calls.findIndex(call => call.command === 'confirm' && call.button === 'Connect');
    assert.ok(index('enrollment.preview') < confirmation && confirmation < index('enrollment.connect'));
    assert.match(calls[confirmation].message, /Example Org/);
    assert.match(calls[confirmation].message, /https:\/\/tenant.example/);
    assert.deepEqual(calls.filter(call => call.command === 'enrollment.connect').map(call => call.params),
        [{link, tenant_id: 'tenant-id'}]);
    assert.ok(index('enrollment.connect') < index('/usr/bin/open'));
    assert.ok(calls.some(call => call.command === 'cleanup' && call.path === '/private/tmp/installer'));
    assert.ok(!JSON.stringify(calls.filter(call => !call.command.startsWith('enrollment.'))).includes('oaet_'));
});

test('signature and Gatekeeper failures stop before copying or submitting enrollment', () => {
    for (const fail of ['/usr/bin/codesign', '/usr/sbin/spctl']) {
        const {mac, calls} = environment({fail});
        assert.throws(() => script.install(mac), /Simulated failure/);
        assert.ok(!calls.some(call => ['/usr/bin/ditto', 'enrollment.connect', 'prompt'].includes(call.command)));
        assert.ok(calls.some(call => call.command === '/usr/bin/hdiutil' && call.args[0] === 'detach'));
    }
});

test('copy failure cleans staging and keeps the target app untouched', () => {
    const {mac, calls} = environment({fail: '/usr/bin/ditto'});
    assert.throws(() => script.install(mac), /Simulated failure/);
    assert.ok(!calls.some(call => call.command === 'move'));
    assert.equal(calls.filter(call => call.command === 'cleanup').length, 2);
});

test('cancellation and expired links never consume a token', () => {
    for (const options of [{cancel: 'Install'}, {cancel: 'Connect'}, {fail: 'enrollment.preview'}, {link: 'https://tenant.example/enroll?token=secret'}]) {
        const {mac, calls} = environment(options);
        assert.throws(() => script.install(mac));
        assert.ok(!calls.some(call => call.command === 'enrollment.connect'));
    }
});

test('existing enrollment is preserved without a download or another token', () => {
    const {mac, calls} = environment({installed: true, enrolled: true});
    assert.match(script.install(mac), /existing connection/);
    assert.ok(calls.some(call => call.command === '/usr/bin/open'));
    assert.ok(!calls.some(call => ['/usr/bin/curl', 'prompt', 'enrollment.connect', 'move'].includes(call.command)));
});

test('a prior uninstall is resumed by the script after confirmation without consuming another link', () => {
    const {mac, calls} = environment({installed: true, enrolled: true, removed: true});
    assert.match(script.install(mac), /existing connection/);
    const confirmation = calls.findIndex(call => call.command === 'confirm' && call.button === 'Install');
    const resume = calls.findIndex(call => call.command === 'resume');
    assert.ok(confirmation >= 0 && confirmation < resume);
    const quit = calls.findIndex(call => call.command === 'quit');
    assert.ok(confirmation < resume && resume < quit);
    assert.equal(calls[quit].app, app);
    assert.match(calls[confirmation].message, /Saved Org/);
    assert.match(calls[confirmation].message, /https:\/\/saved.example/);
    assert.ok(resume < calls.findIndex(call => call.command === '/usr/bin/open'));
    assert.ok(!calls.some(call => ['prompt', 'enrollment.preview', 'enrollment.connect'].includes(call.command)));
});

test('cancelled or failed reinstalls do not launch the app or consume a link', () => {
    for (const options of [{cancel: 'Install'}, {fail: 'quit'}, {fail: 'resume'}]) {
        const {mac, calls} = environment({installed: true, enrolled: true, removed: true, ...options});
        assert.throws(() => script.install(mac), /Cancelled|Simulated failure/);
        assert.ok(!calls.some(call => ['prompt', 'enrollment.connect', '/usr/bin/open'].includes(call.command)));
        if (options.cancel) assert.ok(!calls.some(call => call.command === 'resume'));
        if (options.cancel) assert.ok(!calls.some(call => call.command === 'quit'));
    }
});

test('a removed app without enrollment confirms its organization before resuming setup', () => {
    const {mac, calls} = environment({installed: true, removed: true});
    script.install(mac);
    const commands = calls.map(call => call.command);
    assert.ok(commands.indexOf('enrollment.connect') >= 0);
    assert.ok(commands.indexOf('enrollment.connect') < commands.indexOf('resume'));
    assert.ok(commands.indexOf('resume') < commands.indexOf('/usr/bin/open'));
});

test('existing home Applications installs are reused without creating a second app', () => {
    const existing = '/Users/test/Applications/OpenAIDR.app';
    const {mac, calls} = environment({installed: true, enrolled: true, app: existing});
    script.install(mac);
    assert.deepEqual(calls.find(call => call.command === '/usr/bin/open').args, [existing]);
    assert.ok(!calls.some(call => ['move', '/usr/bin/ditto'].includes(call.command)));
});

test('an unwritable Applications folder stops before downloading instead of installing in a hidden location', () => {
    const {mac, calls} = environment({writable: false});
    assert.throws(() => script.install(mac), /permission.*\/Applications/);
    assert.ok(!calls.some(call => ['/usr/bin/curl', 'move', 'prompt'].includes(call.command)));
});

test('uncertain enrollment and launch failures do not resubmit the link', () => {
    for (const fail of ['enrollment.connect', '/usr/bin/open']) {
        const {mac, calls} = environment({installed: true, fail});
        assert.throws(() => script.install(mac), fail === '/usr/bin/open' ? /Enrollment succeeded/ : /Simulated failure/);
        assert.equal(calls.filter(call => call.command === 'enrollment.connect').length, 1);
    }
});

test('unsupported hosts stop before installation', () => {
    for (const options of [{root: true}, {macos: '11.7.10'}, {intel: true, macos: '11.7'}]) {
        const {mac, calls} = environment(options);
        assert.throws(() => script.install(mac), /normal macOS account|macOS 12 \(Monterey\) or later/);
        assert.ok(!calls.some(call => call.command === 'confirm'));
    }
});

test('the universal installer proceeds on Intel and Apple Silicon Macs with macOS 12 or later', () => {
    for (const options of [{intel: true, macos: '12.7.6'}, {macos: '12.0'}, {intel: true}]) {
        const {mac, calls} = environment(options);
        assert.match(script.install(mac), /enrolled/);
        assert.ok(calls.some(call => call.command === '/usr/bin/curl'));
    }
});

test('an eject failure retains the download directory without traversing the mounted image', () => {
    const {mac, calls} = environment();
    const exec = mac.exec;
    mac.exec = (command, args, input) => {
        if (command === '/usr/bin/hdiutil' && args[0] === 'detach') throw new Error('Volume busy');
        return exec(command, args, input);
    };
    script.install(mac);
    assert.ok(!calls.some(call => call.command === 'cleanup' && call.path === '/private/tmp/installer'));
    assert.ok(calls.some(call => call.command === 'progress' && call.message.includes('Eject OpenAIDR')));
});

for (const root of [true, false]) {
test(`MDM installs silently as ${root ? 'root' : 'the logged-in user'}`, () => {
    const {mac, calls} = environment({root});
    assert.match(script.install(mac, true), /background sensor is running/);
    const commands = calls.map(call => call.command);
    assert.ok(commands.indexOf('console-user') < commands.indexOf('/usr/bin/curl'));
    assert.equal(commands.filter(command => command === '/usr/bin/codesign').length, 2);
    assert.equal(commands.filter(command => command === '/usr/sbin/spctl').length, 2);
    assert.equal(calls.find(call => call.command === 'console-user').callerUid, root ? '0' : '501');
    if (root) {
        assert.deepEqual(calls.find(call => call.command === '/usr/sbin/chown').args,
            ['-R', '-P', 'root:wheel', '/Applications/.openaidr-install.test/OpenAIDR.app']);
    } else {
        assert.ok(!calls.some(call => ['/usr/sbin/chown', '/usr/bin/sudo'].includes(call.command)));
    }
    assert.ok(commands.indexOf('enrollment.preview') < commands.indexOf('enrollment.connect'));
    assert.ok(commands.indexOf('enrollment.connect') < commands.indexOf('setup'));
    assert.ok(!commands.includes('confirm') && !commands.includes('/usr/bin/open'));
    assert.equal(commands.filter(command => command === 'enrollment.connect').length, 1);
});
}

test('MDM rejects unwritable destinations, absent users, removed installations, and failed signature checks without enrollment', () => {
    for (const options of [
        {root: false, writable: false}, {noUser: true}, {removed: true},
        {fail: '/usr/bin/codesign'}, {fail: '/usr/sbin/spctl'}, {fail: '/usr/sbin/chown'},
    ]) {
        const {mac, calls} = environment({root: true, ...options});
        assert.throws(() => script.install(mac, true));
        assert.ok(!calls.some(call => ['confirm', '/usr/bin/open', 'enrollment.connect', 'setup', 'resume'].includes(call.command)));
        if (!options.fail) assert.ok(!calls.some(call => call.command === '/usr/bin/curl'));
    }
});

test('MDM retries preserve enrollment and repair setup without consuming another token', () => {
    for (const root of [true, false]) {
        const {mac, calls} = environment({root, installed: true, enrolled: true, writable: false});
        script.install(mac, true);
        assert.equal(calls.filter(call => call.command === 'setup').length, 1);
        assert.ok(!calls.some(call => ['confirm', 'prompt', 'enrollment.preview', 'enrollment.connect', '/usr/bin/open', '/usr/bin/curl'].includes(call.command)));
    }
});

test('MDM reports incomplete setup and waits for a running sensor without reenrolling', () => {
    for (const setup of [
        {steps: [{step: 'hooks.install', ok: false}]}, {steps: null},
        {service: 'stopped'}, {running: false}, {enrolled: false}, {settings_stale: true},
        {telemetry: {enabled: true, listening: false}},
    ]) {
        const {mac, calls} = environment({root: true, installed: true, setup});
        assert.throws(() => script.install(mac, true), /background setup is incomplete|background sensor is not ready/);
        assert.equal(calls.filter(call => call.command === 'enrollment.connect').length, 1);
        assert.ok(!calls.some(call => ['confirm', '/usr/bin/open'].includes(call.command)));
        assert.ok(calls.filter(call => call.command === 'sleep').length <= 30);
    }
    for (const delay of [1, 30]) {
        const options = {root: true, installed: true, setup: {running: false}};
        const {mac, calls} = environment(options);
        const sleep = mac.sleep;
        mac.sleep = () => {
            sleep();
            if (calls.filter(call => call.command === 'sleep').length === delay) options.laterStatus = {
                enrolled: true, service: 'running', running: true, telemetry: {enabled: true, listening: true},
            };
        };
        assert.match(script.install(mac, true), /background sensor is running/);
        assert.equal(calls.filter(call => call.command === 'sleep').length, delay);
    }
});

test('MDM selects a real login session and sends secrets only through a user-scoped input pipe', () => {
    for (const [callerUid, uid, name, home, accepted] of [
        ['0', '501', 'test', '/Users/test', true], ['0', '502', 'other', '/Users/Other User', true],
        ['501', '501', 'test', '/Users/test', true], ['502', '502', 'other', '/Users/Other User', true],
        ['501', '502', 'other', '/Users/other', false],
        ['0', '0', 'root', '/var/root', false], ['0', '248', '_mbsetupuser', '/var/setup', false],
        ['0', '501', '_mbsetupuser', '/Users/setup', false], ['0', '501', 'test', '/', false],
        ['0', '501', 'test', null, false], ['0', 'invalid', 'test', '/Users/test', false],
    ]) {
        const context = {
            ObjC: {import() {}, bindFunction() {}, unwrap: value => value},
            Application: {currentApplication() { throw new Error('MDM initialized dialog support'); }},
            $: {
                NSFileManager: {defaultManager: {fileExistsAtPath: () => true}},
                NSHomeDirectory: () => '/var/root', NSHomeDirectoryForUser: () => home,
            },
        };
        runInNewContext(source, context);
        const mac = context.nativeMac(true);
        const calls = [];
        mac.exec = (command, args, input) => {
            calls.push({command, args: Array.from(args), input});
            if (command === '/usr/bin/stat') return uid;
            if (command === '/usr/bin/id') return name;
            return JSON.stringify({ok: true, data: {enrolled: true}});
        };
        if (!accepted) {
            assert.throws(() => mac.useConsoleUser(callerUid), /logged.in|incomplete|home folder/);
            assert.equal(mac.user, undefined);
            continue;
        }
        mac.useConsoleUser(callerUid);
        assert.equal(mac.home, home);
        assert.ok(calls.some(call => call.command === '/bin/launchctl' && call.args.join(' ') === 'print gui/' + uid));
        mac.bridge(app + '/Contents/MacOS/openaidr', 'enrollment.connect', {link, tenant_id: 'tenant-id'});
        const request = calls.at(-1);
        const args = ['-i', 'HOME=' + home, 'USER=' + name, 'LOGNAME=' + name,
            'PATH=/usr/bin:/bin:/usr/sbin:/sbin', app + '/Contents/MacOS/openaidr', 'desktop-bridge'];
        if (callerUid === '0') {
            assert.equal(request.command, '/bin/launchctl');
            assert.deepEqual(request.args, ['asuser', uid, '/usr/bin/sudo', '-H', '-n', '-u', '#' + uid, '/usr/bin/env', ...args]);
        } else {
            assert.equal(request.command, '/usr/bin/env');
            assert.deepEqual(request.args, args);
            assert.ok(!request.args.includes('/usr/bin/sudo'));
        }
        assert.equal(JSON.parse(request.input).params.link, link);
        assert.ok(!request.args.join(' ').includes(link));
    }
});

test('reinstall quits only the installed app, waits for termination, and refuses an unresponsive app', () => {
    for (const outcome of ['closed', 'other copy', 'refused', 'unresponsive']) {
        let now = 0;
        let attempts = 0;
        let turns = 0;
        const instance = {
            bundleURL: {path: outcome === 'other copy' ? '/Downloads/OpenAIDR.app' : app},
            isTerminated: false,
            get terminate() { attempts++; return outcome !== 'refused'; },
        };
        const context = {
            ObjC: {import() {}, bindFunction() {}, unwrap: value => value},
            Application: {currentApplication: () => ({})},
            Date: {now: () => now},
            $: {
                NSFileManager: {defaultManager: {}}, NSHomeDirectory: () => '/Users/test',
                NSRunningApplication: {runningApplicationsWithBundleIdentifier: identifier => ({
                    count: identifier === 'com.opensecura.openaidr.sensor' ? 1 : 0,
                    objectAtIndex: () => instance,
                })},
                NSDate: {dateWithTimeIntervalSinceNow: seconds => seconds},
                NSRunLoop: {currentRunLoop: {runUntilDate(seconds) {
                    now += seconds * 1000;
                    turns++;
                    if (outcome === 'closed') instance.isTerminated = true;
                }}},
            },
        };
        runInNewContext(source, context);
        const quit = () => context.nativeMac().quit(app);
        if (outcome === 'closed') {
            quit();
            assert.equal(turns, 1);
        } else {
            assert.throws(quit, /Quit the running|still closing/);
        }
        assert.equal(attempts, outcome === 'other copy' ? 0 : 1);
        assert.ok(now <= 5000);
    }
});

if (process.platform === 'darwin') {
    test('native MDM entry point stays noninteractive and returns failure for setup errors and invalid arguments', () => {
        const directory = mkdtempSync(join(tmpdir(), 'openaidr-mdm-test-'));
        try {
            for (const [root, failure] of [[true, false], [true, true], [false, false], [false, true]]) {
                const harness = source + `
var link = ${JSON.stringify(link)};
var app = ${JSON.stringify(app)};
${environment.toString()}
nativeMac = function (mdm) {
    if (!mdm) throw new Error('MDM mode was lost');
    ObjC.import('Foundation');
    var state = environment({root: ${root}, installed: true, fail: ${failure ? "'setup'" : "'unused'"}});
    state.mac.confirm = state.mac.notify = state.mac.enrollmentLink = function () { throw new Error('Unexpected dialog'); };
    return state.mac;
};`;
                const file = join(directory, 'installer.js');
                writeFileSync(file, harness);
                const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', file, '--mdm', '--enrollment-stdin'], {
                    input: link + '\n', encoding: 'utf8', timeout: 15000,
                });
                assert.equal(result.status === 0, !failure, result.stderr);
                assert.match(failure ? result.stderr : result.stdout, failure ? /Simulated failure/ : /background sensor is running/);
                assert.ok(!result.stdout.includes(link) && !result.stderr.includes(link));
            }
            const file = join(directory, 'installer.js');
            writeFileSync(file, source);
            for (const args of [['--mdm'], ['--mdm', '--wrong'], ['--enrollment-stdin', '--enrollment-stdin']]) {
                const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', file, ...args], {
                    input: '', encoding: 'utf8', timeout: 15000,
                });
                assert.notEqual(result.status, 0);
                assert.match(result.stderr, /Usage:/);
            }
        } finally {
            rmSync(directory, {recursive: true, force: true});
        }
    });

    test('native reinstall restores preferences and updates under both app locks, retaining the marker on failures', () => {
        const home = realpathSync(mkdtempSync(join(tmpdir(), 'openaidr-resume-test-')));
        const directory = join(home, 'Library/Application Support/OpenAIDR');
        mkdirSync(directory, {recursive: true, mode: 0o700});
        const marker = join(directory, 'desktop-removal.json');
        writeFileSync(marker, '{}');
        try {
            const harness = source + `
function run() {
    var mac = nativeMac();
    mac.home = ${JSON.stringify(home)};
    var directory = ${JSON.stringify(directory)};
    var marker = ${JSON.stringify(marker)};
    var names = ['desktop-updater.lock', 'desktop-operation.lock'];
    var events = [];
    var failure = '';
    var exec = mac.exec;
    mac.exec = function (command, args, input) {
        if (command !== '/bin/launchctl') return exec(command, args, input);
        if (!mac.exists(marker)) throw new Error('Marker cleared before updates were enabled');
        if (args[0] !== 'enable' || args[1] !== 'gui/' + exec('/usr/bin/id', ['-u']).trim() + '/com.opensecura.openaidr.updater') throw new Error('Incorrect update registration');
        events.push('enable');
        if (failure === 'enable') throw new Error('Simulated enable failure');
        return '';
    };
    function checkLocks(held) {
        names.forEach(function (name) {
            var descriptor = $.open(directory + '/' + name, 2);
            if (descriptor < 0) throw new Error('Missing lock: ' + name);
            var locked = $.flock(descriptor, 2 | 4) === 0;
            $.close(descriptor);
            if (locked === held) throw new Error('Incorrect lock state: ' + name);
        });
    }
    mac.quit = function (app) {
        if (app !== '/test/OpenAIDR.app') throw new Error('Unexpected app');
        checkLocks(true);
        events.push('quit');
        if (failure === 'quit') throw new Error('Simulated quit failure');
    };
    mac.bridge = function (sensor, action) {
        if (sensor !== '/test/sensor' || action !== 'desktop.resume') throw new Error('Unexpected bridge request');
        checkLocks(true);
        if (!mac.exists(marker)) throw new Error('Marker cleared before preferences were restored');
        events.push('restore');
        if (failure === 'restore') throw new Error('Simulated restore failure');
        return {resumed: failure !== 'response'};
    };
    ['quit', 'restore', 'response', 'enable'].forEach(function (mode) {
        failure = mode;
        events = [];
        var rejected = false;
        var reason = '';
        try { mac.resume('/test/sensor', '/test/OpenAIDR.app'); } catch (error) { rejected = true; reason = error.message; }
        if (!rejected || !mac.exists(marker)) throw new Error('Failure did not preserve uninstall state: ' + mode);
        var expected = mode === 'quit' ? 'quit' : mode === 'enable' ? 'quit,restore,enable' : 'quit,restore';
        if (events.join(',') !== expected) throw new Error('Unexpected resume order: ' + mode + ': ' + reason);
        checkLocks(false);
    });
    names.forEach(function (name) {
        var descriptor = $.open(directory + '/' + name, 2);
        if ($.flock(descriptor, 2 | 4) !== 0) throw new Error('Cannot hold test lock');
        events = [];
        var rejected = false;
        try { mac.resume('/test/sensor', '/test/OpenAIDR.app'); } catch (error) { rejected = /busy/.test(error.message); }
        $.close(descriptor);
        if (!rejected || events.length || !mac.exists(marker)) throw new Error('Concurrent operation was not blocked');
        checkLocks(false);
    });
    var files = $.NSFileManager.defaultManager;
    var lock = directory + '/' + names[0];
    files.removeItemAtPathError(lock, null);
    files.createSymbolicLinkAtPathWithDestinationPathError(lock, marker, null);
    var rejected = false;
    try { mac.resume('/test/sensor', '/test/OpenAIDR.app'); } catch (_) { rejected = true; }
    if (!rejected || !mac.exists(marker)) throw new Error('Symbolic lock was accepted');
    files.removeItemAtPathError(lock, null);
    failure = '';
    events = [];
    mac.resume('/test/sensor', '/test/OpenAIDR.app');
    if (events.join(',') !== 'quit,restore,enable' || mac.exists(marker)) throw new Error('Resume did not finish');
    checkLocks(false);
    return 'Native reinstall passed';
}`;
            const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', '-'], {
                input: harness, encoding: 'utf8', timeout: 15000,
            });
            assert.equal(result.status, 0, result.stderr);
            assert.match(result.stdout, /Native reinstall passed/);
        } finally {
            rmSync(home, {recursive: true, force: true});
        }
    });

    test('the generated-command input enrolls without asking for the link again', () => {
        const directory = mkdtempSync(join(tmpdir(), 'openaidr-stdin-test-'));
        try {
            const harness = source + `
var link = ${JSON.stringify(link)};
var app = ${JSON.stringify(app)};
${environment.toString()}
nativeMac = function () {
    ObjC.import('Foundation');
    var state = environment({installed: true});
    state.mac.enrollmentLink = function () { throw new Error('Unexpected link prompt'); };
    state.mac.notify = function () {
        var connections = state.calls.filter(function (call) { return call.command === 'enrollment.connect'; });
        if (connections.length !== 1 || connections[0].params.link !== link) throw new Error('Incorrect enrollment input');
    };
    return state.mac;
};`;
            const file = join(directory, 'installer.js');
            writeFileSync(file, harness);
            const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', file, '--enrollment-stdin'], {
                input: link + '\n', encoding: 'utf8', timeout: 15000,
            });
            assert.equal(result.status, 0, result.stderr);
            assert.match(result.stdout, /This Mac is enrolled/);
            assert.ok(!result.stdout.includes(link) && !result.stderr.includes(link));
        } finally {
            rmSync(directory, {recursive: true, force: true});
        }
    });

    test('native macOS transport pipes data and refuses to replace an existing destination', () => {
        const directory = mkdtempSync(join(tmpdir(), 'openaidr-script-test-'));
        try {
            writeFileSync(join(directory, 'source'), 'new');
            writeFileSync(join(directory, 'destination'), 'existing');
            const harness = source + `
function run() {
    var mac = nativeMac();
    var directory = ${JSON.stringify(directory)};
    var secret = ${JSON.stringify(link)};
    if (mac.exec('/bin/cat', [], secret) !== secret) throw new Error('Input pipe did not preserve data');
    if (!mac.exists(directory + '/source')) throw new Error('Cannot locate the source');
    var refused = false;
    try { mac.move(directory + '/source', directory + '/destination'); } catch (_) { refused = true; }
    if (!refused) throw new Error('Existing destination was replaced');
    mac.move(directory + '/source', directory + '/moved');
    if (!mac.exists(directory + '/moved')) throw new Error('Move failed');
    mac.cleanup(directory + '/moved');
    if (mac.exists(directory + '/moved')) throw new Error('Cleanup failed');
    var failed = false;
    try { mac.exec('/usr/bin/false', []); } catch (_) { failed = true; }
    if (!failed) throw new Error('Nonzero exit status was ignored');
    var uid = mac.exec('/usr/bin/id', ['-u']).trim();
    mac.user = {uid: uid, name: 'mdm-test', home: directory, root: false};
    var execute = mac.exec;
    mac.exec = function (command, args, input) {
        if (command !== '/usr/bin/env' || args.indexOf('/usr/bin/sudo') !== -1) throw new Error('User transport attempted privilege changes');
        return execute(command, args, input);
    };
    if (mac.userExec('/usr/bin/id', ['-u']).trim() !== uid) throw new Error('User identity changed');
    if (mac.userExec('/bin/cat', [], secret) !== secret) throw new Error('User transport lost its input');
    var environment = mac.userExec('/usr/bin/env', []).trim().split('\\n').sort();
    var expected = ['HOME=' + directory, 'USER=mdm-test', 'LOGNAME=mdm-test', 'PATH=/usr/bin:/bin:/usr/sbin:/sbin'].sort();
    if (JSON.stringify(environment) !== JSON.stringify(expected)) throw new Error('User transport inherited the caller environment');
    return 'Native transport passed';
}`;
            const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', '-'], {
                input: harness, encoding: 'utf8', timeout: 15000,
            });
            assert.equal(result.status, 0, result.stderr);
            assert.match(result.stdout, /Native transport passed/);
            assert.equal(readFileSync(join(directory, 'destination'), 'utf8'), 'existing');
        } finally {
            rmSync(directory, {recursive: true, force: true});
        }
    });
}
