'use strict';
// UNIT ONLY: synthetic receipt/PID records never constitute Native evidence.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const driver = require('./driver.cjs');
test('UNIT: new CLI consumes exactly --electron and --out, without legacy --root', () => {
  assert.deepEqual(driver.parseArgs(['--electron', '/runtime/electron.exe', '--out', '/public/run']),
    { electron: '/runtime/electron.exe', out: '/public/run' });
  for (const args of [[], ['--electron', 'x'], ['--electron', 'x', '--out', 'y', '--root', 'z'],
    ['--electron', 'x', '--out', 'y', '--out', 'z'], ['--electron', '--no-sandbox', '--out', 'y']]) {
    assert.throws(() => driver.parseArgs(args));
  }
});
const native = require('./electron-main.cjs');
const nonce = 'a'.repeat(64);
function temp(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-native-unit-'));
  try { return run(root); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
test('UNIT: main parser accepts ordinary and exact consumed logging layouts, imports inert', () => {
  const run = path.resolve('/run/unit'), entry = path.join(run, 'electron-main.cjs');
  const tail = ['--phase', 'init', '--run-dir', run, '--nonce', nonce];
  const plain = ['/electron.exe', entry, ...tail];
  const logged = ['/electron.exe', '--enable-logging=file', `--log-file=${path.join(run, 'logs', 'chromium.log')}`, entry, ...tail];
  assert.equal(native.parseProcessArgs(plain, entry).phase, 'init');
  assert.equal(native.parseProcessArgs(logged, entry).nonce, nonce);
  for (const args of [[...plain, '--other', 'x'], [...logged.slice(0, 1), '--no-sandbox', ...logged.slice(2)],
    [...plain.slice(0, -1), 'bad'], [...plain.slice(0, 3), 'unknown', ...plain.slice(4)]]) {
    assert.throws(() => native.parseProcessArgs(args, entry));
  }
  assert.equal(native.isEntrypoint(false, undefined), false);
  assert.equal(native.isEntrypoint(false, 'browser'), true);
  const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(path.join(__dirname, 'electron-main.cjs'))});require(${JSON.stringify(path.join(__dirname, 'driver.cjs'))})`], { encoding: 'utf8' });
  assert.equal(result.status, 0); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
});
test('UNIT: environment strips injection/tokens; CA only explicitly supplied physical own certificate', () => temp(root => {
  const cert = path.join(root, 'ca.pem'); fs.writeFileSync(cert, 'UNIT public certificate');
  const env = driver.environment(root, cert, { PATH: '/bin', NODE_OPTIONS: '--require evil',
    ELECTRON_RUN_AS_NODE: '1', NODE_EXTRA_CA_CERTS: '/foreign.pem', GITHUB_TOKEN: 'unit-not-a-token', NODE_TLS_REJECT_UNAUTHORIZED: '0' });
  assert.equal(env.NODE_EXTRA_CA_CERTS, cert); assert.equal(env.PATH, '/bin');
  for (const key of ['NODE_OPTIONS', 'ELECTRON_RUN_AS_NODE', 'GITHUB_TOKEN', 'NODE_TLS_REJECT_UNAUTHORIZED']) assert.equal(env[key], undefined);
  assert.equal(driver.environment(root, null, { NODE_EXTRA_CA_CERTS: '/foreign' }).NODE_EXTRA_CA_CERTS, undefined);
  const nested = path.join(root, 'controls', 'phase'); fs.mkdirSync(nested, { recursive: true });
  assert.equal(driver.environment(nested, cert, { NODE_EXTRA_CA_CERTS: '/foreign' }, root).NODE_EXTRA_CA_CERTS, cert);
  assert.throws(() => driver.environment(root, path.join(root, '..', 'foreign.pem')));
}));
test('UNIT: source copies are physical, byte-hashed and resolve pinned SemVer in expected layout', () => temp(root => {
  const copy = driver.copySources(path.join(root, 'sources'));
  assert.ok(copy.inventory.length > 10);
  assert.equal(native.verifyInventory(copy.root, copy.inventory), copy.inventorySha256);
  assert.equal(require(path.join(copy.root, 'experiments/update-auth-windows/node_modules/semver/package.json')).version, '7.7.3');
  const leaf = path.join(copy.root, copy.inventory[0].path); fs.appendFileSync(leaf, '\n');
  assert.throws(() => native.verifyInventory(copy.root, copy.inventory), /hash/);
  const foreign = path.join(root, 'foreign'); fs.writeFileSync(foreign, 'UNIT');
  fs.unlinkSync(leaf); fs.symlinkSync(foreign, leaf);
  assert.throws(() => native.verifyInventory(copy.root, copy.inventory), /link/);
}));
test('UNIT: read public records rejects links, oversized JSON and overwrite', () => temp(root => {
  const file = path.join(root, 'receipt.json'); native.writeJSON(file, { unit: true });
  assert.deepEqual(driver.readJSON(file), { unit: true });
  assert.throws(() => native.writeJSON(file, {}), /exist/i);
  const link = path.join(root, 'link.json'); fs.symlinkSync(file, link);
  assert.throws(() => driver.readJSON(link));
  fs.writeFileSync(path.join(root, 'big.json'), ' '.repeat(65537));
  assert.throws(() => driver.readJSON(path.join(root, 'big.json')));
}));
function unitRecord(phase = 'init', pid = 101) {
  const nonce = pid.toString(16).padStart(64, '0');
  const root = path.resolve('/UNIT-NOT-NATIVE'), runDir = path.join(root, phase);
  const expected = { phase, nonce, runDir, storeDirectory: path.join(root, 'store'), sourceRoot: path.join(root, 'sources'),
    inventorySha256: 'b'.repeat(64), executable: path.join(root, 'electron.exe'), executableSha256: 'c'.repeat(64), controlPid: phase === 'tls-no-ca' ? 100 : 99 };
  if (phase.startsWith('fixture-')) expected.fixtureCreator = { runtime: 'Node', positiveEvidence: false, kind: phase.slice(8), condition: { unitSynthetic: true } };
  expected.argv = [expected.executable, '--enable-logging=file', `--log-file=${path.join(runDir, 'logs', 'chromium.log')}`,
    path.join(expected.sourceRoot, 'experiments/update-auth-policy-sqlite/electron-main.cjs'),
    '--phase', phase, '--run-dir', runDir, '--nonce', nonce];
  const receipt = { schemaVersion: 1, ...expected, argv: expected.argv, pid, status: 'PASS', nativeElectron: true,
    preflight: true, runtime: { type: 'browser', versions: { electron: '45.0.0' }, platform: 'win32', arch: 'x64' },
    sqliteVersion: '3.53.4', storeAssertions: native.STORE_ASSERTIONS,
    loadedSources: native.loadedNames(expected.sourceRoot), closed: true,
    checks: native.CASES[phase].map(item => {
      if (item.outcome !== 'rejected') return { ...item };
      const messages = { 'rollback-seq': 'AUTH: rollback sequence', 'reuse-seq': 'AUTH: sequence reused',
        'rollback-version': 'AUTH: rollback version', 'equal-version': 'AUTH: rollback version',
        'bad-signature': 'AUTH: signature', 'altered-payload': 'AUTH: signature', 'tls-no-ca': 'fetch failed',
        busy: 'database is locked', 'fixture-missing': 'ENOENT missing', 'fixture-zero': 'STORE: empty database',
        'fixture-truncated': 'database disk image is malformed', 'fixture-header': 'file is not a database',
        'fixture-extra-schema': 'STORE: complete schema/extra object', 'fixture-bad-stored-signature': 'AUTH: signature',
        'fixture-nonce-mismatch': 'STORE: meta cardinality/schemaVersion/nonce', 'fixture-directory-junction': 'STORE: link/junction rejected' };
      const error = { message: messages[item.case] };
      if (item.case === 'tls-no-ca') error.causeCode = 'DEPTH_ZERO_SELF_SIGNED_CERT';
      if (item.case === 'fixture-missing') error.code = 'ENOENT';
      if (['busy', 'fixture-truncated', 'fixture-header'].includes(item.case)) {
        error.code = 'ERR_SQLITE_ERROR'; error.errcode = { busy: 5, 'fixture-truncated': 11, 'fixture-header': 26 }[item.case];
      }
      return { ...item, error, ...(item.case === 'busy' ? { elapsedMs: 1 } : {}) };
    }) };
  const execution = { pid, exitCode: 0, signal: null, timedOut: false, spawnError: null };
  return { receipt, expected, execution };
}
test('UNIT: synthetic receipts require exact process/source/path/argv/runtime/case correspondence', () => {
  const { receipt, expected, execution } = unitRecord();
  driver.validateReceipt(receipt, execution, expected);
  const changes = [{ nonce: 'd'.repeat(64) }, { pid: 102 }, { phase: 'reopen' }, { sourceRoot: '/foreign' },
    { storeDirectory: '/foreign' }, { inventorySha256: 'd'.repeat(64) }, { executable: '/foreign.exe' },
    { executableSha256: 'd'.repeat(64) }, { controlPid: 98 }, { preflight: false }, { nativeElectron: false },
    { argv: [...receipt.argv, '--no-sandbox'] }, { checks: [] }, { checks: [...receipt.checks, receipt.checks[0]] },
    { loadedSources: [] }, { status: 'ERROR' }, { extra: 'forged' }, { closed: false }, { sqliteVersion: '3.51.2' },
    { runtime: { ...receipt.runtime, type: 'node' } }];
  for (const change of changes) assert.throws(() => driver.validateReceipt({ ...receipt, ...change }, execution, expected), JSON.stringify(change));
  for (const change of [{ pid: 102 }, { exitCode: 1 }, { signal: 'SIGTERM' }, { timedOut: true }, { spawnError: 'error' }]) {
    assert.throws(() => driver.validateReceipt(receipt, { ...execution, ...change }, expected));
  }
});
test('UNIT: complete matrix is exact; duplicate/replayed/missing case or PID cannot PASS', () => {
  const records = Object.keys(native.CASES).map((phase, i) => unitRecord(phase, 101 + i));
  const phases = records.map(record => ({ ...record, phase: record.expected.phase }));
  assert.equal(driver.validateMatrix(phases, [99, 100]), true);
  assert.throws(() => driver.validateMatrix(phases.slice(1), [99, 100]));
  assert.throws(() => driver.validateMatrix([...phases, phases[0]], [99, 100]));
  const replay = structuredClone(phases); replay[1].receipt.pid = replay[0].receipt.pid; replay[1].execution.pid = replay[0].execution.pid;
  assert.throws(() => driver.validateMatrix(replay, [99, 100]));
  const bad = structuredClone(phases); bad[1].receipt.preflight = false;
  assert.throws(() => driver.validateMatrix(bad, [99, 100]));
  assert.throws(() => driver.validateMatrix(phases, [0, 100]));
  const repeatedNonce = structuredClone(phases);
  repeatedNonce[1].expected.nonce = repeatedNonce[0].expected.nonce;
  repeatedNonce[1].receipt.nonce = repeatedNonce[0].receipt.nonce;
  assert.throws(() => driver.validateMatrix(repeatedNonce, [99, 100]));
});
test('UNIT: expected rejection classifiers never count generic/unexpected/preflight errors', () => {
  assert.equal(native.expectedFailure('busy', { code: 'ERR_SQLITE_ERROR', errcode: 5, message: 'database is locked' }), true);
  for (const label of Object.keys(native.FAILURES)) {
    assert.equal(native.expectedFailure(label, new Error('unexpected failure')), false);
    assert.equal(native.expectedFailure(label, { message: 'wrong preflight runtime', code: 'CONTROL_BLOCKED' }), false);
  }
});
test('UNIT: off-Windows CLI is honestly BLOCKED/78/nativeElectron false', () => {
  if (process.platform === 'win32') throw new Error('This local UNIT harness requires Linux; never skip');
  const child = spawnSync(process.execPath, [path.join(__dirname, 'driver.cjs'), '--electron', '/not-run.exe', '--out', '/not-created'], { encoding: 'utf8' });
  assert.equal(child.status, 78); assert.equal(child.signal, null);
  const result = JSON.parse(child.stdout); assert.equal(result.status, 'BLOCKED'); assert.equal(result.nativeElectron, false);
});
test('UNIT: holder READY is bound to actual spawn PID, source paths, runtime and nonce', () => {
  const { receipt, expected } = unitRecord('holder');
  const mark = { schemaVersion: 1, phase: 'holder', nonce: expected.nonce, runDir: expected.runDir,
    storeDirectory: expected.storeDirectory, sourceRoot: expected.sourceRoot, loadedSources: receipt.loadedSources,
    controlPid: expected.controlPid, nativeElectron: true, inventorySha256: expected.inventorySha256,
    executable: expected.executable, executableSha256: expected.executableSha256, runtime: receipt.runtime,
    sqliteVersion: receipt.sqliteVersion, pid: 101, status: 'READY', preflight: true };
  driver.validateReady(mark, expected, 101);
  for (const changes of [{ pid: 102 }, { nonce: 'f'.repeat(64) }, { sourceRoot: '/forged' }, { preflight: false },
    { nativeElectron: false }, { extra: true }, { status: 'PASS' }, { sqliteVersion: '3.50.0' }]) {
    assert.throws(() => driver.validateReady({ ...mark, ...changes }, expected, 101));
  }
});
test('UNIT: filesystem handshake observes atomic ready, rejects early exit and expires without fixed sleep', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-handshake-unit-'));
  try {
    const file = path.join(root, 'ready.json'); const ready = native.waitJSON(file, 1000);
    native.writeJSON(file, { UNIT: true }); assert.deepEqual(await ready, { UNIT: true });
    await assert.rejects(native.waitJSON(path.join(root, 'absent.json'), 1000, Promise.resolve()), /exited/);
    await assert.rejects(native.waitJSON(path.join(root, 'deadline.json'), 1), /deadline/);
    const directory = path.join(root, 'not-regular'); fs.mkdirSync(directory);
    await assert.rejects(native.waitJSON(directory, 1000), /regular/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('UNIT: negative fixture preparation proves intended disk condition; never positive Native evidence', () => temp(root => {
  const { DatabaseSync } = require('node:sqlite');
  fs.mkdirSync(path.join(root, 'fixtures')); const clean = path.join(root, 'clean'); fs.mkdirSync(clean);
  const db = new DatabaseSync(path.join(clean, 'policy.sqlite'));
  try {
    db.exec('PRAGMA journal_mode=WAL; CREATE TABLE highwater(payload TEXT, signature TEXT) STRICT;');
    db.prepare('INSERT INTO highwater VALUES (?, ?)').run('UNIT negative-fixture seed, NOT authenticated Policy', 'UNIT');
  } finally { db.close(); }
  for (const name of native.FIXTURES) {
    const fixture = driver.negativeFixture(root, name, clean, nonce);
    assert.equal(fixture.fixtureCreator.runtime, 'Node'); assert.equal(fixture.fixtureCreator.positiveEvidence, false);
    assert.equal(fixture.fixtureCreator.kind, name); assert.ok(Object.keys(fixture.fixtureCreator.condition).length > 0);
    fixture.verifyUnchanged();
    if (name === 'header' || name === 'truncated') {
      const file = path.join(fixture.directory, 'policy.sqlite');
      assert.throws(() => {
        const bad = new DatabaseSync(file);
        try { bad.exec('PRAGMA journal_mode=WAL'); } finally { bad.close(); }
      }, error => native.expectedFailure('fixture-' + name, error));
    }
  }
}));
