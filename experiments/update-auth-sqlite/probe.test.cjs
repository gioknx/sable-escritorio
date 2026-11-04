'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const probe = require('./electron-main.cjs');
const driver = require('./driver.cjs');
const canary = 'a'.repeat(64);
const mainPath = path.join(__dirname, 'electron-main.cjs');

function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqlite-unit-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function databaseOptions(dir, phase = 'write') {
  return { phase, dbPath: path.join(dir, 'canary.sqlite'), canary };
}

test('UNIT: WAL/FULL/exclusive are read back; canary survives close/reopen read-only', t => {
  const dir = temporary(t);
  const options = databaseOptions(dir);
  const written = probe.exerciseDatabase(DatabaseSync, options);
  assert.deepEqual(written.pragmas, { journal_mode: 'wal', synchronous: 2, locking_mode: 'exclusive', busy_timeout: 1000 });
  assert.ok(written.compileOptions.length > 0);
  assert.equal(written.canary, canary);
  const before = fs.readFileSync(options.dbPath);
  const read = probe.exerciseDatabase(DatabaseSync, { ...options, phase: 'read' });
  assert.equal(read.canary, written.canary);
  assert.deepEqual(read.pragmas, written.pragmas);
  assert.deepEqual(fs.readFileSync(options.dbPath), before);
  assert.equal(Object.hasOwn(read, 'status'), false);
  assert.throws(() => probe.exerciseDatabase(DatabaseSync, options), /EEXIST/);
});

test('UNIT: second OS process reopens without recreation or insert', t => {
  const dir = temporary(t);
  const options = databaseOptions(dir);
  probe.exerciseDatabase(DatabaseSync, options);
  const script = 'const {DatabaseSync}=require("node:sqlite"); const result=require(process.argv[1]).exerciseDatabase(DatabaseSync,JSON.parse(process.argv[2])); console.log(JSON.stringify(result));';
  const child = spawnSync(process.execPath, ['-e', script, mainPath, JSON.stringify({ ...options, phase: 'read' })],
    { timeout: 5000, maxBuffer: 65536, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(child.stdout).canary, canary);
});

test('UNIT: missing/corrupt database and wrong canary fail without recreating state', t => {
  const dir = temporary(t);
  const options = databaseOptions(dir, 'read');
  assert.throws(() => probe.exerciseDatabase(DatabaseSync, options), /ENOENT/);
  assert.equal(fs.existsSync(options.dbPath), false);
  const corrupt = Buffer.from('not a sqlite database'.repeat(100));
  fs.writeFileSync(options.dbPath, corrupt);
  assert.throws(() => probe.exerciseDatabase(DatabaseSync, options));
  assert.deepEqual(fs.readFileSync(options.dbPath), corrupt);
  fs.unlinkSync(options.dbPath);
  probe.exerciseDatabase(DatabaseSync, { ...options, phase: 'write' });
  assert.throws(() => probe.exerciseDatabase(DatabaseSync, { ...options, canary: 'b'.repeat(64) }), /Canary mismatch/);
});

test('UNIT: read phase refuses symlink database', t => {
  const dir = temporary(t);
  const options = databaseOptions(dir);
  probe.exerciseDatabase(DatabaseSync, options);
  const link = path.join(dir, 'link.sqlite');
  try { fs.symlinkSync(options.dbPath, link); }
  catch (error) { if (error.code === 'EPERM') return t.skip('Symlink privilege unavailable'); throw error; }
  assert.throws(() => probe.exerciseDatabase(DatabaseSync, { ...options, dbPath: link, phase: 'read' }), /regular database/);
});

test('UNIT: pragma mismatch and SQLite before WAL-reset fix are rejected', () => {
  for (const old of ['3.51.2', '3.50.9', '3.9.99', '2.99.99', 'garbage']) {
    assert.throws(() => probe.assertSQLiteVersion(old), probe.Blocked);
  }
  for (const current of ['3.51.3', '3.52.0', '4.0.0']) probe.assertSQLiteVersion(current);
  const values = { journal_mode: 'delete', synchronous: 2, locking_mode: 'exclusive', busy_timeout: 1000 };
  const fake = { exec() {}, prepare(sql) { return { get: () => ({ value: values[sql.split(' ')[1]] }) }; } };
  assert.throws(() => probe.configure(fake), /pragma readback/);
});

test('UNIT: old SQLite records capabilities but cannot reach schema/commit', t => {
  const evidence = {};
  let closed = false;
  class OldSQLite {
    prepare(sql) {
      return sql === 'SELECT sqlite_version()' ? { get: () => ({ version: '3.51.2' }) } :
        { all: () => [{ compile_options: 'UNIT_ONLY' }] };
    }
    exec() { assert.fail('Old SQLite must not configure or create schema'); }
    close() { closed = true; }
  }
  assert.throws(() => probe.exerciseDatabase(OldSQLite, databaseOptions(temporary(t)), evidence), probe.Blocked);
  assert.deepEqual(evidence, { sqliteVersion: '3.51.2', compileOptions: ['UNIT_ONLY'] });
  assert.equal(closed, true);
});

test('UNIT: only documented app paths are set synchronously before ready', () => {
  const paths = {};
  let disabled = false;
  const fakeApp = {
    isReady: () => false,
    setPath(name, value) {
      assert.ok(['home', 'appData', 'userData', 'sessionData', 'temp', 'logs'].includes(name));
      paths[name] = value;
    },
    disableHardwareAcceleration() { disabled = true; },
  };
  probe.configureAppPaths(fakeApp, '/unit/run');
  assert.equal(paths.sessionData, path.join('/unit/run', 'cache'));
  assert.equal(paths.userData, path.join('/unit/run', 'profile'));
  assert.equal(Object.keys(paths).length, 6);
  assert.equal(disabled, true);
  assert.throws(() => probe.configureAppPaths({ ...fakeApp, isReady: () => true }, '/unit/run'), /before ready/);
});

test('UNIT: fake Node runtime, wrong Electron version/platform/architecture are blocked', t => {
  const valid = { type: 'browser', versions: { electron: '45.0.0' }, platform: 'win32', arch: 'x64' };
  probe.assertRuntime(valid);
  for (const changed of [{ type: undefined }, { type: 'renderer' }, { versions: {} },
    { versions: { electron: '45.0.1' } }, { platform: 'linux' }, { arch: 'arm64' }]) {
    assert.throws(() => probe.assertRuntime({ ...valid, ...changed }), probe.Blocked);
  }
  const dir = temporary(t);
  const receipt = path.join(dir, 'node.receipt.json');
  const dbPath = path.join(dir, 'never-created.sqlite');
  const child = spawnSync(process.execPath, [mainPath, '--phase', 'write', '--db', dbPath,
    '--canary', canary, '--receipt', receipt, '--run-dir', dir, '--nonce', 'unit'],
  { timeout: 5000, maxBuffer: 65536 });
  assert.equal(child.status, 78);
  const evidence = JSON.parse(fs.readFileSync(receipt, 'utf8'));
  assert.equal(evidence.status, 'BLOCKED');
  assert.equal(evidence.pid, child.pid);
  assert.equal(evidence.runtime.type, null);
  assert.equal(evidence.probeSha256, crypto.createHash('sha256').update(fs.readFileSync(mainPath)).digest('hex'));
  assert.equal(fs.existsSync(dbPath), false);
});

test('UNIT: strict CLI and physical root/executable containment', t => {
  const temp = temporary(t);
  const root = path.join(temp, 'benchmark');
  fs.mkdirSync(root);
  const executable = path.join(root, 'electron.exe');
  fs.writeFileSync(executable, 'UNIT fixture, not an executable');
  const options = { root, electron: executable, out: path.join(temp, 'evidence') };
  const args = ['--electron', executable, '--root', root, '--out', options.out];
  assert.deepEqual(driver.parseArgs(args), options);
  assert.deepEqual(driver.validatePaths(options, temp), options);
  for (const invalid of [[], args.slice(0, -1), [...args, '--root', root], [...args, '--unknown', 'x']]) {
    assert.throws(() => driver.parseArgs(invalid));
  }
  assert.throws(() => driver.validatePaths(options, undefined), /RUNNER_TEMP/);
  assert.throws(() => driver.validatePaths({ ...options, root: temp }, temp), /strictly under/);
  assert.throws(() => driver.validatePaths({ ...options, root: path.join(temp, 'missing') }, temp), /ENOENT/);
  assert.throws(() => driver.validatePaths({ ...options, root: executable }, temp), /physical directory/);
  const escapedExe = path.join(temp, 'outside.exe');
  fs.writeFileSync(escapedExe, 'fixture');
  assert.throws(() => driver.validatePaths({ ...options, electron: path.join(root, '..', 'outside.exe') }, temp), /inside root/);
  assert.throws(() => driver.validatePaths({ ...options, root: 'relative' }, temp), /absolute/);
});

test('UNIT: symlink root, executable and output ancestor rejected', t => {
  const temp = temporary(t);
  const root = path.join(temp, 'benchmark');
  fs.mkdirSync(root);
  const exe = path.join(root, 'electron.exe');
  fs.writeFileSync(exe, 'fixture');
  const link = path.join(temp, 'linked');
  try { fs.symlinkSync(root, link, 'junction'); }
  catch (error) { if (error.code === 'EPERM') return t.skip('Symlink privilege unavailable'); throw error; }
  const options = { root, electron: exe, out: path.join(temp, 'evidence') };
  assert.throws(() => driver.validatePaths({ ...options, root: link }, temp), /Symlink/);
  assert.throws(() => driver.validatePaths({ ...options, electron: path.join(link, 'electron.exe') }, temp), /Symlink/);
  assert.throws(() => driver.validatePaths({ ...options, out: path.join(link, 'new') }, temp), /Symlink/);
});

test('UNIT: environment isolated without secrets, Node options or run-as-node', () => {
  const env = driver.childEnvironment('/unit/run', {
    SystemRoot: 'C:\\Windows', PATH: 'runtime-path', NODE_OPTIONS: '--require=evil',
    electron_run_as_node: '1', CI_TOKEN: 'not-forwarded', APPDATA: 'old', HOME: 'old',
  });
  assert.equal(env.SystemRoot, 'C:\\Windows');
  assert.equal(env.PATH, 'runtime-path');
  assert.equal(env.APPDATA, path.join('/unit/run', 'appdata'));
  assert.equal(env.LOCALAPPDATA, path.join('/unit/run', 'localappdata'));
  assert.equal(env.USERPROFILE, env.HOME);
  assert.equal(env.TEMP, env.TMP);
  assert.equal(Object.keys(env).some(key => /TOKEN|NODE_OPTIONS|ELECTRON_RUN_AS_NODE/i.test(key)), false);
});

test('UNIT: receipt PID/hash/phase/nonce and process result must correspond', () => {
  const expected = { phase: 'read', nonce: 'nonce', dbPath: '/db', canary, probeSha256: 'hash' };
  const execution = { pid: 123, exitCode: 78, signal: null, timedOut: false, spawnError: null };
  const receipt = { schemaVersion: 1, pid: 123, status: 'BLOCKED', ...expected };
  driver.validateReceipt(receipt, execution, expected);
  for (const change of [{ pid: 124 }, { probeSha256: 'other' }, { phase: 'write' }, { nonce: 'other' }, { dbPath: '/other' }]) {
    assert.throws(() => driver.validateReceipt({ ...receipt, ...change }, execution, expected), /correspondence/);
  }
  for (const change of [{ timedOut: true }, { signal: 'SIGTERM' }, { spawnError: 'failure' }, { pid: null }, { exitCode: 0 }]) {
    assert.throws(() => driver.validateReceipt(receipt, { ...execution, ...change }, expected));
  }
  const success = { ...receipt, status: 'PASS', runtime: { type: null, versions: {}, platform: 'win32', arch: 'x64' } };
  assert.throws(() => driver.validateReceipt(success, { ...execution, exitCode: 0 }, expected), probe.Blocked);
});

test('UNIT: non-Windows driver emits BLOCKED, never native PASS', { skip: process.platform === 'win32' }, () => {
  const child = spawnSync(process.execPath, [path.join(__dirname, 'driver.cjs'), '--electron', '/unused/electron.exe',
    '--root', '/unused', '--out', '/unused/out'], { timeout: 5000, encoding: 'utf8', maxBuffer: 65536 });
  assert.equal(child.status, 78);
  const result = JSON.parse(child.stdout);
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.nativeElectron, false);
});
