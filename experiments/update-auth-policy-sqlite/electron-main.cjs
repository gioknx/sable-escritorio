'use strict';
// Isolated Native collector. Node imports are inert and cannot certify Native PASS.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const STORE_ASSERTIONS = 'Approved hashed Store constructor asserts SQLite version, WAL/FULL/EXCLUSIVE/busy1000 readbacks and takes a real transaction lock; private connection values are not exported';
const accepted = (name, seq, version) => ({ case: name, outcome: 'accepted', seq, version });
const rejected = (name, state = false) => ({ case: name, outcome: 'rejected', ...(state ? { seq: 2, version: '2.2.3' } : {}) });
const INCOMING = ['rollback-seq', 'reuse-seq', 'rollback-version', 'equal-version', 'bad-signature', 'altered-payload'];
const FIXTURES = ['missing', 'zero', 'truncated', 'header', 'extra-schema', 'bad-stored-signature', 'nonce-mismatch', 'directory-junction'];
const CASES = Object.freeze({
  init: [accepted('initialise1', 1, '2.2.2'), accepted('advance2', 2, '2.2.3'), accepted('idempotent2', 2, '2.2.3'), { case: 'freeze-guard', outcome: 'accepted', frozen: true, forgedBlocked: true }],
  reopen: [accepted('reopen2', 2, '2.2.3'), ...INCOMING.map(name => rejected(name, true))],
  'tls-no-ca': [rejected('tls-no-ca')],
  holder: [{ case: 'exclusive-held', outcome: 'accepted' }, { case: 'released-closed', outcome: 'accepted' }],
  busy: [rejected('busy')],
  'after-lock': [accepted('after-lock2', 2, '2.2.3')],
  ...Object.fromEntries(FIXTURES.map(name => ['fixture-' + name, [rejected('fixture-' + name)]])),
});
const FAILURES = Object.freeze({
  'rollback-seq': { message: '^AUTH: rollback sequence$' },
  'reuse-seq': { message: '^AUTH: sequence reused$' },
  'rollback-version': { message: '^AUTH: rollback version$' },
  'equal-version': { message: '^AUTH: rollback version$' },
  'bad-signature': { message: '^AUTH: signature$' },
  'altered-payload': { message: '^AUTH: signature$' },
  'tls-no-ca': { message: '^fetch failed$', certificate: true },
  busy: { message: 'database is locked', code: 'ERR_SQLITE_ERROR', errcode: 5 },
  'fixture-missing': { message: 'ENOENT', code: 'ENOENT' },
  'fixture-zero': { message: '^STORE: empty database$' },
  'fixture-truncated': { message: 'malformed', code: 'ERR_SQLITE_ERROR', errcode: 11 },
  'fixture-header': { message: 'not a database', code: 'ERR_SQLITE_ERROR', errcode: 26 },
  'fixture-extra-schema': { message: '^STORE: complete schema/extra object$' },
  'fixture-bad-stored-signature': { message: '^AUTH: signature$' },
  'fixture-nonce-mismatch': { message: '^STORE: meta cardinality/schemaVersion/nonce$' },
  'fixture-directory-junction': { message: '^STORE: link/junction rejected$' },
});
function expectedFailure(name, error) {
  const rule = FAILURES[name];
  return !!rule && typeof error?.message === 'string' && new RegExp(rule.message).test(error.message) &&
    (!rule.code || error.code === rule.code) && (!rule.errcode || error.errcode === rule.errcode) &&
    (!rule.certificate || ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(error.causeCode || error.cause?.code));
}
function errorRecord(error) {
  return { message: String(error.message).slice(0, 1024), ...(error.code ? { code: error.code } : {}),
    ...(error.errcode !== undefined ? { errcode: error.errcode } : {}), ...(error.cause?.code ? { causeCode: error.cause.code } : {}) };
}
function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function fileDigest(file) {
  const hash = crypto.createHash('sha256'), buffer = Buffer.alloc(65536), fd = fs.openSync(file, 'r');
  try { let n; while ((n = fs.readSync(fd, buffer, 0, buffer.length, null))) hash.update(buffer.subarray(0, n)); }
  finally { fs.closeSync(fd); }
  return hash.digest('hex');
}
function physical(target) {
  assert.ok(path.isAbsolute(target), 'absolute path');
  const resolved = path.resolve(target); let current = path.parse(resolved).root;
  for (const part of resolved.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); const stat = fs.lstatSync(current);
    assert.ok(!stat.isSymbolicLink(), 'link/junction rejected');
    if (current !== resolved) assert.ok(stat.isDirectory(), 'directory ancestor');
    else if (stat.isFile()) assert.equal(stat.nlink, 1, 'hard link rejected');
  }
  assert.equal(fs.realpathSync.native(resolved), resolved, 'physical canonical path');
  return resolved;
}
function listFiles(root, prefix = '') {
  physical(root);
  return fs.readdirSync(root).sort().flatMap(name => {
    const absolute = path.join(root, name), relative = prefix ? prefix + '/' + name : name;
    physical(absolute); const stat = fs.lstatSync(absolute);
    if (stat.isDirectory()) return listFiles(absolute, relative);
    assert.ok(stat.isFile(), 'regular source');
    return [{ path: relative, size: stat.size, sha256: fileDigest(absolute) }];
  });
}
function verifyInventory(root, inventory) {
  assert.deepEqual(listFiles(root), inventory, 'source inventory/hash mismatch');
  return digest(JSON.stringify(inventory));
}
function loadedNames(root) {
  return ['experiments/update-auth-policy-sqlite/electron-main.cjs', 'experiments/update-auth-policy-sqlite/policy.cjs',
    'experiments/update-auth-policy-sqlite/store.cjs', 'experiments/update-auth-windows/node_modules/semver/index.js'].map(name => path.join(root, name));
}
function writeJSON(file, value, limit = 65536) {
  assert.ok(!fs.existsSync(file), 'refusing existing record');
  const text = JSON.stringify(value, null, 2) + '\n'; assert.ok(Buffer.byteLength(text) <= limit && limit <= 512 * 1024, 'bounded JSON');
  const temp = file + '.writing'; fs.writeFileSync(temp, text, { flag: 'wx', mode: 0o600 });
  fs.renameSync(temp, file); // Exclusive assay tree, no concurrent mutator/replacement.
}
function waitJSON(file, timeout = 15000, ended) {
  return new Promise((resolve, reject) => {
    let settled = false;
    function finish(error, value) { if (settled) return; settled = true; clearTimeout(timer); watcher.close(); error ? reject(error) : resolve(value); }
    function inspect() {
      try {
        if (!fs.existsSync(file)) return;
        physical(file); const stat = fs.statSync(file);
        assert.ok(stat.isFile() && stat.size <= 65536, 'bounded regular handshake');
        finish(null, JSON.parse(fs.readFileSync(file, 'utf8')));
      } catch (error) { finish(error); }
    }
    const watcher = fs.watch(path.dirname(file), inspect);
    const timer = setTimeout(() => finish(new Error('Handshake deadline')), timeout);
    if (ended) ended.then(() => { if (!fs.existsSync(file)) finish(new Error('Process exited before handshake')); }, finish);
    inspect();
  });
}
function parseProcessArgs(argv, entry = __filename) {
  const index = argv[1] === entry ? 1 : argv[3] === entry ? 3 : -1;
  assert.ok(index >= 0, 'entrypoint');
  const args = argv.slice(index + 1);
  assert.equal(args.length, 6, 'argument count');
  assert.equal(args[0], '--phase'); assert.ok(Object.hasOwn(CASES, args[1]), 'phase');
  assert.equal(args[2], '--run-dir'); assert.ok(path.isAbsolute(args[3]));
  assert.equal(args[4], '--nonce'); assert.match(args[5], /^[a-f0-9]{64}$/);
  if (index === 3) assert.deepEqual(argv.slice(1, 3), ['--enable-logging=file', `--log-file=${path.join(args[3], 'logs', 'chromium.log')}`]);
  assert.ok(argv.length <= 16 && Buffer.byteLength(JSON.stringify(argv)) <= 8192, 'bounded argv');
  return { phase: args[1], runDir: args[3], nonce: args[5] };
}
function assertRuntime(runtime) {
  assert.deepEqual(Object.keys(runtime).sort(), ['arch', 'platform', 'type', 'versions']);
  assert.deepEqual(Object.keys(runtime.versions), ['electron']);
  assert.equal(runtime.type, 'browser'); assert.equal(runtime.versions.electron, '45.0.0');
  assert.equal(runtime.platform, 'win32'); assert.equal(runtime.arch, 'x64');
}
function assertSQLiteVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version); assert.ok(match, 'SQLite version');
  const [major, minor, patch] = match.slice(1).map(Number);
  assert.ok(major > 3 || major === 3 && (minor > 51 || minor === 51 && patch >= 3), 'SQLite >=3.51.3');
}
async function rejectedCall(name, action) {
  try { await action(); } catch (error) {
    assert.ok(expectedFailure(name, error), `unexpected ${name}: ${error.message}`);
    return errorRecord(error);
  }
  throw new Error(`${name} returned metadata/accepted unexpectedly`);
}
async function runCase(config, Policy) {
  const { phase, storeDirectory: directory, storeNonce, publicKey, feedURL } = config;
  const options = { directory, nonce: storeNonce, publicKey, feedURL, channel: 'stable' }, app = { version: '2.2.1' };
  let policy; const checks = [];
  const state = (name, info) => {
    const manifest = policy.guard(info); return accepted(name, manifest.seq, manifest.version);
  };
  try {
    if (phase === 'init') {
      policy = await Policy.initialise(options, app);
      // Init emits no info. Close first, then decode its actual persisted envelope using Policy.
      policy.close();
      const { DatabaseSync } = require('node:sqlite');
      const reader = new DatabaseSync(path.join(directory, 'policy.sqlite'), { readOnly: true, allowExtension: false });
      try {
        const row = reader.prepare('SELECT payload, signature FROM highwater WHERE id=1').get();
        const initial = policy.decode(row);
        checks.push(accepted('initialise1', initial.seq, initial.version));
      } finally { reader.close(); }
      policy = new Policy(options, app);
      const info = await policy.latest(); checks.push(state('advance2', info));
      checks.push(state('idempotent2', await policy.latest()));
      const frozen = [info, info.files, info.files[0], policy.guard(info)].every(Object.isFrozen);
      assert.ok(frozen); assert.equal(Reflect.set(info, 'version', '9.0.0'), false);
      assert.throws(() => policy.guard({ ...info }), /metadata not current\/authenticated/);
      checks.push({ case: 'freeze-guard', outcome: 'accepted', frozen, forgedBlocked: true });
    } else if (phase === 'reopen') {
      policy = new Policy(options, app); checks.push(state('reopen2', await policy.latest()));
      for (const name of INCOMING) {
        const error = await rejectedCall(name, () => policy.latest());
        const observed = state(name, await policy.latest());
        checks.push({ ...observed, outcome: 'rejected', error });
      }
    } else if (phase === 'holder') {
      policy = new Policy(options, app);
      writeJSON(path.join(config.runDir, 'ready.json'), { ...config.readyRecord, pid: process.pid, status: 'READY', preflight: true });
      const release = await waitJSON(path.join(config.runDir, 'release.json'));
      assert.deepEqual(release, { nonce: config.nonce, pid: process.pid, action: 'close' });
      checks.push({ case: 'exclusive-held', outcome: 'accepted' });
      policy.close(); checks.push({ case: 'released-closed', outcome: 'accepted' });
    } else if (phase === 'after-lock') {
      policy = new Policy(options, app); checks.push(state('after-lock2', await policy.latest()));
    } else if (phase === 'tls-no-ca') {
      policy = new Policy(options, app);
      checks.push({ ...rejected(phase), error: await rejectedCall(phase, () => policy.latest()) });
    } else {
      const started = performance.now();
      const error = await rejectedCall(phase, () => { policy = new Policy(options, app); });
      const elapsedMs = performance.now() - started;
      if (phase === 'busy') assert.ok(elapsedMs < 5000, 'busy bound');
      checks.push({ ...rejected(phase), error, ...(phase === 'busy' ? { elapsedMs } : {}) });
    }
    assert.equal(checks.length, CASES[phase].length);
    for (let i = 0; i < checks.length; i++) {
      for (const [key, value] of Object.entries(CASES[phase][i])) assert.equal(checks[i][key], value, 'observed case ' + key);
    }
    if (policy) { policy.close(); policy.close(); }
    return { checks, closed: true };
  } finally { if (policy) policy.close(); }
}
async function main() {
  const args = parseProcessArgs(process.argv); physical(args.runDir);
  const configPath = path.join(args.runDir, 'config.json'); physical(configPath);
  const configStat = fs.statSync(configPath); assert.ok(configStat.isFile() && configStat.size <= 65536, 'bounded regular config');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(config.phase, args.phase); assert.equal(config.runDir, args.runDir); assert.equal(config.nonce, args.nonce);
  const runtime = { type: process.type || null, versions: { electron: process.versions.electron || null }, platform: process.platform, arch: process.arch };
  let app, exitCode = 1;
  const record = { schemaVersion: 1, phase: args.phase, nonce: args.nonce, runDir: args.runDir,
    storeDirectory: config.storeDirectory, sourceRoot: config.sourceRoot, inventorySha256: config.inventorySha256,
    executable: process.execPath, executableSha256: fileDigest(process.execPath), controlPid: config.controlPid,
    pid: process.pid, argv: [...process.argv], runtime, status: 'ERROR', nativeElectron: false, preflight: false,
    ...(config.fixtureCreator ? { fixtureCreator: config.fixtureCreator } : {}) };
  const checkpoint = stage => writeJSON(path.join(args.runDir, `checkpoint-${stage}.json`), { stage, phase: args.phase, nonce: args.nonce, pid: process.pid });
  try {
    checkpoint('js-entry'); assertRuntime(runtime);
    assert.equal(record.executable, config.executable); assert.equal(record.executableSha256, config.executableSha256);
    assert.equal(__filename, loadedNames(config.sourceRoot)[0]);
    assert.equal(verifyInventory(config.sourceRoot, config.inventory), config.inventorySha256);
    app = require('electron').app; assert.equal(app.isReady(), false);
    for (const [name, directory] of Object.entries({ home: 'home', appData: 'appdata', userData: 'profile', sessionData: 'cache', temp: 'temp', logs: 'logs' })) app.setPath(name, path.join(args.runDir, directory));
    app.disableHardwareAcceleration(); await app.whenReady(); checkpoint('app-ready');
    const { DatabaseSync } = require('node:sqlite'); const memory = new DatabaseSync(':memory:', { allowExtension: false });
    try { record.sqliteVersion = memory.prepare('SELECT sqlite_version() v').get().v; } finally { memory.close(); }
    assertSQLiteVersion(record.sqliteVersion); checkpoint('sqlite-ready');
    const { Policy } = require('./policy.cjs');
    const loaded = [__filename, require.resolve('./policy.cjs'), require.resolve('./store.cjs'), require.resolve('../update-auth-windows/node_modules/semver')];
    assert.deepEqual(loaded, loadedNames(config.sourceRoot));
    for (const filename of loaded.slice(1)) assert.equal(require.cache[filename]?.filename, filename, 'actual loaded CJS module');
    assert.equal(require('../update-auth-windows/node_modules/semver/package.json').version, '7.7.3');
    Object.assign(record, { nativeElectron: true, preflight: true, storeAssertions: STORE_ASSERTIONS, loadedSources: loaded });
    config.readyRecord = { schemaVersion: 1, phase: args.phase, nonce: args.nonce, runDir: args.runDir, storeDirectory: config.storeDirectory,
      sourceRoot: config.sourceRoot, loadedSources: loaded, controlPid: config.controlPid, nativeElectron: true,
      inventorySha256: config.inventorySha256, executable: record.executable, executableSha256: record.executableSha256, runtime, sqliteVersion: record.sqliteVersion };
    Object.assign(record, await runCase(config, Policy));
    assert.equal(verifyInventory(config.sourceRoot, config.inventory), config.inventorySha256);
    checkpoint('case-complete'); record.status = 'PASS'; exitCode = 0;
  } catch (error) { record.error = errorRecord(error); }
  try { writeJSON(path.join(args.runDir, 'receipt.json'), record); }
  finally { if (app) app.exit(exitCode); else process.exitCode = exitCode; }
}
function isEntrypoint(isMain, type) { return isMain || type === 'browser'; }
module.exports = { STORE_ASSERTIONS, INCOMING, FIXTURES, CASES, FAILURES, expectedFailure, digest, fileDigest,
  physical, listFiles, verifyInventory, loadedNames, writeJSON, waitJSON, parseProcessArgs, assertRuntime, assertSQLiteVersion, isEntrypoint };
if (isEntrypoint(require.main === module, process.type)) main().catch(error => { console.error(JSON.stringify({ status: 'ERROR', reason: error.message })); process.exitCode = 1; });
