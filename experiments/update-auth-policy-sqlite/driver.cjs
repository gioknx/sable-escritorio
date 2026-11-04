'use strict';
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const S = require('../update-auth-sqlite/driver.cjs');
const { controlPaths } = require('../update-auth-sqlite/startup-control.cjs');
const N = require('./electron-main.cjs');
const checkout = path.resolve(__dirname, '../..');
const execute = promisify(execFile);
const random = () => crypto.randomBytes(32).toString('hex');
const ARCHIVE_SHA256 = 'ae53887a23bb640369c93dbd38c408a2af5c0deb86f2fa76c6c244cb444b7f47';
async function pinnedRuntime(executable, runDir) {
  const archive = path.join(path.dirname(path.dirname(executable)), 'electron.zip');
  N.physical(archive); assert.equal(N.fileDigest(archive), ARCHIVE_SHA256, 'official archive pin');
  const script = '$ErrorActionPreference="Stop"; $z=[IO.Compression.ZipFile]::OpenRead($env:POLICY_ARCHIVE); try { $entries=@($z.Entries | Where-Object FullName -eq "electron.exe"); if($entries.Count -ne 1){throw "Unique electron.exe entry required"}; $s=$entries[0].Open(); try { $h=[Security.Cryptography.SHA256]::Create(); try { [BitConverter]::ToString($h.ComputeHash($s)).Replace("-", "").ToLowerInvariant() } finally { $h.Dispose() } } finally { $s.Dispose() } } finally { $z.Dispose() }';
  const { stdout } = await execute('pwsh', ['-NoProfile', '-NonInteractive', '-Command', script], {
    env: { ...S.childEnvironment(runDir), POLICY_ARCHIVE: archive }, timeout: 30000, maxBuffer: 4096,
  });
  const entrySha256 = stdout.trim(); assert.match(entrySha256, /^[a-f0-9]{64}$/);
  assert.equal(N.fileDigest(executable), entrySha256, 'executable must match the pinned ZIP entry');
  return { archive, archiveSha256: ARCHIVE_SHA256, executable, executableSha256: entrySha256 };
}
function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    assert.ok(['--electron', '--out'].includes(key) && !Object.hasOwn(result, key), 'CLI option');
    assert.ok(typeof argv[i + 1] === 'string' && argv[i + 1] && !argv[i + 1].startsWith('--'), 'CLI value');
    result[key] = argv[i + 1];
  }
  assert.equal(Object.keys(result).length, 2, 'required --electron and --out');
  return { electron: result['--electron'], out: result['--out'] };
}
function readJSON(file) {
  S.physicalPath(file); N.physical(file); const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.size <= 65536, 'bounded regular JSON');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function environment(runDir, certificate, source = process.env, ownRoot = runDir) {
  N.physical(ownRoot); assert.ok(runDir === ownRoot || S.inside(ownRoot, runDir), 'owned run directory');
  const env = S.childEnvironment(runDir, source);
  if (certificate) {
    N.physical(certificate); assert.ok(S.inside(ownRoot, certificate), 'own public CA path');
    assert.ok(fs.statSync(certificate).isFile()); env.NODE_EXTRA_CA_CERTS = certificate;
  }
  return env;
}
function profiles(runDir) {
  fs.mkdirSync(runDir);
  for (const name of ['appdata', 'localappdata', 'home', 'profile', 'cache', 'temp', 'logs']) fs.mkdirSync(path.join(runDir, name));
  N.physical(runDir);
}
function copySources(root) {
  fs.mkdirSync(root); N.physical(root);
  const names = ['experiments/update-auth-policy-sqlite/policy.cjs', 'experiments/update-auth-policy-sqlite/store.cjs',
    'experiments/update-auth-policy-sqlite/electron-main.cjs', 'experiments/update-auth-sqlite/startup-control.cjs'];
  const semverRoot = path.join(checkout, 'experiments/update-auth-windows/node_modules/semver');
  assert.equal(require(path.join(semverRoot, 'package.json')).version, '7.7.3');
  for (const item of N.listFiles(semverRoot)) names.push('experiments/update-auth-windows/node_modules/semver/' + item.path);
  const originals = [];
  for (const name of names.sort()) {
    const source = path.join(checkout, name), destination = path.join(root, name);
    N.physical(source); const bytes = fs.readFileSync(source);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, bytes, { flag: 'wx', mode: 0o600 });
    originals.push({ path: name, size: bytes.length, sha256: N.digest(bytes) });
  }
  const inventory = N.listFiles(root), inventorySha256 = N.verifyInventory(root, inventory);
  assert.deepEqual(inventory, originals, 'copies preserve exact checkout bytes, including LF/CRLF');
  return { root, inventory, inventorySha256, originals };
}
function unchanged(copy) {
  N.verifyInventory(copy.root, copy.inventory);
  for (const item of copy.originals) assert.equal(N.fileDigest(path.join(checkout, item.path)), item.sha256, 'original source changed');
}
function argvFor(entry, expected) {
  return ['--enable-logging=file', `--log-file=${path.join(expected.runDir, 'logs', 'chromium.log')}`, entry,
    '--phase', expected.phase, '--run-dir', expected.runDir, '--nonce', expected.nonce];
}
function validateReceipt(receipt, execution, expected) {
  assert.ok(execution.pid > 0 && Number.isInteger(execution.pid));
  assert.equal(execution.exitCode, 0); assert.equal(execution.signal, null); assert.equal(execution.timedOut, false); assert.equal(execution.spawnError, null);
  const keys = ['schemaVersion', 'phase', 'nonce', 'runDir', 'storeDirectory', 'sourceRoot', 'inventorySha256', 'executable',
    'executableSha256', 'controlPid', 'pid', 'argv', 'runtime', 'status', 'nativeElectron', 'preflight', 'sqliteVersion', 'storeAssertions', 'loadedSources', 'checks', 'closed', 'fixtureCreator'];
  assert.ok(Object.keys(receipt).every(key => keys.includes(key)), 'unknown receipt field');
  assert.equal(receipt.schemaVersion, 1); assert.equal(receipt.status, 'PASS'); assert.equal(receipt.nativeElectron, true); assert.equal(receipt.preflight, true); assert.equal(receipt.closed, true);
  assert.equal(receipt.pid, execution.pid);
  assert.ok(Number.isInteger(receipt.controlPid) && receipt.controlPid > 0 && receipt.controlPid !== receipt.pid, 'real distinct control PID');
  assert.deepEqual(expected.argv, [expected.executable, ...argvFor(N.loadedNames(expected.sourceRoot)[0], expected)], 'trusted canonical launch argv');
  for (const name of ['phase', 'nonce', 'runDir', 'storeDirectory', 'sourceRoot', 'inventorySha256', 'executable', 'executableSha256', 'controlPid']) assert.equal(receipt[name], expected[name], name);
  assert.match(receipt.nonce, /^[a-f0-9]{64}$/); assert.match(receipt.inventorySha256, /^[a-f0-9]{64}$/); assert.match(receipt.executableSha256, /^[a-f0-9]{64}$/);
  const consumed = [expected.argv[0], ...expected.argv.slice(3)];
  assert.ok(JSON.stringify(receipt.argv) === JSON.stringify(expected.argv) || JSON.stringify(receipt.argv) === JSON.stringify(consumed), 'exact argv correspondence');
  N.assertRuntime(receipt.runtime); N.assertSQLiteVersion(receipt.sqliteVersion);
  assert.equal(receipt.storeAssertions, N.STORE_ASSERTIONS); assert.deepEqual(receipt.loadedSources, N.loadedNames(expected.sourceRoot));
  assert.deepEqual(receipt.fixtureCreator, expected.fixtureCreator);
  if (expected.phase.startsWith('fixture-')) {
    assert.equal(receipt.fixtureCreator?.runtime, 'Node'); assert.equal(receipt.fixtureCreator.positiveEvidence, false);
    assert.equal(receipt.fixtureCreator.kind, expected.phase.slice(8)); assert.ok(Object.keys(receipt.fixtureCreator.condition).length > 0);
  } else assert.equal(receipt.fixtureCreator, undefined);
  const specifications = N.CASES[expected.phase]; assert.ok(specifications);
  assert.equal(receipt.checks.length, specifications.length, 'exact case count');
  for (let i = 0; i < specifications.length; i++) {
    const check = receipt.checks[i], spec = specifications[i];
    assert.ok(Object.keys(check).every(key => Object.hasOwn(spec, key) || ['error', 'elapsedMs'].includes(key)), 'unknown check field');
    for (const [key, value] of Object.entries(spec)) assert.equal(check[key], value, 'case ' + key);
    if (spec.outcome === 'rejected') assert.ok(N.expectedFailure(spec.case, check.error), 'specific expected rejection');
    else assert.equal(check.error, undefined);
    if (spec.case === 'busy') assert.ok(Number.isFinite(check.elapsedMs) && check.elapsedMs >= 0 && check.elapsedMs < 5000, 'bounded busy');
  }
}
function validateMatrix(phases, controlPids) {
  assert.equal(controlPids.length, 2); assert.equal(new Set(controlPids).size, 2);
  assert.ok(controlPids.every(pid => Number.isInteger(pid) && pid > 0), 'valid control PIDs');
  const names = Object.keys(N.CASES);
  assert.deepEqual(phases.map(item => item.phase), names, 'complete exact ordered matrix');
  const seen = new Set(controlPids), nonces = new Set(), runDirs = new Set();
  for (const item of phases) {
    assert.ok(!nonces.has(item.expected.nonce) && !runDirs.has(item.expected.runDir), 'no nonce/run directory replay');
    nonces.add(item.expected.nonce); runDirs.add(item.expected.runDir);
    for (const key of ['sourceRoot', 'inventorySha256', 'executable', 'executableSha256']) assert.equal(item.expected[key], phases[0].expected[key], 'shared pinned source/runtime');
    validateReceipt(item.receipt, item.execution, item.expected);
    assert.equal(item.expected.controlPid, controlPids[item.phase === 'tls-no-ca' ? 1 : 0]);
    assert.ok(!seen.has(item.execution.pid), 'distinct actual PIDs, no replay'); seen.add(item.execution.pid);
  }
  return true;
}
function validateReady(mark, expected, actualPid) {
  const shape = { schemaVersion: 1, phase: 'holder', nonce: expected.nonce, runDir: expected.runDir, storeDirectory: expected.storeDirectory,
    sourceRoot: expected.sourceRoot, loadedSources: N.loadedNames(expected.sourceRoot), controlPid: expected.controlPid, nativeElectron: true,
    inventorySha256: expected.inventorySha256, executable: expected.executable, executableSha256: expected.executableSha256,
    runtime: mark.runtime, sqliteVersion: mark.sqliteVersion, pid: actualPid, status: 'READY', preflight: true };
  assert.deepEqual(mark, shape); N.assertRuntime(mark.runtime); N.assertSQLiteVersion(mark.sqliteVersion);
  assert.ok(Number.isInteger(actualPid) && actualPid > 0);
}
function trimLog(file) {
  if (!fs.existsSync(file)) return;
  N.physical(file); const stat = fs.statSync(file); assert.ok(stat.isFile());
  if (stat.size > 65536) {
    const fd = fs.openSync(file, 'r'), buffer = Buffer.alloc(65536);
    try { fs.readSync(fd, buffer, 0, buffer.length, stat.size - buffer.length); } finally { fs.closeSync(fd); }
    fs.writeFileSync(file, buffer); // Diagnostics only, after the process has closed.
  }
}
// Only the holder needs a live PID. Same allowlisted env/flags as S.runChild;
// asynchronous streams, deadline, kill/finally and bounded logs remain explicit.
function startHolder(executable, argv, options, prefix) {
  const child = spawn(executable, argv, { ...options, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = Buffer.alloc(0), err = Buffer.alloc(0), timedOut = false, spawnError = null;
  child.stdout.on('data', bytes => { out = Buffer.concat([out, bytes]).subarray(0, 65536); });
  child.stderr.on('data', bytes => { err = Buffer.concat([err, bytes]).subarray(0, 65536); });
  child.on('error', error => { spawnError = error.message; });
  const done = new Promise(resolve => {
    let settled = false, deadline;
    const finish = (exitCode, signal) => {
      if (settled) return; settled = true; clearTimeout(timer); clearTimeout(deadline);
      try {
        fs.writeFileSync(prefix + '.stdout.log', out, { flag: 'wx' }); fs.writeFileSync(prefix + '.stderr.log', err, { flag: 'wx' });
      } catch (error) { spawnError ||= 'diagnostic write: ' + error.message; }
      resolve({ pid: child.pid || null, exitCode, signal, timedOut, spawnError });
    };
    const timer = setTimeout(() => {
      timedOut = true; child.kill(); deadline = setTimeout(() => finish(null, 'timeout'), 2000);
    }, 20000);
    child.once('close', finish);
  });
  return { child, done };
}
function negativeFixture(out, name, cleanStore, storeNonce) {
  const fixtureRoot = path.join(out, 'fixtures', name + '-' + random()); fs.mkdirSync(fixtureRoot);
  let directory = fixtureRoot, file = path.join(directory, 'policy.sqlite');
  const original = path.join(cleanStore, 'policy.sqlite');
  assert.ok(fs.statSync(original).size > 64);
  for (const suffix of ['-wal', '-shm']) assert.ok(!fs.existsSync(original + suffix), 'clean closed DB only');
  if (name !== 'missing') fs.copyFileSync(original, file, fs.constants.COPYFILE_EXCL);
  const condition = {};
  if (name === 'missing') { assert.ok(!fs.existsSync(file)); condition.absent = true; }
  if (name === 'zero' || name === 'truncated') {
    const size = name === 'zero' ? 0 : 64; fs.truncateSync(file, size); assert.equal(fs.statSync(file).size, size); condition.size = size;
  }
  if (name === 'header') {
    const data = fs.readFileSync(file); data.fill(0x58, 0, 16); fs.writeFileSync(file, data);
    assert.equal(fs.readFileSync(file).subarray(0, 16).toString(), 'XXXXXXXXXXXXXXXX'); condition.header = 'XXXXXXXXXXXXXXXX';
  }
  if (['extra-schema', 'bad-stored-signature'].includes(name)) {
    const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(file, { allowExtension: false });
    try {
      if (name === 'extra-schema') { db.exec('CREATE TABLE extra (value TEXT) STRICT'); assert.equal(db.prepare("SELECT count(*) n FROM sqlite_schema WHERE name='extra'").get().n, 1); condition.extraTable = true; }
      else { const signature = Buffer.alloc(64).toString('base64'); db.prepare('UPDATE highwater SET signature=?').run(signature); assert.equal(db.prepare('SELECT signature FROM highwater').get().signature, signature); condition.signature = signature; }
    } finally { db.close(); }
  }
  if (name === 'directory-junction') {
    directory = fixtureRoot + '-junction'; fs.symlinkSync(fixtureRoot, directory, 'junction'); assert.ok(fs.lstatSync(directory).isSymbolicLink()); condition.realLink = true;
  }
  let expectedNonce = storeNonce;
  if (name === 'nonce-mismatch') { expectedNonce = random(); assert.notEqual(expectedNonce, storeNonce); condition.expectedNonceDiffers = true; }
  const before = fs.existsSync(file) ? N.fileDigest(file) : null;
  return { directory, expectedNonce, fixtureCreator: { runtime: 'Node', positiveEvidence: false, kind: name, condition },
    verifyUnchanged() { assert.equal(fs.existsSync(file) ? N.fileDigest(file) : null, before, 'negative fixture must not reset/repair'); } };
}
async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    console.log(JSON.stringify({ status: 'BLOCKED', nativeElectron: false, reason: 'Requires Windows x64 host; UNIT is not Native' })); return 78;
  }
  const temp = N.physical(process.env.RUNNER_TEMP), electron = N.physical(path.resolve(options.electron));
  const out = path.resolve(options.out);
  assert.ok(S.inside(temp, electron) && fs.statSync(electron).isFile() && path.extname(electron).toLowerCase() === '.exe');
  assert.ok(S.inside(temp, out) && !S.inside(checkout, out) && out !== checkout && !S.inside(out, electron), 'exclusive public out under RUNNER_TEMP, outside checkout/runtime');
  N.physical(path.dirname(out)); fs.mkdirSync(out); N.physical(out);
  const report = { schemaVersion: 1, classification: 'PUBLIC: public keys/certificates, signed fixtures, source copies/hashes, runtime paths, PIDs and bounded diagnostics; NO private keys/tokens',
    status: 'ERROR', nativeElectron: false, scope: 'Policy+SQLite only; not updater/NSIS/app/activation/production/durability', controls: [], phases: [] };
  let privateRoot, server, holder; const diagnosticFiles = [];
  try {
    privateRoot = fs.mkdtempSync(path.join(temp, 'policy-private-')); N.physical(privateRoot);
    const runtimePin = await pinnedRuntime(electron, privateRoot); report.runtimePin = runtimePin;
    const keyPath = path.join(privateRoot, 'key.pem'), privateCert = path.join(privateRoot, 'cert.pem'), cert = path.join(out, 'ca.pem');
    await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=UNIT AND NATIVE ephemeral localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', keyPath, '-out', privateCert], { env: S.childEnvironment(privateRoot), timeout: 30000, maxBuffer: 65536 });
    fs.copyFileSync(privateCert, cert, fs.constants.COPYFILE_EXCL);
    const pair = crypto.generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
    const plans = new Map();
    server = https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(cert) }, (req, res) => {
      const plan = plans.get(req.url); if (!plan) { res.writeHead(404); res.end(); return; }
      res.end(JSON.stringify(plan.items[Math.min(plan.index++, plan.items.length - 1)]));
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const origin = `https://127.0.0.1:${server.address().port}`;
    const signed = (changes = {}) => {
      const payload = JSON.stringify({ appId: 'MINDTECH', channel: 'stable', platform: 'win32', arch: 'x64', version: '2.2.3', seq: 2,
        sha512: crypto.createHash('sha512').update('INERT SIGNED METADATA ONLY').digest('base64'), size: 25, url: origin + '/inert-not-downloaded.exe', ...changes });
      return { payload, signature: crypto.sign(null, Buffer.from(payload), pair.privateKey).toString('base64') };
    };
    const good = signed(), first = signed({ seq: 1, version: '2.2.2' });
    const incoming = [first, signed({ version: '2.2.4' }), signed({ seq: 3, version: '2.2.2' }), signed({ seq: 3 }),
      { ...good, signature: Buffer.alloc(64).toString('base64') }, { ...good, payload: good.payload.replace('2.2.3', '2.2.4') }];
    const copy = copySources(path.join(out, 'sources'));
    N.writeJSON(path.join(out, 'source-inventory.json'), { inventory: copy.inventory, inventorySha256: copy.inventorySha256, bytePolicy: 'exact copied bytes, no LF/CRLF normalization', originals: copy.originals });
    const { stdout: head } = await execute('git', ['rev-parse', 'HEAD'], { cwd: checkout, env: S.childEnvironment(privateRoot), timeout: 5000 });
    N.writeJSON(path.join(out, 'original-head.json'), { head: head.trim(), driverSha256: N.fileDigest(__filename) });
    const executableSha256 = runtimePin.executableSha256, storeNonce = random(), storeDirectory = path.join(out, 'store-' + storeNonce);
    const controlRoot = path.join(out, 'controls'); fs.mkdirSync(controlRoot);
    for (const name of ['with-ca', 'without-ca']) {
      const runDir = path.join(controlRoot, name + '-' + random()); profiles(runDir); fs.mkdirSync(controlPaths(runDir).directory);
      diagnosticFiles.push(controlPaths(runDir).nativeLog);
      const entry = path.join(runDir, 'startup-control.cjs');
      fs.copyFileSync(path.join(copy.root, 'experiments/update-auth-sqlite/startup-control.cjs'), entry, fs.constants.COPYFILE_EXCL);
      const expected = { runDir, nonce: random(), controlSha256: N.fileDigest(entry) };
      const args = S.buildControlArgv(entry, expected); expected.argv = [electron, ...args];
      const execution = await S.runChild(electron, args, { cwd: runDir, env: environment(runDir, name === 'with-ca' ? cert : null, process.env, out) }, path.join(runDir, 'logs', 'control'));
      const mark = S.readStartupControl(controlPaths(runDir).checkpoint, execution, expected);
      report.controls.push({ name, expected, execution, mark }); trimLog(controlPaths(runDir).nativeLog);
      S.requireReadyControl(mark, execution); assert.equal(N.fileDigest(entry), expected.controlSha256); unchanged(copy);
    }
    const phaseRoot = path.join(out, 'phases'); fs.mkdirSync(phaseRoot); fs.mkdirSync(path.join(out, 'fixtures'));
    const prepare = (phase, fixture) => {
      unchanged(copy); const nonce = random(), runDir = path.join(phaseRoot, phase + '-' + nonce); profiles(runDir);
      diagnosticFiles.push(path.join(runDir, 'logs', 'chromium.log'));
      const route = '/manifest/' + nonce;
      plans.set(route, { items: phase === 'init' ? [first, good, good] : phase === 'reopen' ? [good, ...incoming.flatMap(item => [item, good])] : [good], index: 0 });
      const expected = { phase, nonce, runDir, storeDirectory: fixture?.directory || storeDirectory, sourceRoot: copy.root,
        inventorySha256: copy.inventorySha256, executable: electron, executableSha256,
        controlPid: report.controls[phase === 'tls-no-ca' ? 1 : 0].execution.pid,
        ...(fixture ? { fixtureCreator: fixture.fixtureCreator } : {}) };
      const args = argvFor(N.loadedNames(copy.root)[0], expected); expected.argv = [electron, ...args];
      N.writeJSON(path.join(runDir, 'config.json'), { ...expected, inventory: copy.inventory, storeNonce: fixture?.expectedNonce || storeNonce, publicKey, feedURL: origin + route });
      const item = { phase, expected }; report.phases.push(item);
      return { item, args, options: { cwd: runDir, env: environment(runDir, phase === 'tls-no-ca' ? null : cert, process.env, out) }, prefix: path.join(runDir, 'logs', 'process') };
    };
    const finish = (prepared, execution) => {
      prepared.item.execution = execution;
      trimLog(path.join(prepared.item.expected.runDir, 'logs', 'chromium.log'));
      prepared.item.receipt = readJSON(path.join(prepared.item.expected.runDir, 'receipt.json'));
      validateReceipt(prepared.item.receipt, execution, prepared.item.expected); unchanged(copy);
    };
    for (const phase of ['init', 'reopen', 'tls-no-ca']) {
      const prepared = prepare(phase); finish(prepared, await S.runChild(electron, prepared.args, prepared.options, prepared.prefix));
    }
    const held = prepare('holder'); holder = startHolder(electron, held.args, held.options, held.prefix);
    try {
      const ready = await N.waitJSON(path.join(held.item.expected.runDir, 'ready.json'), 10000, holder.done);
      validateReady(ready, held.item.expected, holder.child.pid);
      const blocked = prepare('busy'); finish(blocked, await S.runChild(electron, blocked.args, blocked.options, blocked.prefix));
      assert.notEqual(blocked.item.execution.pid, holder.child.pid);
      N.writeJSON(path.join(held.item.expected.runDir, 'release.json'), { nonce: held.item.expected.nonce, pid: holder.child.pid, action: 'close' });
      const execution = await holder.done; assert.equal(execution.pid, ready.pid); finish(held, execution); holder = undefined;
    } finally { if (holder) { holder.child.kill(); await holder.done; holder = undefined; } }
    const after = prepare('after-lock'); finish(after, await S.runChild(electron, after.args, after.options, after.prefix));
    for (const name of N.FIXTURES) {
      const fixture = negativeFixture(out, name, storeDirectory, storeNonce), prepared = prepare('fixture-' + name, fixture);
      finish(prepared, await S.runChild(electron, prepared.args, prepared.options, prepared.prefix)); fixture.verifyUnchanged();
    }
    validateMatrix(report.phases, report.controls.map(item => item.execution.pid)); unchanged(copy);
    assert.equal(N.fileDigest(electron), executableSha256); report.status = 'PASS'; report.nativeElectron = true;
  } catch (error) { report.status = 'ERROR'; report.reason = String(error.message).slice(0, 1024); }
  finally {
    const cleanupError = error => {
      report.cleanupErrors ||= []; report.cleanupErrors.push(String(error.message).slice(0, 512));
      report.status = 'ERROR'; report.nativeElectron = false;
    };
    try { if (holder) { holder.child.kill(); await holder.done; } } catch (error) { cleanupError(error); }
    try { if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } } catch (error) { cleanupError(error); }
    try { if (privateRoot) fs.rmSync(privateRoot, { recursive: true, force: true }); } catch (error) { cleanupError(error); }
    for (const file of diagnosticFiles) { try { trimLog(file); } catch (error) { cleanupError(error); } }
  }
  N.writeJSON(path.join(out, 'result.json'), report, 512 * 1024);
  console.log(JSON.stringify({ status: report.status, nativeElectron: report.nativeElectron, evidence: path.join(out, 'result.json') }));
  return report.status === 'PASS' ? 0 : 1;
}
module.exports = { ARCHIVE_SHA256, parseArgs, readJSON, environment, copySources, validateReceipt, validateMatrix, validateReady, negativeFixture, main };
if (require.main === module) main().then(code => { process.exitCode = code; }).catch(error => {
  console.error(JSON.stringify({ status: 'ERROR', nativeElectron: false, reason: String(error.message).slice(0, 1024) })); process.exitCode = 1;
});
