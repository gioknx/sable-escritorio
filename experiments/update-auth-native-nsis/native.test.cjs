'use strict';
// UNIT ONLY: these synthetic PIDs are never Native evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const D = require('./driver.cjs');
const E = require('./electron-main.cjs');
const nonce = 'a'.repeat(64);
test('UNIT failure diagnostics preserve child error before cleanup and never authorize Native', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nsis-failure-diagnostics-'));
  try {
    for (const phase of ['negative', 'positive']) fs.mkdirSync(path.join(root, phase));
    fs.writeFileSync(path.join(root, 'negative', 'receipt.json'), JSON.stringify({ status: 'ERROR', error: { message: 'actual child failure' } }));
    fs.writeFileSync(path.join(root, 'positive', 'receipt.json'), '{broken');
    const execution = { phase: 'negative', pid: 123, exitCode: 1, stdout: 'x'.repeat(20000), stderr: 'actual stderr' };
    const snapshot = D.diagnosticSnapshot(root, [execution]);
    assert.equal(snapshot.classification, 'PUBLIC_NON_AUTHORIZING_DIAGNOSTIC');
    assert.equal(snapshot.nativeAuthorization, false);
    assert.equal(snapshot.receipts.negative.error.message, 'actual child failure');
    assert.ok(snapshot.receipts.positive.diagnosticReadError);
    assert.equal(snapshot.receipts.reopen, undefined);
    assert.equal(snapshot.executions[0].exitCode, 1);
    assert.equal(snapshot.executions[0].stdout.length, 4096);
    assert.equal(snapshot.executions[0].stderr, 'actual stderr');
    assert.equal(execution.stdout.length, 20000, 'diagnostics do not mutate acceptance input');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('UNIT installer ACK must precede awaiting updater process close', () => {
  const source = fs.readFileSync(require.resolve('./driver.cjs'), 'utf8');
  const ack = source.indexOf("fs.writeFileSync(ack, nonce, { flag: 'wx' })");
  const processClose = source.indexOf('const posExecution = await positive.job.done');
  assert.ok(ack >= 0 && processClose > ack, 'awaiting A close before ACK can deadlock installer waiting for ACK');
});
test('UNIT handshake diagnostics are bounded and non-authorizing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nsis-handshake-diagnostics-'));
  try {
    fs.mkdirSync(path.join(root, 'handshake'));
    fs.writeFileSync(path.join(root, 'handshake/ready.json'), JSON.stringify({ status: 'READY', pid: 123 }));
    fs.writeFileSync(path.join(root, 'handshake/installed.json'), 'x'.repeat(9000));
    const snapshot = D.diagnosticSnapshot(root, []);
    assert.equal(snapshot.nativeAuthorization, false);
    assert.equal(snapshot.handshake['ready.json'].status, 'READY');
    assert.match(snapshot.handshake['installed.json'].diagnosticReadError, /bounded JSON/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('UNIT full Windows install inventory fits legacy paths without dropping files', () => {
  const root = 'D:\\a\\_temp\\nsis-private-UNITxx';
  const files = [{ path: 'resources/app/experiments/update-auth-windows/node_modules/electron-updater/out/differentialDownloader/FileWithEmbeddedBlockMapDifferentialDownloader.js.map' }];
  const oldTarget = path.win32.join(root, 'installed-' + nonce);
  assert.ok(path.win32.join(oldTarget, files[0].path).length >= 260, 'measured Windows inventory reproduces old target overflow');
  const target = D.installationTarget(root, files);
  assert.equal(target, path.win32.join(root, 'installed'));
  assert.ok(path.win32.join(target, files[0].path).length < 260);
  assert.equal(files.length, 1, 'no inventory filtering');
  assert.throws(() => D.installationTarget('D:\\' + 'a'.repeat(230), files), /NSIS Windows path/);
});
test('UNIT extraction errors are scoped and dead installer cannot cause full handshake wait', () => {
  const nsi = fs.readFileSync(path.join(__dirname, 'fixture.nsi'), 'utf8');
  assert.match(nsi, /ack_received:\s+ClearErrors[^\n]*\n\s+SetOutPath/);
  assert.match(nsi, /"status":"EXTRACTION_FAILED"/);
  const source = fs.readFileSync(require.resolve('./driver.cjs'), 'utf8');
  assert.ok(source.includes('N.waitJSON(installedPath, 180000, observer.done)'));
});
test('UNIT inert imports', () => {
  const r = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(path.join(__dirname, 'driver.cjs'))});require(${JSON.stringify(path.join(__dirname, 'electron-main.cjs'))});require(${JSON.stringify(path.join(__dirname, 'update-auth.cjs'))})`]);
  assert.equal(r.status, 0); assert.equal(r.stdout.length, 0); assert.equal(r.stderr.length, 0);
});
test('UNIT strict packaged argv, no default-app entry or logging bypass', () => {
  const argv = ['/owned/electron.exe', '--phase', 'positive', '--run-dir', path.resolve('/owned/run'), '--nonce', nonce];
  assert.equal(E.parseArgs(argv).phase, 'positive');
  for (const bad of [[...argv, '--force'], [argv[0], 'script.cjs', ...argv.slice(1)], [...argv.slice(0, -1), 'bad'], argv.map(x => x === 'positive' ? 'unknown' : x)]) assert.throws(() => E.parseArgs(bad));
});
test('UNIT negative classifier accepts only real hash/size rejection', () => {
  for (const message of ['AUTH: installer SHA512', 'AUTH: download size', 'AUTH: response size limit']) assert.equal(E.expectedNegative({ message }), true);
  for (const message of ['fetch failed', 'ENOENT', 'AUTH: signature', 'wrong runtime', 'AUTH: file metadata']) assert.equal(E.expectedNegative({ message }), false);
});
test('UNIT clone delta is exclusively imports and SQLite Policy', () => D.verifyClone());
test('UNIT clone delta accepts Windows CRLF without changing raw inventory checks', () => {
  const baseline = fs.readFileSync(path.resolve(__dirname, '../update-auth-windows/update-auth.cjs'), 'utf8').replace(/\r\n/g, '\n');
  const expected = fs.readFileSync(path.join(__dirname, 'update-auth.cjs'), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(D.cloneSource(baseline.replace(/\n/g, '\r\n')), expected);
  assert.equal(D.cloneSource(baseline), expected);
  assert.doesNotMatch(D.cloneSource(baseline.replace(/\n/g, '\r\n')), /const semver = require\('semver'\)/);
});
test('UNIT genuine updater/provider inheritance; no fixture subclass', () => {
  const { AuthenticatedNsisUpdater: A } = require('./update-auth.cjs');
  const { NsisUpdater } = require('../update-auth-windows/node_modules/electron-updater');
  assert.equal(Object.getPrototypeOf(A.prototype), NsisUpdater.prototype);
  const source = fs.readFileSync(path.join(__dirname, 'electron-main.cjs'), 'utf8');
  assert.match(source, /new AuthenticatedNsisUpdater\(options\)/);
  assert.doesNotMatch(source, /new AuthenticatedNsisUpdater\(options,/);
  assert.match(source, /instanceof ElectronAppAdapter/);
  assert.match(source, /Policy\.initialise\(options, adapter\)/);
});
test('UNIT fixture package version is source controlled, B only changes version', () => {
  const pkg = require('./fixture-package.json');
  assert.equal(pkg.version, '2.2.1'); assert.equal(pkg.main, 'experiments/update-auth-native-nsis/electron-main.cjs');
  assert.equal(D.packageFor('2.2.3').version, '2.2.3'); assert.throws(() => D.packageFor('9.9.9'));
});
test('UNIT public allowlist cannot include private keys, payloads, exe or ZIP', () => {
  for (const name of ['result.json', 'source-inventory.json', 'ca.pem', 'negative.json']) assert.equal(D.publicName(name), true);
  for (const name of ['key.pem', 'fixture.exe', 'electron.zip', '../result.json', 'private.json', 'token.log']) assert.equal(D.publicName(name), false);
});
test('UNIT completion is not installer launch and reopen is driver-driven', () => {
  const a = { phase: 'positive', nonce, pid: 101, status: 'LAUNCH_REQUESTED', version: '2.2.1', nativeElectron: true, isPackaged: true };
  assert.throws(() => D.validateCompleted(a, { nonce, pid: 101 }, { nonce, pid: 102 }, 101));
  const installed = { status: 'INSTALLED', nonce, pid: 102 };
  const b = { phase: 'reopen', status: 'PASS', nonce, pid: 103, version: '2.2.3', nativeElectron: true, isPackaged: true, canary: nonce, driverDriven: true, checkedForUpdates: false };
  D.validateCompleted(b, installed, { nonce, pid: 102 }, 101);
  for (const delta of [{ pid: 101 }, { nonce: 'b'.repeat(64) }, { version: '2.2.1' }, { canary: 'wrong' }, { driverDriven: false }, { checkedForUpdates: true }]) assert.throws(() => D.validateCompleted({ ...b, ...delta }, installed, { nonce, pid: 102 }, 101));
});
test('UNIT physical/hash inventory rejects changed bytes and links', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nsis-unit-'));
  try {
    fs.writeFileSync(path.join(root, 'file'), 'UNIT'); const items = E.inventory(root);
    E.verifyInventory(root, items); fs.appendFileSync(path.join(root, 'file'), '!'); assert.throws(() => E.verifyInventory(root, items));
    fs.symlinkSync(path.join(root, 'file'), path.join(root, 'link')); assert.throws(() => E.inventory(root));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('UNIT OS chain correspondence rejects forged PID/path/nonce', () => {
  const ready = { status: 'READY', nonce, pid: 102 };
  const chain = [{ pid: 102, parent: 101, executable: '/owned/update.exe' }];
  D.validateChain(ready, chain, { nonce, pid: 101, installer: '/owned/update.exe', root: '/owned' });
  for (const delta of [{ nonce: 'bad' }, { pid: 101 }, { pid: 0 }]) assert.throws(() => D.validateChain({ ...ready, ...delta }, chain, { nonce, pid: 101, installer: '/owned/update.exe', root: '/owned' }));
  assert.throws(() => D.validateChain(ready, [{ ...chain[0], executable: '/foreign.exe' }], { nonce, pid: 101, installer: '/owned/update.exe', root: '/owned' }));
});
test('UNIT Linux cannot certify Native', () => {
  assert.notEqual(process.platform, 'win32');
  const r = spawnSync(process.execPath, [path.join(__dirname, 'driver.cjs'), '--electron', '/none.exe', '--out', '/absent', '--compiler', '/none']);
  assert.equal(r.status, 78); assert.equal(JSON.parse(r.stdout).nativeElectron, false);
});
test('UNIT actual package source copy preserves byte inventory and excludes npm launch links', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nsis-copy-unit-'));
  try {
    const runtime = path.join(root, 'UNIT-runtime-not-Electron'); fs.mkdirSync(runtime); fs.mkdirSync(path.join(runtime, 'resources'));
    fs.writeFileSync(path.join(runtime, 'electron.exe'), 'UNIT text, never executed');
    const copied = D.copyApplication(runtime, path.join(root, 'A'), '2.2.1', 'UNIT-cache');
    assert.notEqual(path.basename(copied.executable).toLowerCase(), 'electron.exe', 'Electron45 Windows identifies electron.exe as unpackaged');
    assert.equal(E.hash(copied.executable), E.hash(path.join(runtime, 'electron.exe')), 'packaging rename preserves pinned executable bytes');
    assert.equal(fs.existsSync(path.join(root, 'A/electron.exe')), false);
    const appRoot = path.join(root, 'A/resources/app'); E.verifyInventory(appRoot, copied.items);
    assert.equal(require(path.join(appRoot, 'package.json')).version, '2.2.1');
    assert.equal(fs.existsSync(path.join(appRoot, 'experiments/update-auth-windows/node_modules/.bin')), false);
    assert.equal(require(path.join(appRoot, 'experiments/update-auth-windows/node_modules/electron-updater/package.json')).version, '6.8.11');
    assert.equal(E.hash(path.join(root, 'A/resources/source-inventory.json')), copied.inventorySha256);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('UNIT real TLS/SQLite reopen and genuine wrapper reject tampered bytes then rehash full bytes; no installer launch', async () => {
  const https = require('node:https'), crypto = require('node:crypto');
  const { execFile } = require('node:child_process'), { promisify } = require('node:util');
  const execute = promisify(execFile), P = require('../update-auth-policy-sqlite/driver.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nsis-policy-unit-'));
  let server;
  try {
    const key = path.join(root, 'key.pem'), cert = path.join(root, 'ca.pem');
    await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=UNIT ONLY', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', key, '-out', cert]);
    const pair = crypto.generateKeyPairSync('ed25519'), bytes = Buffer.from('UNIT inert bytes NEVER executed'); let envelope, downloads = 0;
    server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
      if (req.url === '/manifest') return res.end(JSON.stringify(envelope));
      assert.equal(req.url, '/UNIT.exe'); const actual = Buffer.from(bytes); if (++downloads === 1) actual[0] ^= 1; res.end(actual);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = `https://127.0.0.1:${server.address().port}`, publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
    const payload = JSON.stringify({ appId: 'MINDTECH', channel: 'stable', platform: 'win32', arch: 'x64', version: '2.2.3', seq: 2,
      sha512: crypto.createHash('sha512').update(bytes).digest('base64'), size: bytes.length, url: origin + '/UNIT.exe' });
    envelope = { payload, signature: crypto.sign(null, Buffer.from(payload), pair.privateKey).toString('base64') };
    const script = `
      const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
      const { Policy } = require(${JSON.stringify(path.resolve(__dirname, '../update-auth-policy-sqlite/policy.cjs'))});
      const { AuthenticatedNsisUpdater } = require(${JSON.stringify(path.join(__dirname, 'update-auth.cjs'))});
      const E = require(${JSON.stringify(path.join(__dirname, 'electron-main.cjs'))});
      (async () => {
        const root = process.argv[1], publicKey = process.argv[2], feedURL = process.argv[3];
        fs.writeFileSync(path.join(root, 'UNIT.yml'), 'updaterCacheDirName: UNIT-only-cache\\n');
        // Explicit UNIT adapter, never consumed by the Native entrypoint.
        const app = { version: '2.2.1', name: 'UNIT-only', isPackaged: true, userDataPath: root, baseCachePath: root,
          appUpdateConfigPath: path.join(root, 'UNIT.yml'), whenReady: () => Promise.resolve() };
        const options = { directory: path.join(root, 'store'), nonce: '${nonce}', publicKey, feedURL, channel: 'stable' };
        const initial = await Policy.initialise(options, app); initial.close();
        const updater = new AuthenticatedNsisUpdater(options, app); updater.logger = null;
        try {
          const checked = await updater.checkForUpdates(); assert.equal(checked.updateInfo.version, '2.2.3');
          await assert.rejects(updater.downloadUpdate(), e => E.expectedNegative(e) && e.message === 'AUTH: installer SHA512');
          const files = await updater.downloadUpdate(); assert.equal(files.length, 1);
          assert.equal(fs.readFileSync(files[0], 'utf8'), 'UNIT inert bytes NEVER executed');
          assert.throws(() => updater.doInstall({ isSilent: true, isForceRunAfter: true }), /unsupported install options/);
          assert.throws(() => updater.doInstall({ isSilent: true, isAdminRightsRequired: true }), /unsupported install options/);
          updater.close(); updater.close();
          assert.throws(() => updater.doInstall({ isSilent: true, isForceRunAfter: false }), /policy closed/);
          console.log(JSON.stringify({ status: 'PASS', scope: 'UNIT Node only', nativeElectron: false, tamperedRejected: true, fullRehash: true, policyReopened: true }));
        } finally { updater.close(); }
      })().catch(e => { console.error(e); process.exitCode = 1; });`;
    const result = await execute(process.execPath, ['-e', script, root, publicKey, origin + '/manifest'], { env: P.environment(root, cert), timeout: 20000, maxBuffer: 65536 });
    assert.equal(JSON.parse(result.stdout).nativeElectron, false); assert.equal(downloads, 2);
  } finally {
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    fs.rmSync(root, { recursive: true, force: true });
  }
});
