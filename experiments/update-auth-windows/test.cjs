'use strict';
// UNIT ONLY: inert .exe bytes; launchInstaller substitutes ChildProcess, never executes NSIS.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { EventEmitter } = require('node:events');
const { generateKeyPairSync, sign, createHash } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { AuthenticatedNsisUpdater } = require('./update-auth.cjs');
const assert = require('node:assert/strict');
const test = require('node:test');
const sha = bytes => createHash('sha512').update(bytes).digest('base64');
const good = Buffer.from('UNIT ONLY: MINDTECH inert installer fixture.\n');
const bad = Buffer.alloc(good.length, 88);
function app(root) {
  fs.mkdirSync(root, { recursive: true });
  const config = path.join(root, 'app-update.yml');
  fs.writeFileSync(config, 'updaterCacheDirName: mindtech-unit\n');
  const handlers = [];
  return {
    version: '2.2.1', name: 'MINDTECH', isPackaged: true,
    appUpdateConfigPath: config, userDataPath: root, baseCachePath: path.join(root, 'cache'),
    whenReady: async () => {}, relaunch() {}, quitCount: 0,
    onQuit(handler) { handlers.push(handler); },
    quit() { this.quitCount++; this.fireQuit(0); },
    fireQuit(code) { handlers.forEach(handler => handler(code)); },
  };
}
class FixtureUpdater extends AuthenticatedNsisUpdater {
  spawns = [];
  spawnError;
  launchInstaller(file, args) {
    this.spawns.push({ file: path.basename(file), hash: sha(fs.readFileSync(file)), args });
    const child = new EventEmitter();
    child.pid = this.spawnError ? undefined : 12345; // UNIT adapter, NOT a native process.
    child.unref = () => {};
    if (this.spawnError) {
      const code = this.spawnError;
      process.nextTick(() => child.emit('error', Object.assign(new Error('UNIT spawn failure'), { code })));
    }
    return child;
  }
  probePackage(info) {
    return this.executeDownload({
      fileInfo: {
        url: new URL(info.files[0].url),
        info: info.files[0],
        packageInfo: { path: 'UNIT-package.7z', sha512: info.files[0].sha512 },
      },
      downloadUpdateOptions: { updateInfoAndProvider: { info } },
    });
  }
}
function setup(root, options, autoQuit = false) {
  const adapter = app(root), updater = new FixtureUpdater(options, adapter);
  updater.logger = null; updater.autoInstallOnAppQuit = autoQuit;
  return { adapter, updater };
}
async function worker() {
  const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
  const { adapter, updater } = setup(input.root, input.options, true);
  let rejected = false, error;
  try {
    await updater.checkForUpdates(); await updater.downloadUpdate();
    if (input.mode === 'swap') fs.writeFileSync(pending(input.root), bad);
  } catch (e) { rejected = true; error = e.message; }
  if (input.mode !== 'prime') adapter.fireQuit(0);
  const output = { rejected, error, spawns: updater.spawns, quitCount: adapter.quitCount };
  updater.close();
  console.log(JSON.stringify(output));
}
function pending(root) { return path.join(root, 'cache/mindtech-unit/pending/update-x64.exe'); }
if (process.argv[2] === 'worker') {
  worker().catch(e => { console.error(e); process.exitCode = 1; });
} else {
  const root = fs.mkdtempSync(path.join(__dirname, '.unit-'));
  const pair = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
  let server, origin, envelope, artifact = good, artifactHits = 0, manifestHits = 0;
  let redirect = false, serial = 0;
  let artifactAvailable = true;
  const signed = (changes = {}, key = pair.privateKey) => {
    const payload = JSON.stringify({ appId: 'MINDTECH', channel: 'stable', platform: 'win32',
      arch: 'x64', version: '2.2.2', seq: 1, sha512: sha(good), size: good.length,
      url: origin + '/update-x64.exe', ...changes });
    return { payload, signature: sign(null, Buffer.from(payload), key).toString('base64') };
  };
  const options = () => ({ publicKey, feedURL: origin + '/manifest', channel: 'stable' });
  const fresh = (autoQuit = false) => {
    const dir = path.join(root, String(++serial));
    return { root: dir, ...setup(dir, options(), autoQuit) };
  };
  test.before(async () => {
    server = https.createServer({ key: fs.readFileSync(process.env.UNIT_TLS_KEY),
      cert: fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS) }, (req, res) => {
      if (req.url === '/manifest') {
        manifestHits++; res.end(JSON.stringify(envelope));
      } else if (req.url === '/update-x64.exe') {
        artifactHits++;
        if (!artifactAvailable) { res.writeHead(404); res.end(); return; }
        if (redirect) { res.writeHead(302, { location: origin + '/other.exe' }); res.end(); }
        else res.end(artifact);
      } else { res.writeHead(404); res.end(); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    origin = `https://127.0.0.1:${server.address().port}`;
  });
  test.beforeEach(() => { artifact = good; redirect = false; artifactAvailable = true; envelope = signed(); });
  test.after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  });
  test('valid full download, authenticated event and explicit real install() path', async () => {
    const { updater } = fresh();
    try {
      let events = 0; updater.on('update-downloaded', () => events++);
      const start = artifactHits;
      assert.equal((await updater.checkForUpdates()).isUpdateAvailable, true);
      assert.equal(updater.autoDownload, false); assert.equal(updater.autoInstallOnAppQuit, false);
      await updater.downloadUpdate();
      assert.equal(events, 1); assert.equal(artifactHits, start + 1);
      assert.equal(updater.install(false, false), true);
      assert.equal(updater.spawns[0].hash, sha(good));
    } finally { updater.close(); }
  });
  test('wrong key, missing signature, modified payload rejected before cache creation', async () => {
    const cases = [signed({}, other.privateKey), { payload: signed().payload },
      { ...signed(), payload: signed().payload.replace('2.2.2', '2.2.3') }];
    for (const candidate of cases) {
      const { root: dir, updater, adapter } = fresh(true);
      try {
        envelope = candidate; const start = artifactHits;
        await assert.rejects(updater.checkForUpdates(), /AUTH:/);
        adapter.fireQuit(0);
        assert.equal(artifactHits, start); assert.equal(updater.spawns.length, 0);
        assert.equal(fs.existsSync(path.join(dir, 'cache')), false);
      } finally { updater.close(); }
    }
  });
  test('signed policy violations: identity, channel, OS, arch, SemVer, sequence, hash, size, origin, schema', async () => {
    const cases = [{ appId: 'OTHER' }, { channel: 'beta' }, { platform: 'darwin' },
      { arch: 'arm64' }, { version: '2.2.1' }, { version: 'v2.2.2' }, { seq: 0 },
      { seq: 1.1 }, { sha512: 'bad' }, { size: 0 }, { url: 'https://example.invalid/upstream.exe' },
      { extra: 'unsigned semantics forbidden' }];
    for (const changes of cases) {
      const { updater } = fresh();
      try { envelope = signed(changes); await assert.rejects(updater.checkForUpdates(), /AUTH:/); }
      finally { updater.close(); }
    }
  });
  test('antirollback persists; older seq, reused seq and higher-seq older version blocked', async () => {
    const { root: dir, updater } = fresh();
    envelope = signed({ version: '2.2.3', seq: 2 });
    await updater.checkForUpdates(); updater.close();
    for (const changes of [{}, { version: '2.2.4', seq: 2 }, { version: '2.2.2', seq: 3 }]) {
      const { updater: next } = setup(dir, options());
      try { envelope = signed(changes); await assert.rejects(next.checkForUpdates(), /AUTH: (rollback|sequence)/); }
      finally { next.close(); }
    }
  });
  test('same-instance cache swapped: cache fast path rehash rejects, no event/install/quit spawn', async () => {
    const { root: dir, updater, adapter } = fresh(true);
    try {
      await updater.checkForUpdates(); await updater.downloadUpdate();
      fs.writeFileSync(pending(dir), bad);
      const start = artifactHits; let events = 0;
      updater.on('update-downloaded', () => events++);
      await assert.rejects(updater.downloadUpdate(), /AUTH: installer SHA512/);
      assert.equal(artifactHits, start); assert.equal(events, 0);
      assert.equal(updater.install(), false); adapter.fireQuit(0);
      assert.equal(updater.spawns.length, 0);
    } finally { updater.close(); }
  });
  test('swap after download blocks actual quitAndInstall() and automatic quit', async () => {
    const { root: dir, updater, adapter } = fresh(true);
    try {
      await updater.checkForUpdates(); await updater.downloadUpdate();
      fs.writeFileSync(pending(dir), bad);
      updater.quitAndInstall(); adapter.fireQuit(0);
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(updater.spawns.length, 0); assert.equal(adapter.quitCount, 0);
    } finally { updater.close(); }
  });
  test('auth metadata cannot be mutated; new manifest invalidates older pending install', async () => {
    const { updater } = fresh();
    try {
      const result = await updater.checkForUpdates(); await updater.downloadUpdate();
      assert.equal(Reflect.set(result.updateInfo, 'version', '9.0.0'), false);
      assert.equal(Reflect.set(result.updateInfo.files[0], 'sha512', sha(bad)), false);
      const bytesB = Buffer.from('UNIT ONLY: MINDTECH installer B, distinct inert bytes.\n');
      artifact = bytesB;
      envelope = signed({ version: '2.2.3', seq: 2, sha512: sha(bytesB), size: bytesB.length });
      await updater.checkForUpdates();
      assert.equal(updater.install(), false);
      assert.equal(updater.spawns.length, 0);
      await updater.downloadUpdate();
      assert.equal(updater.install(), true);
      assert.equal(updater.spawns.length, 1);
      assert.equal(updater.spawns[0].hash, sha(bytesB));
    } finally { updater.close(); }
  });
  test('wrong artifact hash/size, oversized body, and redirect never dispatch or install', async () => {
    for (const kind of ['hash', 'short', 'oversize', 'redirect']) {
      const { updater, adapter } = fresh(true);
      try {
        artifact = kind === 'hash' ? bad : kind === 'short' ? good.subarray(1) :
          kind === 'oversize' ? Buffer.concat([good, good]) : good;
        redirect = kind === 'redirect';
        let events = 0; updater.on('update-downloaded', () => events++);
        await updater.checkForUpdates(); await assert.rejects(updater.downloadUpdate());
        adapter.fireQuit(0); assert.equal(events, 0); assert.equal(updater.spawns.length, 0);
      } finally { updater.close(); }
    }
  });
  test('spawn EACCES/UNKNOWN/ENOENT: observable failure, no elevation/shell fallback, retry recovers', async () => {
    for (const code of ['EACCES', 'UNKNOWN', 'ENOENT']) {
      const { updater } = fresh();
      try {
        const errors = [];
        updater.on('error', error => errors.push(error));
        await updater.checkForUpdates();
        await updater.downloadUpdate();
        updater.spawnError = code;
        assert.equal(updater.install(), false, 'no PID cannot report launch success');
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(errors.length, 1);
        assert.equal(errors[0].code, code);
        assert.deepEqual(updater.spawns.map(item => item.file), ['update-x64.exe']);
        updater.spawnError = undefined;
        assert.equal(updater.install(), true, 'failed launch must release latch');
        assert.deepEqual(updater.spawns.map(item => item.file), ['update-x64.exe', 'update-x64.exe']);
      } finally { updater.close(); }
    }
  });
  test('package rejected from public download metadata without DownloadedUpdateHelper access', async () => {
    const { updater } = fresh();
    try {
      const result = await updater.checkForUpdates();
      await assert.rejects(updater.probePackage(result.updateInfo), /AUTH: file metadata/);
      assert.equal(updater.spawns.length, 0);
    } finally { updater.close(); }
  });
  test('accepted B with unavailable artifact fails closed, never reauthorizes A', async () => {
    const { updater, adapter } = fresh(true);
    try {
      await updater.checkForUpdates();
      await updater.downloadUpdate();
      envelope = signed({ version: '2.2.3', seq: 2 });
      await updater.checkForUpdates();
      assert.equal(updater.install(), false);
      artifactAvailable = false;
      await assert.rejects(updater.downloadUpdate(), /AUTH: HTTP response/);
      assert.equal(updater.install(), false);
      adapter.fireQuit(0);
      envelope = signed();
      await assert.rejects(updater.checkForUpdates(), /AUTH: rollback sequence/);
      assert.equal(updater.spawns.length, 0);
    } finally { updater.close(); }
  });
  async function child(dir, mode) {
    const input = path.join(root, `worker-${++serial}.json`);
    fs.writeFileSync(input, JSON.stringify({ root: dir, options: options(), mode }));
    const { stdout } = await promisify(execFile)(process.execPath, [__filename, 'worker', input], {
      env: { PATH: process.env.PATH, HOME: root, NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS },
      timeout: 15000,
    });
    return JSON.parse(stdout);
  }
  test('real new Node process: valid cache+quit; post-cache swap+quit blocked; rollback+quit blocked', async () => {
    const dir = path.join(root, 'cross-process'), start = artifactHits;
    let result = await child(dir, 'prime');
    assert.equal(result.rejected, false); assert.equal(result.spawns.length, 0);
    result = await child(dir, 'quit');
    assert.equal(result.rejected, false); assert.equal(result.spawns[0].hash, sha(good));
    assert.equal(artifactHits, start + 1, 'second process actually used library cache');
    for (const invalid of [signed({}, other.privateKey),
      { ...signed(), payload: signed().payload.replace('2.2.2', '2.2.3') }]) {
      envelope = invalid; result = await child(dir, 'quit');
      assert.equal(result.rejected, true); assert.equal(result.spawns.length, 0);
      assert.equal(artifactHits, start + 1, 'invalid manifest must not touch cached installer');
    }
    envelope = signed();
    result = await child(dir, 'swap');
    assert.equal(result.rejected, false); assert.equal(result.spawns.length, 0);
    envelope = signed({ version: '2.2.3', seq: 2 });
    result = await child(dir, 'prime'); assert.equal(result.rejected, false);
    envelope = signed(); result = await child(dir, 'quit');
    assert.equal(result.rejected, true); assert.match(result.error, /rollback sequence/);
    assert.equal(result.spawns.length, 0);
  });
  test('new process poison cache metadata cannot authorize bad bytes; valid bytes repair cache', async () => {
    const dir = path.join(root, 'poison-process');
    await child(dir, 'prime');
    fs.writeFileSync(pending(dir), bad);
    fs.writeFileSync(path.join(path.dirname(pending(dir)), 'update-info.json'),
      JSON.stringify({ fileName: 'update-x64.exe', sha512: sha(bad), isAdminRightsRequired: true }));
    const start = artifactHits, result = await child(dir, 'quit');
    assert.equal(result.rejected, false); assert.equal(artifactHits, start + 1);
    assert.equal(result.spawns.length, 1); assert.equal(result.spawns[0].hash, sha(good));
  });
  test('concurrent writer fails closed; corrupted state fails closed; no leaked lock', async () => {
    const { root: dir, updater } = fresh();
    try { assert.throws(() => setup(dir, options()), /EEXIST/); }
    finally { updater.close(); }
    fs.writeFileSync(path.join(dir, 'mindtech-update-seq.json'), '{}');
    assert.throws(() => setup(dir, options()), /AUTH:/);
    assert.equal(fs.existsSync(path.join(dir, 'mindtech-update-seq.json.lock')), false);
    assert.ok(manifestHits > 0);
  });
}
