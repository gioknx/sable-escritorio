'use strict';
// Disposable packaged Electron fixture. Imports under Node are inert.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
function parseArgs(argv) {
  assert.equal(argv.length, 7, 'packaged argv count');
  assert.equal(argv[1], '--phase'); assert.ok(['negative', 'positive', 'reopen'].includes(argv[2]));
  assert.equal(argv[3], '--run-dir'); assert.ok(path.isAbsolute(argv[4]));
  assert.equal(argv[5], '--nonce'); assert.match(argv[6], /^[a-f0-9]{64}$/);
  assert.ok(Buffer.byteLength(JSON.stringify(argv)) <= 8192);
  return { phase: argv[2], runDir: argv[4], nonce: argv[6] };
}
function expectedNegative(error) {
  return ['AUTH: installer SHA512', 'AUTH: download size', 'AUTH: response size limit'].includes(error?.message);
}
function physical(file) {
  assert.ok(path.isAbsolute(file)); let current = path.parse(file).root;
  for (const part of file.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); const st = fs.lstatSync(current);
    assert.ok(!st.isSymbolicLink(), 'link/junction');
    if (st.isFile()) assert.equal(st.nlink, 1, 'hardlink');
  }
  assert.equal(fs.realpathSync.native(file), file); return file;
}
function hash(file, algorithm = 'sha256') {
  physical(file); const h = crypto.createHash(algorithm), fd = fs.openSync(file, 'r'), buffer = Buffer.alloc(65536);
  try { let n; while ((n = fs.readSync(fd, buffer, 0, buffer.length, null))) h.update(buffer.subarray(0, n)); }
  finally { fs.closeSync(fd); } return h.digest(algorithm === 'sha512' ? 'base64' : 'hex');
}
function inventory(root, prefix = '') {
  physical(root);
  return fs.readdirSync(root).sort().flatMap(name => {
    const file = path.join(root, name), relative = prefix ? `${prefix}/${name}` : name;
    physical(file); const st = fs.statSync(file);
    if (st.isDirectory()) return inventory(file, relative);
    assert.ok(st.isFile()); return [{ path: relative, size: st.size, sha256: hash(file) }];
  });
}
function verifyInventory(root, items) { assert.deepEqual(inventory(root), items, 'inventory/hash mismatch'); }
function readJSON(file, limit = 65536) {
  physical(file); assert.ok(fs.statSync(file).size <= limit, 'bounded JSON'); return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function writeJSON(file, value) {
  const text = JSON.stringify(value); assert.ok(Buffer.byteLength(text) <= 65536);
  fs.writeFileSync(file + '.writing', text, { flag: 'wx', mode: 0o600 });
  assert.ok(!fs.existsSync(file)); fs.renameSync(file + '.writing', file);
}
async function main() {
  const args = parseArgs(process.argv), config = readJSON(path.join(args.runDir, 'config.json'));
  for (const key of ['phase', 'runDir', 'nonce']) assert.equal(config[key], args[key]);
  physical(args.runDir); let app, updater, exitCode = 1;
  const record = { ...args, status: 'ERROR', pid: process.pid, argv: [...process.argv], nativeElectron: false,
    runtime: { type: process.type || null, platform: process.platform, arch: process.arch, electron: process.versions.electron || null, node: process.versions.node },
    executable: process.execPath, executableSha256: hash(process.execPath), checkedForUpdates: false, driverDriven: args.phase === 'reopen' };
  try {
    assert.equal(process.type, 'browser'); assert.equal(process.platform, 'win32'); assert.equal(process.arch, 'x64');
    assert.equal(process.versions.electron, '45.0.0'); assert.equal(record.executable, config.executable);
    assert.equal(record.executableSha256, config.executableSha256);
    app = require('electron').app; assert.equal(app.isReady(), false);
    const paths = { home: config.home, appData: config.appdata, userData: config.userData,
      sessionData: config.cache, temp: config.temp, logs: config.logs };
    for (const [key, value] of Object.entries(paths)) { physical(value); app.setPath(key, value); }
    app.disableHardwareAcceleration(); await app.whenReady();
    const { DatabaseSync } = require('node:sqlite'); const memory = new DatabaseSync(':memory:', { allowExtension: false });
    try { record.sqliteVersion = memory.prepare('SELECT sqlite_version() v').get().v; } finally { memory.close(); }
    assert.ok(require('../update-auth-windows/node_modules/semver').gte(record.sqliteVersion, '3.51.3'));
    assert.equal(process.env.ELECTRON_FORCE_IS_PACKAGED, undefined, 'no packaged-status override');
    record.isPackaged = app.isPackaged; assert.equal(app.isPackaged, true);
    record.version = app.getVersion(); assert.equal(record.version, args.phase === 'reopen' ? '2.2.3' : '2.2.1');
    record.paths = Object.fromEntries(Object.keys(paths).map(key => [key, app.getPath(key)])); assert.deepEqual(record.paths, paths);
    const sourceRoot = app.getAppPath(); assert.equal(sourceRoot, path.join(process.resourcesPath, 'app'));
    const sourceInventory = path.join(process.resourcesPath, 'source-inventory.json');
    assert.equal(hash(sourceInventory), config.inventorySha256); verifyInventory(sourceRoot, readJSON(sourceInventory, 8 * 1024 * 1024));
    record.sourceRoot = sourceRoot; record.inventorySha256 = config.inventorySha256;
    const canary = path.join(config.userData, 'canary.txt');
    if (args.phase === 'reopen') {
      record.canary = fs.readFileSync(physical(canary), 'utf8'); assert.equal(record.canary, config.canary);
      record.nativeElectron = true; record.status = 'PASS'; exitCode = 0;
    } else {
      assert.equal(fs.readFileSync(physical(canary), 'utf8'), config.canary);
      const { Policy } = require('../update-auth-policy-sqlite/policy.cjs');
      const { ElectronAppAdapter } = require('../update-auth-windows/node_modules/electron-updater/out/ElectronAppAdapter');
      const { AuthenticatedNsisUpdater } = require('./update-auth.cjs');
      const adapter = new ElectronAppAdapter();
      const options = { directory: config.directory, nonce: config.storeNonce, publicKey: config.publicKey, feedURL: config.feedURL, channel: 'stable' };
      const policy = await Policy.initialise(options, adapter); policy.close();
      updater = new AuthenticatedNsisUpdater(options); // Undefined second arg: genuine default adapter.
      assert.ok(updater.app instanceof ElectronAppAdapter); assert.equal(updater.app.app, app);
      assert.equal(updater.currentVersion.version, '2.2.1'); assert.equal(updater.app.isPackaged, true);
      record.adapter = { name: updater.app.constructor.name, version: updater.app.version, userDataPath: updater.app.userDataPath,
        baseCachePath: updater.app.baseCachePath, appUpdateConfigPath: updater.app.appUpdateConfigPath };
      assert.equal(record.adapter.appUpdateConfigPath, path.join(process.resourcesPath, 'app-update.yml'));
      record.config = await updater.configOnDisk.value;
      assert.equal(record.config.updaterCacheDirName, config.cacheName);
      assert.equal(record.adapter.baseCachePath.toLowerCase(), config.localappdata.toLowerCase());
      assert.equal(updater.autoRunAppAfterInstall, false); assert.equal(updater.autoInstallOnAppQuit, false);
      updater.on('error', error => { record.lastUpdaterError = { message: String(error.message).slice(0, 1024), code: error.code }; });
      record.loaded = [require.resolve('./update-auth.cjs'), require.resolve('../update-auth-policy-sqlite/policy.cjs'),
        require.resolve('../update-auth-policy-sqlite/store.cjs'), require.resolve('../update-auth-windows/node_modules/electron-updater'),
        require.resolve('../update-auth-windows/node_modules/semver')];
      for (const file of record.loaded) { assert.ok(file.startsWith(sourceRoot + path.sep)); assert.equal(require.cache[file].filename, file); }
      record.versions = { updater: require('../update-auth-windows/node_modules/electron-updater/package.json').version,
        semver: require('../update-auth-windows/node_modules/semver/package.json').version, electron: process.versions.electron };
      assert.equal(record.versions.updater, '6.8.11'); assert.equal(record.versions.semver, '7.7.3');
      record.checkedForUpdates = true;
      const checked = await updater.checkForUpdates(); assert.equal(checked.updateInfo.version, '2.2.3');
      // Reopened SQLite highwater must authenticate the same seq2 envelope idempotently.
      if (args.phase === 'negative') {
        let failure;
        try { await updater.downloadUpdate(); } catch (error) { failure = error; }
        assert.ok(expectedNegative(failure), `negativeUnexpected: ${failure?.message || 'accepted'}`);
        record.rejection = { message: failure.message }; assert.equal(updater.installerPath, null);
        record.status = 'REJECTED'; record.nativeElectron = true; exitCode = 0;
      } else {
        const files = await updater.downloadUpdate(); assert.equal(files.length, 1);
        record.installer = updater.installerPath; assert.equal(record.installer, files[0]);
        record.installerSha512 = hash(record.installer, 'sha512'); record.nativeElectron = true;
        record.status = 'LAUNCH_REQUESTED'; record.installCompleted = false;
        record.flags = { isSilent: true, isForceRunAfter: false, autoRunAppAfterInstall: updater.autoRunAppAfterInstall };
        // A receipt is intent, not process acceptance or install completion. No spawn overrides.
        writeJSON(path.join(args.runDir, 'receipt.json'), record);
        updater.quitAndInstall(true, false); return;
      }
    }
  } catch (error) { record.error = { message: String(error.message).slice(0, 1024), code: error.code }; }
  finally { if (updater) updater.close(); }
  writeJSON(path.join(args.runDir, 'receipt.json'), record);
  if (app) app.exit(exitCode); else process.exitCode = exitCode;
}
module.exports = { parseArgs, expectedNegative, physical, hash, inventory, verifyInventory, readJSON, writeJSON };
if (process.type === 'browser' || require.main === module) main().catch(error => {
  console.error(JSON.stringify({ status: 'ERROR', nativeElectron: false, reason: String(error.message).slice(0, 1024) }));
  if (process.type === 'browser') require('electron').app.exit(1); else process.exitCode = 1;
});
