'use strict';
// Parent Node orchestrates signing/TLS/compilation only; never positive Policy proxy.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const execute = promisify(execFile);
const E = require('./electron-main.cjs');
const S = require('../update-auth-sqlite/driver.cjs');
const P = require('../update-auth-policy-sqlite/driver.cjs');
const N = require('../update-auth-policy-sqlite/electron-main.cjs');
const { controlPaths } = require('../update-auth-sqlite/startup-control.cjs');
const checkout = path.resolve(__dirname, '../..');
const random = () => crypto.randomBytes(32).toString('hex');
const ARCHIVE_SHA256 = 'ae53887a23bb640369c93dbd38c408a2af5c0deb86f2fa76c6c244cb444b7f47';
const FIXTURE_EXE = 'MindtechNsisFixture.exe'; // Official Electron45 App::IsPackaged rejects basename electron.exe; preserve bytes, never force the flag.
function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    assert.ok(['--electron', '--out', '--compiler'].includes(argv[i]) && !Object.hasOwn(result, argv[i]));
    assert.ok(argv[i + 1] && !argv[i + 1].startsWith('--')); result[argv[i]] = argv[i + 1];
  }
  assert.equal(Object.keys(result).length, 3);
  return { electron: result['--electron'], out: result['--out'], compiler: result['--compiler'] };
}
function cloneSource(source) {
  source = source.replace(/\r\n/g, '\n'); // Canonical delta comparison only; inventories still hash raw copied bytes.
  source = source.slice(0, source.indexOf('class Policy {')) + source.slice(source.indexOf('class SignedProvider'));
  source = source.replace("const semver = require('semver');\n", '').replace("const { createHash, createPublicKey, verify } = require('node:crypto');\n", '');
  source = source.replace("require('electron-updater')", "require('../update-auth-windows/node_modules/electron-updater')")
    .replace("require('builder-util-runtime')", "require('../update-auth-windows/node_modules/builder-util-runtime')");
  const start = source.indexOf('const BOOTSTRAP'), end = source.indexOf('async function receive');
  return source.slice(0, start) + "const { Policy } = require('../update-auth-policy-sqlite/policy.cjs');\nfunction demand(ok, reason) { if (!ok) throw new Error(`AUTH: ${reason}`); }\n" + source.slice(end);
}
function verifyClone() {
  assert.equal(fs.readFileSync(path.join(__dirname, 'update-auth.cjs'), 'utf8').replace(/\r\n/g, '\n'),
    cloneSource(fs.readFileSync(path.join(checkout, 'experiments/update-auth-windows/update-auth.cjs'), 'utf8')), 'only Policy/import delta');
}
function packageFor(version) {
  assert.ok(['2.2.1', '2.2.3'].includes(version)); return { ...require('./fixture-package.json'), version };
}
function diagnosticSnapshot(privateRoot, executions) {
  const receipts = {}, handshake = {};
  for (const phase of ['negative', 'positive', 'reopen']) {
    const file = path.join(privateRoot, phase, 'receipt.json');
    if (fs.existsSync(file)) {
      try { receipts[phase] = E.readJSON(file); }
      catch (error) { receipts[phase] = { diagnosticReadError: String(error.message).slice(0, 1024) }; }
    }
  }
  for (const name of ['ready.json', 'installed.json', 'observer-ready.json', 'installer-exit.json']) {
    const file = path.join(privateRoot, 'handshake', name);
    if (fs.existsSync(file)) {
      try { handshake[name] = E.readJSON(file, 8192); }
      catch (error) { handshake[name] = { diagnosticReadError: String(error.message).slice(0, 1024) }; }
    }
  }
  return { classification: 'PUBLIC_NON_AUTHORIZING_DIAGNOSTIC', nativeAuthorization: false, receipts, handshake,
    executions: executions.map(execution => ({ ...execution, stdout: String(execution.stdout ?? '').slice(0, 4096),
      stderr: String(execution.stderr ?? '').slice(0, 4096) })) };
}
const PUBLIC = ['result.json', 'source-inventory.json', 'runtime.json', 'compiler.json', 'source-before.json', 'source-after.json',
  'negative.json', 'positive.json', 'reopen.json', 'control.json', 'ca.pem', 'diagnostics.json'];
function publicName(name) { return PUBLIC.includes(name); }
function validateChain(ready, chain, expected) {
  assert.equal(ready.status, 'READY'); assert.equal(ready.nonce, expected.nonce);
  assert.ok(Number.isInteger(ready.pid) && ready.pid > 0 && ready.pid !== expected.pid);
  assert.ok(Array.isArray(chain) && chain.length > 0 && chain.length <= 8);
  assert.equal(chain[0].pid, ready.pid);
  let linked = ready.pid, installerSeen = false; const seen = new Set();
  for (const item of chain) {
    assert.equal(item.pid, linked); assert.ok(Number.isInteger(item.pid) && item.pid > 0 && !seen.has(item.pid)); seen.add(item.pid);
    assert.ok(S.inside(expected.root, item.executable), 'OS image must remain owned');
    if (item.executable.toLowerCase() === expected.installer.toLowerCase()) {
      installerSeen = true;
      if (item.commandLine !== undefined) assert.ok([`${expected.installer} /S`, `"${expected.installer}" /S`].some(command => command.toLowerCase() === item.commandLine.toLowerCase()), 'genuine /S-only installer command');
    }
    linked = item.parent;
  }
  assert.equal(linked, expected.pid, 'OS parent chain reaches actual Native A'); assert.ok(installerSeen, 'actual downloaded installer in OS chain');
}
function validateCompleted(b, installed, ready, aPid) {
  assert.equal(installed.status, 'INSTALLED'); assert.equal(installed.nonce, ready.nonce); assert.equal(installed.pid, ready.pid);
  assert.equal(b.phase, 'reopen'); assert.equal(b.status, 'PASS'); assert.equal(b.nonce, ready.nonce);
  assert.ok(Number.isInteger(b.pid) && b.pid > 0 && b.pid !== aPid && b.pid !== ready.pid);
  assert.equal(b.version, '2.2.3'); assert.equal(b.nativeElectron, true); assert.equal(b.isPackaged, true);
  assert.equal(b.canary, ready.nonce); assert.equal(b.driverDriven, true); assert.equal(b.checkedForUpdates, false);
}
function profiles(root) {
  fs.mkdirSync(root);
  for (const name of ['appdata', 'localappdata', 'home', 'profile', 'cache', 'temp', 'logs']) fs.mkdirSync(path.join(root, name));
}
function start(exe, args, options) {
  const child = spawn(exe, args, { ...options, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), spawnError = null, timedOut = false;
  child.stdout.on('data', b => { stdout = Buffer.concat([stdout, b]).subarray(0, 65536); });
  child.stderr.on('data', b => { stderr = Buffer.concat([stderr, b]).subarray(0, 65536); });
  child.on('error', e => { spawnError = String(e.message).slice(0, 1024); });
  const done = new Promise(resolve => {
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, 180000);
    child.once('close', (exitCode, signal) => { clearTimeout(timer); resolve({ pid: child.pid || null, exitCode, signal, spawnError, timedOut,
      stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') }); });
  });
  return { child, done };
}
function cleanExit(execution) {
  assert.equal(execution.exitCode, 0); assert.equal(execution.signal, null); assert.equal(execution.spawnError, null); assert.equal(execution.timedOut, false);
}
async function pinRuntime(electron, privateRoot) {
  const archive = path.join(path.dirname(path.dirname(electron)), 'electron.zip');
  assert.equal(E.hash(archive), ARCHIVE_SHA256);
  const script = '$ErrorActionPreference="Stop"; $z=[IO.Compression.ZipFile]::OpenRead($env:NSIS_ARCHIVE); try { $e=@($z.Entries | Where-Object FullName -eq "electron.exe"); if($e.Count -ne 1){throw "Unique electron entry required"}; $s=$e[0].Open(); try { $h=[Security.Cryptography.SHA256]::Create(); try { [BitConverter]::ToString($h.ComputeHash($s)).Replace("-", "").ToLowerInvariant() } finally {$h.Dispose()} } finally {$s.Dispose()} } finally {$z.Dispose()}';
  const { stdout } = await execute('pwsh', ['-NoProfile', '-NonInteractive', '-Command', script], {
    env: { ...S.childEnvironment(privateRoot), NSIS_ARCHIVE: archive }, timeout: 30000, maxBuffer: 4096 });
  assert.match(stdout.trim(), /^[a-f0-9]{64}$/); assert.equal(E.hash(electron), stdout.trim());
  return { archiveSha256: ARCHIVE_SHA256, executableSha256: stdout.trim(), electron };
}
function copyApplication(runtime, destination, version, cacheName) {
  fs.cpSync(runtime, destination, { recursive: true, errorOnExist: true, force: false, dereference: false });
  fs.renameSync(path.join(destination, 'electron.exe'), path.join(destination, FIXTURE_EXE));
  const resources = path.join(destination, 'resources'), root = path.join(resources, 'app');
  assert.ok(!fs.existsSync(root) && !fs.existsSync(path.join(resources, 'app.asar')), 'pristine runtime only'); fs.mkdirSync(root);
  const names = ['experiments/update-auth-policy-sqlite/policy.cjs', 'experiments/update-auth-policy-sqlite/store.cjs',
    'experiments/update-auth-native-nsis/electron-main.cjs', 'experiments/update-auth-native-nsis/update-auth.cjs'];
  for (const name of names) {
    const source = path.join(checkout, name), target = path.join(root, name); E.physical(source);
    fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
    assert.equal(E.hash(source), E.hash(target));
  }
  const deps = path.join(checkout, 'experiments/update-auth-windows/node_modules');
  const copiedDeps = path.join(root, 'experiments/update-auth-windows/node_modules'); fs.mkdirSync(copiedDeps, { recursive: true });
  // npm .bin launch links are not runtime dependencies; every package byte is copied without links.
  for (const name of fs.readdirSync(deps).filter(name => name !== '.bin').sort()) {
    const source = path.join(deps, name), target = path.join(copiedDeps, name); E.physical(source);
    if (fs.statSync(source).isDirectory()) {
      const original = E.inventory(source); fs.cpSync(source, target, { recursive: true, force: false, errorOnExist: true });
      E.verifyInventory(target, original);
    } else { fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL); assert.equal(E.hash(source), E.hash(target)); }
  }
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(packageFor(version)), { flag: 'wx' });
  fs.writeFileSync(path.join(resources, 'app-update.yml'), `provider: generic\nurl: https://127.0.0.1/unused\nupdaterCacheDirName: ${cacheName}\n`, { flag: 'wx' });
  const items = E.inventory(root), external = path.join(resources, 'source-inventory.json');
  assert.ok(Buffer.byteLength(JSON.stringify(items)) <= 8 * 1024 * 1024); fs.writeFileSync(external, JSON.stringify(items), { flag: 'wx' });
  return { executable: path.join(destination, FIXTURE_EXE), inventorySha256: E.hash(external), items };
}
async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    console.log(JSON.stringify({ status: 'BLOCKED', nativeElectron: false, reason: 'Requires disposable Windows GHA x64; UNIT is not Native' })); return 78;
  }
  assert.equal(process.env.GITHUB_ACTIONS, 'true'); assert.ok(process.env.RUNNER_TEMP);
  const temp = E.physical(process.env.RUNNER_TEMP), electron = E.physical(path.resolve(options.electron)), out = path.resolve(options.out);
  assert.ok(S.inside(temp, electron) && path.extname(electron).toLowerCase() === '.exe');
  assert.ok(S.inside(temp, out) && !S.inside(checkout, out) && !S.inside(out, electron));
  E.physical(path.dirname(out)); fs.mkdirSync(out);
  const compiler = E.physical(path.resolve(options.compiler)); assert.equal(path.basename(compiler).toLowerCase(), 'makensis.exe');
  const report = { status: 'ERROR', nativeElectron: false, classification: 'PUBLIC',
    scope: 'Disposable packaged fixture only; driver-driven reopen, not Sable release or production auto-update' };
  let privateRoot, server; const live = new Set(), executions = []; let chain = [];
  const publish = (name, value) => { assert.ok(publicName(name)); N.writeJSON(path.join(out, name), value, 512 * 1024); };
  try {
    verifyClone(); privateRoot = fs.mkdtempSync(path.join(temp, 'nsis-private-')); profiles(path.join(privateRoot, 'tools'));
    const tools = path.join(privateRoot, 'tools'), toolEnv = S.childEnvironment(tools);
    report.runtime = await pinRuntime(electron, tools); publish('runtime.json', report.runtime);
    const compilerDirectory = path.dirname(path.dirname(compiler));
    assert.equal(path.basename(path.dirname(compiler)), 'Bin'); assert.equal(path.basename(compilerDirectory), 'windows');
    const toolArchive = path.resolve(compilerDirectory, '../../..', 'nsis-bundle-3.12.tar.gz');
    const toolPin = '56997fdefe25e7928a1a68b4583d08b240b66cf660234053b20131a74cc082f4';
    assert.ok(S.inside(temp, toolArchive)); assert.equal(E.hash(toolArchive), toolPin, 'official NSIS bundle pin');
    const compilerEnv = { ...toolEnv, NSISDIR: compilerDirectory }; // Compiler only, never Electron/TLS/global config.
    const compilerVersion = await execute(compiler, ['/VERSION'], { env: compilerEnv, timeout: 30000, maxBuffer: 4096 });
    assert.ok(compilerVersion.stdout.trim().length > 0 && compilerVersion.stdout.length <= 1024);
    publish('compiler.json', { executable: compiler, sha256: E.hash(compiler), version: compilerVersion.stdout.trim(), toolset: '1.2.1', declaredNSIS: '3.12', archiveSha256: toolPin, nsisDirectory: compilerDirectory, image: process.env.ImageOS, imageVersion: process.env.ImageVersion });
    const sourceNames = ['experiments/update-auth-policy-sqlite/policy.cjs', 'experiments/update-auth-policy-sqlite/store.cjs',
      ...['update-auth.cjs', 'electron-main.cjs', 'driver.cjs', 'fixture.nsi', 'fixture-package.json', 'native.test.cjs', 'README.md'].map(n => 'experiments/update-auth-native-nsis/' + n)];
    const before = sourceNames.map(file => ({ path: file, sha256: E.hash(path.join(checkout, file)) })); publish('source-before.json', before);
    // First startup is the pristine pinned EXE, before any packaged A/B fixtures are made.
    const control = path.join(privateRoot, 'control'); profiles(control); fs.mkdirSync(controlPaths(control).directory);
    const entry = path.join(control, 'startup-control.cjs'); fs.copyFileSync(path.join(checkout, 'experiments/update-auth-sqlite/startup-control.cjs'), entry);
    const expectedControl = { runDir: control, nonce: random(), controlSha256: E.hash(entry) };
    const controlArgs = S.buildControlArgv(entry, expectedControl); expectedControl.argv = [electron, ...controlArgs];
    const controlExecution = await S.runChild(electron, controlArgs, { cwd: control, env: S.childEnvironment(control) }, path.join(control, 'logs', 'process'));
    const mark = S.readStartupControl(controlPaths(control).checkpoint, controlExecution, expectedControl); S.requireReadyControl(mark, controlExecution);
    publish('control.json', { mark, execution: controlExecution, expected: expectedControl });
    const key = path.join(privateRoot, 'key.pem'), cert = path.join(privateRoot, 'ca.pem');
    await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Disposable NSIS localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', key, '-out', cert], { env: toolEnv, timeout: 30000, maxBuffer: 65536 });
    fs.copyFileSync(cert, path.join(out, 'ca.pem'), fs.constants.COPYFILE_EXCL);
    const nonce = random(), cacheName = 'disposable-nsis-' + nonce;
    const aRoot = path.join(privateRoot, 'A'), bRoot = path.join(privateRoot, 'B'), target = path.join(privateRoot, 'installed-' + nonce);
    const a = copyApplication(path.dirname(electron), aRoot, '2.2.1', cacheName), b = copyApplication(path.dirname(electron), bRoot, '2.2.3', cacheName);
    assert.equal(E.hash(a.executable), report.runtime.executableSha256); assert.equal(E.hash(b.executable), report.runtime.executableSha256);
    publish('source-inventory.json', { A: a.items, B: b.items });
    const bFiles = E.inventory(bRoot), installer = path.join(privateRoot, 'fixture.exe');
    const handshake = path.join(privateRoot, 'handshake'); fs.mkdirSync(handshake);
    const readyPath = path.join(handshake, 'ready.json'), installedPath = path.join(handshake, 'installed.json'), ack = path.join(handshake, 'ack');
    const defines = { OUTPUT: installer, TARGET: target, PAYLOAD: bRoot, READY: readyPath, INSTALLED: installedPath, ACK: ack, NONCE: nonce };
    for (const value of Object.values(defines)) assert.ok(!/[\r\n$"!]/.test(value), 'NSIS define metacharacter');
    await execute(compiler, ['/V2', ...Object.entries(defines).map(([k, v]) => `/D${k}=${v}`), path.join(__dirname, 'fixture.nsi')], { env: compilerEnv, timeout: 300000, maxBuffer: 65536 });
    const installerSize = fs.statSync(installer).size, installerSha512 = E.hash(installer, 'sha512');
    assert.ok(installerSize > 0 && installerSize <= 1024 ** 3); report.payload = { size: installerSize, sha512: installerSha512, sha256: E.hash(installer), files: bFiles.length };
    const pair = crypto.generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
    let tamper = true, envelope; const counts = { negative: { requests: 0, bytes: 0 }, positive: { requests: 0, bytes: 0 } };
    server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
      if (req.url === '/manifest') { res.end(JSON.stringify(envelope)); return; }
      if (req.url !== '/fixture.exe' || req.method !== 'GET') { res.writeHead(404); res.end(); return; }
      const negative = tamper, counter = counts[negative ? 'negative' : 'positive']; counter.requests++;
      res.writeHead(200, { 'content-length': installerSize, 'content-type': 'application/octet-stream' });
      const input = fs.createReadStream(installer);
      input.on('data', bytes => { counter.bytes += bytes.length; });
      // Mutation occurs in the actual outgoing stream, while signed metadata stays unchanged.
      const { Transform } = require('node:stream'); let flip = negative;
      const mutate = new Transform({ transform(chunk, encoding, callback) { if (flip) { chunk = Buffer.from(chunk); chunk[0] ^= 1; flip = false; } callback(null, chunk); } });
      input.on('error', () => res.destroy()); res.on('close', () => input.destroy()); input.pipe(mutate).pipe(res);
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const feedURL = `https://127.0.0.1:${server.address().port}/manifest`;
    const payload = JSON.stringify({ appId: 'MINDTECH', arch: 'x64', channel: 'stable', platform: 'win32', seq: 2,
      sha512: installerSha512, size: installerSize, url: feedURL.replace('/manifest', '/fixture.exe'), version: '2.2.3' });
    envelope = { payload, signature: crypto.sign(null, Buffer.from(payload), pair.privateKey).toString('base64') }; report.envelope = envelope; report.publicKey = publicKey;
    const userData = path.join(privateRoot, 'shared-profile'); fs.mkdirSync(userData); fs.writeFileSync(path.join(userData, 'canary.txt'), nonce, { flag: 'wx' });
    const prepare = (phase, executable, inventorySha256) => {
      const runDir = path.join(privateRoot, phase); profiles(runDir);
      const config = { phase, nonce, runDir, executable, executableSha256: report.runtime.executableSha256, inventorySha256,
        home: path.join(runDir, 'home'), appdata: path.join(runDir, 'appdata'), localappdata: path.join(runDir, 'localappdata'), userData,
        cache: path.join(runDir, 'cache'), temp: path.join(runDir, 'temp'), logs: path.join(runDir, 'logs'), cacheName, canary: nonce,
        directory: path.join(runDir, 'policy'), storeNonce: random(), publicKey, feedURL };
      E.writeJSON(path.join(runDir, 'config.json'), config);
      const argv = ['--phase', phase, '--run-dir', runDir, '--nonce', nonce];
      const job = start(executable, argv, { cwd: runDir, env: P.environment(runDir, cert, process.env, privateRoot) }); live.add(job);
      job.done.then(execution => executions.push({ phase, ...execution }));
      return { config, job, receipt: path.join(runDir, 'receipt.json') };
    };
    const validateApp = (receipt, prepared, execution) => {
      cleanExit(execution); assert.equal(receipt.pid, execution.pid); assert.ok(Number.isInteger(execution.pid) && execution.pid > 0);
      assert.equal(receipt.phase, prepared.config.phase); assert.equal(receipt.nonce, nonce); assert.equal(receipt.runDir, prepared.config.runDir);
      assert.equal(receipt.executable, prepared.config.executable); assert.equal(receipt.executableSha256, report.runtime.executableSha256);
      assert.deepEqual(receipt.argv, [prepared.config.executable, '--phase', prepared.config.phase, '--run-dir', prepared.config.runDir, '--nonce', nonce]);
      assert.equal(receipt.inventorySha256, prepared.config.inventorySha256); assert.equal(receipt.nativeElectron, true); assert.equal(receipt.isPackaged, true);
    };
    const negative = prepare('negative', a.executable, a.inventorySha256), negExecution = await negative.job.done; live.delete(negative.job);
    const neg = E.readJSON(negative.receipt); validateApp(neg, negative, negExecution);
    assert.equal(neg.status, 'REJECTED'); assert.ok(E.expectedNegative(neg.rejection));
    assert.equal(counts.negative.requests, 1); assert.equal(counts.negative.bytes, installerSize);
    assert.ok(!fs.existsSync(target) && !fs.existsSync(readyPath) && !fs.existsSync(installedPath));
    publish('negative.json', { receipt: neg, execution: negExecution, counts: counts.negative, installTargetAbsent: true, installerReadyAbsent: true, installedReceiptAbsent: true });
    tamper = false;
    const positive = prepare('positive', a.executable, a.inventorySha256);
    const pos = await N.waitJSON(positive.receipt, 180000, positive.job.done);
    assert.equal(pos.status, 'LAUNCH_REQUESTED'); assert.equal(pos.installerSha512, installerSha512);
    assert.deepEqual(pos.flags, { isSilent: true, isForceRunAfter: false, autoRunAppAfterInstall: false });
    assert.ok(S.inside(privateRoot, pos.installer)); assert.equal(E.hash(pos.installer, 'sha512'), installerSha512);
    const ready = await N.waitJSON(readyPath, 180000);
    const observed = await execute('pwsh', ['-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop"; $rows=@(); $id=[int]$env:NSIS_PID; for($i=0;$i -lt 8;$i++){ $p=Get-CimInstance Win32_Process -Filter "ProcessId=$id"; if(-not $p){throw "Missing live installer ancestor"}; $rows+=@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;executable=$p.ExecutablePath;commandLine=$p.CommandLine}; if($p.ParentProcessId -eq [int]$env:NSIS_PARENT){break}; $id=[int]$p.ParentProcessId }; ConvertTo-Json -InputObject @($rows) -Compress'], {
      env: { ...toolEnv, NSIS_PID: String(ready.pid), NSIS_PARENT: String(positive.job.child.pid) }, timeout: 30000, maxBuffer: 16384 });
    chain = JSON.parse(observed.stdout); validateChain(ready, chain, { nonce, pid: positive.job.child.pid, installer: pos.installer, root: privateRoot });
    assert.equal(counts.positive.requests, 1); assert.equal(counts.positive.bytes, installerSize);
    // Capture a genuine OS process handle before ACK; exit0 is additional proof, not completion alone.
    const observerReady = path.join(handshake, 'observer-ready.json'), installerExitPath = path.join(handshake, 'installer-exit.json');
    const observer = start('pwsh', ['-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop"; $p=Get-Process -Id ([int]$env:NSIS_PID); $null=$p.Handle; @{pid=$p.Id;nonce=$env:NSIS_NONCE;status="OBSERVING"} | ConvertTo-Json -Compress | Set-Content ($env:NSIS_OBSERVER_READY+".writing"); Move-Item -LiteralPath ($env:NSIS_OBSERVER_READY+".writing") -Destination $env:NSIS_OBSERVER_READY; if(-not $p.WaitForExit(180000)){throw "Installer exit deadline"}; @{pid=$p.Id;nonce=$env:NSIS_NONCE;exitCode=$p.ExitCode} | ConvertTo-Json -Compress | Set-Content ($env:NSIS_EXIT+".writing"); Move-Item -LiteralPath ($env:NSIS_EXIT+".writing") -Destination $env:NSIS_EXIT'], {
      cwd: tools, env: { ...toolEnv, NSIS_PID: String(ready.pid), NSIS_NONCE: nonce, NSIS_OBSERVER_READY: observerReady, NSIS_EXIT: installerExitPath } }); live.add(observer);
    observer.done.then(execution => executions.push({ phase: 'installer-observer', ...execution }));
    assert.deepEqual(await N.waitJSON(observerReady, 30000, observer.done), { pid: ready.pid, nonce, status: 'OBSERVING' });
    for (const item of chain) { assert.equal(typeof item.commandLine, 'string'); item.executableSha256 = E.hash(item.executable); }
    assert.ok(!fs.existsSync(target), 'ready is not installed'); fs.writeFileSync(ack, nonce, { flag: 'wx' });
    const installed = await N.waitJSON(installedPath, 180000);
    assert.deepEqual(installed, { status: 'INSTALLED', nonce, pid: ready.pid }); E.verifyInventory(target, bFiles);
    const observerExecution = await observer.done; live.delete(observer); cleanExit(observerExecution);
    const installerExit = E.readJSON(installerExitPath); assert.deepEqual(installerExit, { pid: ready.pid, nonce, exitCode: 0 });
    // Never wait for A stdout/process close while NSIS is blocked on our ACK. Validate its exit after install finishes.
    const posExecution = await positive.job.done; live.delete(positive.job); validateApp(pos, positive, posExecution);
    publish('positive.json', { receipt: pos, execution: posExecution, ready, chain, installed, installerExit, observerExecution, filesVerified: true, counts: counts.positive });
    const reopened = prepare('reopen', path.join(target, FIXTURE_EXE), b.inventorySha256);
    const bExecution = await reopened.job.done; live.delete(reopened.job); const bReceipt = E.readJSON(reopened.receipt);
    validateApp(bReceipt, reopened, bExecution); validateCompleted(bReceipt, installed, ready, positive.job.child.pid);
    assert.equal(bReceipt.paths.userData, userData); publish('reopen.json', { receipt: bReceipt, execution: bExecution, driverDriven: true });
    assert.equal(fs.readFileSync(path.join(userData, 'canary.txt'), 'utf8'), nonce); E.verifyInventory(target, bFiles);
    E.verifyInventory(path.join(aRoot, 'resources/app'), a.items); E.verifyInventory(path.join(bRoot, 'resources/app'), b.items);
    for (const item of before) assert.equal(E.hash(path.join(checkout, item.path)), item.sha256); publish('source-after.json', before);
    assert.equal(E.hash(electron), report.runtime.executableSha256); assert.equal(E.hash(installer, 'sha512'), installerSha512);
    report.status = 'PASS'; report.nativeElectron = true; report.installCompleted = true; report.reopenedByDriver = true;
  } catch (error) { report.reason = String(error.message).slice(0, 2048); }
  finally {
    const cleanupError = error => { report.status = 'ERROR'; report.nativeElectron = false; report.cleanupError = String(error.message).slice(0, 1024); };
    try { for (const job of live) { job.child.kill(); await job.done; } } catch (e) { cleanupError(e); }
    try {
      // Only installer PIDs actually observed by CIM are eligible for cleanup. No arbitrary PID from a receipt.
      if (chain.length && privateRoot) await execute('pwsh', ['-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop"; foreach($id in ($env:NSIS_CLEAN_PIDS -split ",")){ $p=Get-CimInstance Win32_Process -Filter "ProcessId=$id"; if($p -and $p.ExecutablePath.StartsWith($env:NSIS_CLEAN_ROOT,[StringComparison]::OrdinalIgnoreCase)){Stop-Process -Id ([int]$id) -Force} }'], {
        env: { ...S.childEnvironment(path.join(privateRoot, 'tools')), NSIS_CLEAN_PIDS: chain.map(p => p.pid).join(','), NSIS_CLEAN_ROOT: privateRoot + path.sep }, timeout: 30000, maxBuffer: 4096 });
    } catch (e) { cleanupError(e); }
    try { if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } } catch (e) { cleanupError(e); }
    // Preserve actual child failure before deleting private state; diagnostics can never authorize PASS.
    try { if (privateRoot) publish('diagnostics.json', { ...diagnosticSnapshot(privateRoot, executions), osChain: chain }); } catch (e) { cleanupError(e); }
    try { if (privateRoot) fs.rmSync(privateRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }); } catch (e) { cleanupError(e); }
    try { assert.ok(fs.readdirSync(out).every(publicName), 'public artifact allowlist'); } catch (e) { cleanupError(e); }
  }
  publish('result.json', report); console.log(JSON.stringify({ status: report.status, nativeElectron: report.nativeElectron, evidence: path.join(out, 'result.json') }));
  return report.status === 'PASS' && report.nativeElectron ? 0 : 1;
}
module.exports = { parseArgs, cloneSource, verifyClone, packageFor, publicName, validateChain, validateCompleted, copyApplication, diagnosticSnapshot, main };
if (require.main === module) main().then(code => { process.exitCode = code; }).catch(error => {
  console.error(JSON.stringify({ status: 'ERROR', nativeElectron: false, reason: String(error.message).slice(0, 1024) })); process.exitCode = 1;
});
