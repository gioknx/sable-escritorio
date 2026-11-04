'use strict';
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { fork, spawnSync } = require('node:child_process');
const { generateKeyPairSync, sign, createHash } = require('node:crypto');
const { withTLS, errorRecord, writeEvidence } = require('./run-unit.cjs');
const stateName = 'mindtech-update-seq.json';
function snapshot(root) {
  return Object.fromEntries(['', '.lock', '.new'].map(suffix => {
    const file = path.join(root, stateName + suffix);
    try {
      const stat = fs.lstatSync(file);
      const item = { exists: true, size: stat.size, file: stat.isFile() };
      if (stat.isFile() && stat.size <= 16384 && suffix !== '.lock') {
        const bytes = fs.readFileSync(file);
        item.sha256 = createHash('sha256').update(bytes).digest('hex');
        // Only the signed public envelope is stored here, never a signing/TLS private key.
        try { item.envelope = JSON.parse(bytes.toString('utf8')); }
        catch (error) { item.text = bytes.toString('utf8'); item.parseError = errorRecord(error); }
      }
      return [stateName + suffix, item];
    } catch (error) {
      if (error.code === 'ENOENT') return [stateName + suffix, { exists: false }];
      return [stateName + suffix, { error: errorRecord(error) }];
    }
  }));
}
function adapter(root) {
  return { version: '2.2.1', name: 'MINDTECH', isPackaged: true, userDataPath: root,
    whenReady: async () => {}, onQuit() {}, quit() { throw new Error('Unexpected quit in Policy-only gate'); },
    relaunch() { throw new Error('Unexpected relaunch in Policy-only gate'); } };
}
async function worker(input) {
  const { AuthenticatedNsisUpdater } = require('./update-auth.cjs');
  const report = { operation: input.operation, pid: process.pid, status: 'FAIL',
    snapshots: { before: snapshot(input.root) }, emittedErrors: [] };
  let updater;
  try {
    updater = new AuthenticatedNsisUpdater(input.options, adapter(input.root));
    updater.logger = null;
    updater.on('error', error => report.emittedErrors.push(errorRecord(error)));
    report.snapshots.open = snapshot(input.root);
    if (input.operation === 'locked') throw new Error('Concurrent constructor unexpectedly acquired lock');
    const result = await updater.checkForUpdates();
    if (!result.isUpdateAvailable) throw new Error('Expected authenticated update metadata');
    report.updateInfo = result.updateInfo;
    report.snapshots.accepted = snapshot(input.root);
    report.status = 'PASS';
    if (input.hold) {
      process.send({ kind: 'ready', report });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Parent did not request close')), 25000);
        process.once('message', command => {
          clearTimeout(timer);
          if (command.close === true) resolve(); else reject(new Error('Unexpected parent command'));
        });
      });
    }
  } catch (error) {
    report.error = errorRecord(error);
    report.status = input.operation === 'locked' && error.code === 'EEXIST' ? 'EXPECTED_LOCK_REJECTION' :
      input.operation === 'rollback' && /^AUTH: rollback sequence/.test(error.message) ? 'EXPECTED_ROLLBACK_REJECTION' : 'BLOQUEADO';
  } finally {
    report.snapshots.beforeClose = snapshot(input.root);
    try { if (updater) updater.close(); }
    catch (error) { report.closeError = errorRecord(error); report.status = 'BLOQUEADO'; }
    report.snapshots.afterClose = snapshot(input.root);
  }
  process.send({ kind: 'done', report }, () => process.disconnect());
}
function launch(input, env) {
  const child = fork(__filename, ['--worker'], {
    env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true,
  });
  let last, output = '', readyResolve;
  const ready = new Promise(resolve => { readyResolve = resolve; });
  const done = new Promise(resolve => {
    const timer = setTimeout(() => child.kill(), 35000);
    child.stdout.on('data', bytes => { output = (output + bytes).slice(-32768); });
    child.stderr.on('data', bytes => { output = (output + bytes).slice(-32768); });
    child.on('message', message => {
      if (message.kind === 'ready') readyResolve(message.report);
      if (message.kind === 'done') last = message.report;
    });
    child.on('error', error => { last = { status: 'BLOQUEADO', error: errorRecord(error) }; });
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      if (!last || code !== 0 || signal) last = { status: 'BLOQUEADO', code, signal, output, partial: last };
      readyResolve(null);
      resolve(last);
    });
  });
  child.send(input);
  return { child, ready, done };
}
function proveNTFS(root) {
  const command = "$ErrorActionPreference='Stop'; $item=Get-Item -LiteralPath $env:UPDATE_AUTH_PROBE_ROOT; " +
    "$drive=$item.PSDrive.Root; if ($drive -notmatch '^[A-Za-z]:\\\\$') { throw 'Not a local drive path' }; " +
    "$v=Get-Volume -DriveLetter $drive.Substring(0,1); " +
    "[pscustomobject]@{ drive=$drive; fileSystem=$v.FileSystem; driveType=[string]$v.DriveType } | ConvertTo-Json -Compress";
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
    env: { ...process.env, UPDATE_AUTH_PROBE_ROOT: root }, shell: false,
    encoding: 'utf8', timeout: 15000, windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`NTFS proof failed: ${result.stderr}`);
  const volume = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim());
  if (volume.fileSystem !== 'NTFS' || volume.driveType !== 'Fixed') {
    throw new Error(`NTFS local fixed volume required: ${JSON.stringify(volume)}`);
  }
  return volume;
}
async function main() {
  const report = { gate: 'Policy persistence', status: 'BLOQUEADO', platform: process.platform,
    arch: process.arch, node: process.version, rounds: [],
    scope: 'Real signed HTTPS metadata and unmodified updater APIs; no installer, crash or power-loss proof' };
  if (process.platform !== 'win32') {
    report.status = 'BLOQUEADO_NAO_WINDOWS';
    writeEvidence('probe', report); process.exitCode = 78; return;
  }
  let server;
  try {
    if (process.arch !== 'x64') throw new Error('win32/x64 required');
    if (!process.env.RUNNER_TEMP || !path.isAbsolute(process.env.RUNNER_TEMP)) throw new Error('Absolute RUNNER_TEMP required');
    const root = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, 'update-auth-policy-'));
    report.root = root;
    report.volume = proveNTFS(root);
    await withTLS(async ({ key, cert, env }) => {
      const pair = generateKeyPairSync('ed25519');
      const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
      let envelope;
      server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
        if (req.url !== '/manifest') { res.writeHead(404); res.end(); return; }
        report.manifestRequests = (report.manifestRequests || 0) + 1;
        res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(envelope));
      });
      await new Promise((resolve, reject) => {
        server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
      });
      try {
        const origin = `https://127.0.0.1:${server.address().port}`;
        const signed = (version, seq) => {
          const bytes = Buffer.from('POLICY ONLY: inert artifact; never downloaded or executed.\n');
          const payload = JSON.stringify({ appId: 'MINDTECH', channel: 'stable', platform: 'win32', arch: 'x64',
            version, seq, sha512: createHash('sha512').update(bytes).digest('base64'), size: bytes.length,
            url: origin + '/update-x64.exe' });
          return { payload, signature: sign(null, Buffer.from(payload), pair.privateKey).toString('base64') };
        };
        const options = { publicKey, feedURL: origin + '/manifest', channel: 'stable' };
        envelope = signed('2.2.3', 2);
        report.acceptedEnvelope = envelope;
        const first = launch({ root, options, operation: 'prime', hold: true }, env);
        const ready = await first.ready;
        if (ready) {
          try { report.rounds.push(await launch({ root, options, operation: 'locked' }, env).done); }
          finally { first.child.send({ close: true }); }
        }
        report.rounds.push(await first.done);
        // Even if the first persist failed after rename, try the unchanged state in a NEW process.
        // A successful restart must never erase the first failure or make this gate green.
        report.rounds.push(await launch({ root, options, operation: 'resume' }, env).done);
        envelope = signed('2.2.2', 1);
        report.rounds.push(await launch({ root, options, operation: 'rollback' }, env).done);
        report.finalState = snapshot(root);
        const expected = ['EXPECTED_LOCK_REJECTION', 'PASS', 'PASS', 'EXPECTED_ROLLBACK_REJECTION'];
        const statuses = report.rounds.map(round => round.status);
        const clean = report.finalState[stateName + '.lock'].exists === false &&
          report.finalState[stateName + '.new'].exists === false;
        const persisted = report.finalState[stateName].envelope;
        const sameEnvelope = persisted && JSON.stringify(persisted) === JSON.stringify(report.acceptedEnvelope);
        const successes = report.rounds.filter(round => round.status === 'PASS');
        const lifecycle = successes.length === 2 && successes[0].pid !== successes[1].pid && successes.every(round =>
          round.snapshots.open[stateName + '.lock'].exists === true &&
          round.snapshots.beforeClose[stateName + '.lock'].exists === true &&
          round.snapshots.afterClose[stateName + '.lock'].exists === false &&
          round.snapshots.afterClose[stateName + '.new'].exists === false);
        report.status = JSON.stringify(statuses) === JSON.stringify(expected) && clean && sameEnvelope && lifecycle ? 'PASS' : 'BLOQUEADO';
      } finally {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve)); server = undefined;
      }
    });
    report.tlsCleanup = 'completed';
  } catch (error) {
    report.status = 'BLOQUEADO';
    report.error = errorRecord(error);
    if (report.root) report.finalState = snapshot(report.root);
  } finally {
    if (server) { server.closeAllConnections(); server.close(); }
  }
  writeEvidence('probe', report);
  process.exitCode = report.status === 'PASS' ? 0 : 1;
}
if (process.argv[2] === '--worker') {
  process.once('message', input => worker(input).catch(error => {
    process.send({ kind: 'done', report: { status: 'BLOQUEADO', error: errorRecord(error) } }, () => process.disconnect());
  }));
} else if (require.main === module) {
  main().catch(error => { console.error(error); process.exitCode = 1; });
}
