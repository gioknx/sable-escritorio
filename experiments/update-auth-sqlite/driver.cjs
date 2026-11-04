'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { assertRuntime, assertSQLiteVersion } = require('./electron-main.cjs');
const LIMIT = 64 * 1024;
const TIMEOUT_MS = 20000;
const digest = content => crypto.createHash('sha256').update(content).digest('hex');

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!['--electron', '--root', '--out'].includes(key) || result[key] !== undefined ||
        !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error('Invalid CLI arguments');
    result[key] = argv[i + 1];
  }
  if (Object.keys(result).length !== 3) throw new Error('Required: --electron <exe> --root <benchmarkRoot> --out <evidenceDir>');
  return { electron: result['--electron'], root: result['--root'], out: result['--out'] };
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

// Reject symlinks/junctions in every existing component, not just the leaf.
function physicalPath(value, allowMissing = false) {
  if (!path.isAbsolute(value)) throw new Error('Paths must be absolute');
  const resolved = path.resolve(value);
  const root = path.parse(resolved).root;
  let current = root;
  const components = resolved.slice(root.length).split(path.sep).filter(Boolean);
  for (let i = 0; i < components.length; i++) {
    current = path.join(current, components[i]);
    let stat;
    try { stat = fs.lstatSync(current); }
    catch (error) {
      if (allowMissing && error.code === 'ENOENT') return resolved;
      throw error;
    }
    if (stat.isSymbolicLink()) throw new Error('Symlink/junction paths are not allowed');
    if (i < components.length - 1 && !stat.isDirectory()) throw new Error('Path ancestor is not a directory');
  }
  return fs.realpathSync.native(resolved);
}

function validatePaths(options, runnerTemp) {
  if (!runnerTemp) throw new Error('RUNNER_TEMP is required');
  const temp = physicalPath(runnerTemp);
  const root = physicalPath(options.root);
  const electron = physicalPath(options.electron);
  const out = physicalPath(options.out, true);
  if (!fs.statSync(temp).isDirectory() || !fs.statSync(root).isDirectory() || !inside(temp, root)) {
    throw new Error('Root must be a physical directory strictly under RUNNER_TEMP');
  }
  if (!inside(root, electron) || !fs.statSync(electron).isFile() || path.extname(electron).toLowerCase() !== '.exe') {
    throw new Error('Electron executable must be a regular .exe inside root');
  }
  if (fs.existsSync(out) && !fs.statSync(out).isDirectory()) throw new Error('Output must be a directory');
  return { root, electron, out };
}

function childEnvironment(runDir, source = process.env) {
  const env = {};
  // Explicit allowlist: do not forward CI tokens, NODE_OPTIONS or ELECTRON_RUN_AS_NODE.
  for (const name of ['SystemRoot', 'WINDIR', 'SystemDrive', 'COMSPEC', 'PATH', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE']) {
    const key = Object.keys(source).find(key => key.toUpperCase() === name.toUpperCase());
    if (key) env[name] = source[key];
  }
  Object.assign(env, {
    APPDATA: path.join(runDir, 'appdata'), LOCALAPPDATA: path.join(runDir, 'localappdata'),
    HOME: path.join(runDir, 'home'), USERPROFILE: path.join(runDir, 'home'),
    TEMP: path.join(runDir, 'temp'), TMP: path.join(runDir, 'temp'),
  });
  return env;
}

function runChild(executable, argv, options, logPrefix) {
  return new Promise(resolve => {
    const started = process.hrtime.bigint();
    let child;
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0);
    let stdoutTruncated = false, stderrTruncated = false;
    let timedOut = false, spawnError = null, settled = false, deadline;
    const finish = (exitCode, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(deadline);
      fs.writeFileSync(`${logPrefix}.stdout.log`, stdout, { flag: 'wx', mode: 0o600 });
      fs.writeFileSync(`${logPrefix}.stderr.log`, stderr, { flag: 'wx', mode: 0o600 });
      resolve({ pid: child.pid || null, exitCode, signal, timedOut, spawnError,
        elapsedMs: Number(process.hrtime.bigint() - started) / 1e6,
        stdoutTruncated, stderrTruncated, logPrefix });
    };
    child = spawn(executable, argv, { ...options, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
      deadline = setTimeout(() => finish(null, 'timeout'), 2000);
    }, TIMEOUT_MS);
    child.stdout.on('data', chunk => {
      stdoutTruncated ||= stdout.length + chunk.length > LIMIT;
      stdout = Buffer.concat([stdout, chunk.subarray(0, Math.max(0, LIMIT - stdout.length))]);
    });
    child.stderr.on('data', chunk => {
      stderrTruncated ||= stderr.length + chunk.length > LIMIT;
      stderr = Buffer.concat([stderr, chunk.subarray(0, Math.max(0, LIMIT - stderr.length))]);
    });
    child.on('error', error => { spawnError = String(error.message).slice(0, 1024); });
    child.on('close', finish);
  });
}

function validateReceipt(receipt, execution, expected) {
  if (execution.timedOut || execution.spawnError || execution.signal || !Number.isInteger(execution.pid) || execution.pid <= 0) {
    throw new Error('Electron process did not finish normally');
  }
  if (receipt.schemaVersion !== 1 || receipt.pid !== execution.pid || receipt.phase !== expected.phase ||
      receipt.nonce !== expected.nonce || receipt.dbPath !== expected.dbPath || receipt.probeSha256 !== expected.probeSha256) {
    throw new Error('Receipt/process/hash correspondence mismatch');
  }
  const expectedExit = { PASS: 0, BLOCKED: 78, ERROR: 1 }[receipt.status];
  if (expectedExit === undefined || execution.exitCode !== expectedExit) throw new Error('Receipt/exit mismatch');
  if (receipt.status === 'PASS') {
    assertRuntime(receipt.runtime);
    assertSQLiteVersion(receipt.sqliteVersion);
    const p = receipt.pragmas;
    if (!p || p.journal_mode !== 'wal' || p.synchronous !== 2 || p.locking_mode !== 'exclusive' ||
        p.busy_timeout !== 1000 || receipt.canary !== expected.canary ||
        !Array.isArray(receipt.compileOptions) || !receipt.compileOptions.every(item => typeof item === 'string')) {
      throw new Error('Incomplete capability receipt');
    }
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (process.platform !== 'win32') {
    console.log(JSON.stringify({ status: 'BLOCKED', nativeElectron: false, reason: 'Requires Windows host' }));
    return 78;
  }
  const locations = validatePaths(options, process.env.RUNNER_TEMP);
  fs.mkdirSync(locations.out, { recursive: true });
  physicalPath(locations.out);
  const reportPath = path.join(locations.out, 'capability.json');
  if (fs.existsSync(reportPath)) throw new Error('Refusing to overwrite capability.json');
  const report = { schemaVersion: 1, status: 'ERROR', nativeElectron: false,
    scope: 'capability/reopen only; not authentication, durability, crash recovery or NSIS', phases: [] };
  try {
    const runDir = fs.mkdtempSync(path.join(locations.root, 'sqlite-probe-'));
    report.runDir = runDir;
    for (const directory of ['appdata', 'localappdata', 'home', 'profile', 'logs', 'cache', 'temp']) {
      fs.mkdirSync(path.join(runDir, directory));
    }
    const source = fs.readFileSync(path.join(__dirname, 'electron-main.cjs'));
    const probe = path.join(runDir, 'electron-main.cjs');
    fs.writeFileSync(probe, source, { flag: 'wx', mode: 0o600 });
    const probeSha256 = digest(source);
    const expected = { dbPath: path.join(runDir, 'canary.sqlite'), canary: crypto.randomBytes(32).toString('hex'),
      nonce: crypto.randomBytes(32).toString('hex'), probeSha256 };
    report.probeSha256 = probeSha256;
    for (const phase of ['write', 'read']) {
      if (digest(fs.readFileSync(probe)) !== probeSha256) throw new Error('Probe changed before launch');
      const receiptPath = path.join(runDir, `${phase}.receipt.json`);
      const execution = await runChild(locations.electron, [probe, '--phase', phase, '--db', expected.dbPath,
        '--canary', expected.canary, '--receipt', receiptPath, '--run-dir', runDir, '--nonce', expected.nonce],
      { cwd: runDir, env: childEnvironment(runDir) }, path.join(runDir, 'logs', phase));
      report.phases.push({ phase, receiptPath, ...execution });
      if (fs.statSync(receiptPath).size > LIMIT) throw new Error('Oversized receipt');
      const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
      report.phases.at(-1).receipt = receipt;
      validateReceipt(receipt, execution, { ...expected, phase });
      if (digest(fs.readFileSync(probe)) !== probeSha256) throw new Error('Probe changed during execution');
      if (receipt.status !== 'PASS') {
        report.status = receipt.status;
        report.reason = receipt.reason;
        break;
      }
      if (phase === 'read') {
        if (report.phases[0].pid === execution.pid) throw new Error('Reopen requires distinct process PIDs');
        report.status = 'PASS';
        report.nativeElectron = true;
      }
    }
  } catch (error) {
    report.status = 'ERROR';
    report.reason = String(error.message).slice(0, 1024);
  }
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ status: report.status, capability: reportPath }));
  return report.status === 'PASS' ? 0 : report.status === 'BLOCKED' ? 78 : 1;
}

module.exports = { parseArgs, physicalPath, inside, validatePaths, childEnvironment, validateReceipt, main };
if (require.main === module) main().then(code => { process.exitCode = code; }).catch(error => {
  console.error(JSON.stringify({ status: 'ERROR', reason: String(error.message).slice(0, 1024) }));
  process.exitCode = 1;
});
