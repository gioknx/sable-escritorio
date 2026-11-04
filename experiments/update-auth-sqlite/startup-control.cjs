'use strict';

// Independent startup diagnostic: no SQLite, probe import, database or capability PASS.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function controlPaths(runDir) {
  if (!path.isAbsolute(runDir)) throw new Error('Absolute control directory required');
  const directory = path.join(runDir, 'logs', 'startup');
  return { directory, nativeLog: path.join(directory, 'chromium.log'), checkpoint: path.join(directory, 'checkpoint.json') };
}

function parseControlArgs(argv, entry, runDir) {
  const index = argv[1] === entry ? 1 : argv[3] === entry ? 3 : -1;
  if (index < 0 || (index === 3 && (argv[1] !== '--enable-logging=file' ||
      argv[2] !== `--log-file=${controlPaths(runDir).nativeLog}`))) throw new Error('Invalid control entry/switches');
  const args = argv.slice(index + 1);
  if (args.length !== 6 || args[0] !== '--phase' || args[1] !== 'startup' ||
      args[2] !== '--run-dir' || args[3] !== runDir || args[4] !== '--nonce' ||
      !/^[a-f0-9]{64}$/.test(args[5])) throw new Error('Invalid control arguments');
  return { nonce: args[5] };
}

function assertControlRuntime(runtime) {
  if (runtime.type !== 'browser' || runtime.versions.electron !== '45.0.0' ||
      runtime.platform !== 'win32' || runtime.arch !== 'x64') {
    const error = new Error('Requires real Electron 45.0.0 Windows x64 browser main');
    error.code = 'CONTROL_BLOCKED';
    throw error;
  }
}

function physicalDirectory(directory) {
  let current = path.parse(directory).root;
  for (const component of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('Unsafe control directory');
  }
}

async function main() {
  const runDir = process.cwd();
  const files = controlPaths(runDir);
  physicalDirectory(files.directory);
  if (__filename !== path.join(runDir, 'startup-control.cjs') || !fs.lstatSync(__filename).isFile() ||
      fs.lstatSync(__filename).isSymbolicLink()) throw new Error('Control must be a local regular copy');
  if (process.argv.length > 16 || process.argv.some(arg => Buffer.byteLength(arg) > 1024) ||
      Buffer.byteLength(JSON.stringify(process.argv)) > 2048) throw new Error('Oversized control argv');
  const record = { schemaVersion: 1, phase: 'startup', stage: 'js-entry', status: 'STARTING',
    pid: process.pid, nonce: /^[a-f0-9]{64}$/.test(process.argv.at(-1)) ? process.argv.at(-1) : null,
    controlSha256: crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
    runtime: { type: process.type || null, versions: { electron: process.versions.electron || null },
      platform: process.platform, arch: process.arch }, requireMain: require.main === module, argv: [...process.argv] };
  const fd = fs.openSync(files.checkpoint, 'wx', 0o600);
  function mark(stage, status = 'STARTING') {
    Object.assign(record, { stage, status });
    const text = JSON.stringify(record);
    if (Buffer.byteLength(text) > 4096) throw new Error('Oversized control mark');
    const bytes = fs.writeSync(fd, text, 0, 'utf8');
    if (bytes !== Buffer.byteLength(text)) throw new Error('Incomplete control mark');
    fs.ftruncateSync(fd, bytes);
  }
  let app;
  let exitCode = 1;
  try {
    // This mark precedes argument parsing and the runtime guard, including Node CLI.
    mark('js-entry');
    parseControlArgs(process.argv, __filename, runDir);
    assertControlRuntime(record.runtime);
    app = require('electron').app;
    mark('electron-loaded');
    if (app.isReady()) throw new Error('Control paths must be configured before ready');
    for (const [name, directory] of Object.entries({ home: 'home', appData: 'appdata', userData: 'profile',
      sessionData: 'cache', temp: 'temp', logs: 'logs' })) app.setPath(name, path.join(runDir, directory));
    app.disableHardwareAcceleration();
    await app.whenReady();
    mark('app-ready', 'READY');
    exitCode = 0;
  } catch (error) {
    exitCode = error.code === 'CONTROL_BLOCKED' ? 78 : 1;
    record.reason = String(error.message).slice(0, 512);
    // Failure of this write propagates: a broken marker cannot certify startup.
    mark(record.stage, exitCode === 78 ? 'BLOCKED' : 'ERROR');
  } finally {
    fs.closeSync(fd);
    if (app) app.exit(exitCode);
    else process.exitCode = exitCode;
  }
}

module.exports = { controlPaths, parseControlArgs, assertControlRuntime };
// No require.main dependency in Electron browser; Node helper imports remain inert.
if (process.type === 'browser' || require.main === module) main().catch(error => {
  console.error(JSON.stringify({ event: 'control-unhandled-error', reason: String(error.message).slice(0, 512) }));
  process.exitCode = 1;
});
