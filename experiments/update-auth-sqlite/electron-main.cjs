'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class Blocked extends Error {
  constructor(message) { super(message); this.name = 'Blocked'; }
}

function assertRuntime(runtime) {
  if (runtime.type !== 'browser' || runtime.versions.electron !== '45.0.0' ||
      runtime.platform !== 'win32' || runtime.arch !== 'x64') {
    throw new Blocked('Requires real Electron 45.0.0 Windows x64 browser main');
  }
}

function assertSQLiteVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  const parts = match && match.slice(1).map(Number);
  if (!parts || parts[0] < 3 ||
      (parts[0] === 3 && (parts[1] < 51 || (parts[1] === 51 && parts[2] < 3)))) {
    throw new Blocked(`SQLite ${version}: requires >=3.51.3 (WAL-reset fix)`);
  }
}

function scalar(db, sql) { return Object.values(db.prepare(sql).get())[0]; }

function configure(db) {
  db.exec('PRAGMA busy_timeout=1000; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
  const result = {
    journal_mode: scalar(db, 'PRAGMA journal_mode'),
    synchronous: scalar(db, 'PRAGMA synchronous'),
    locking_mode: scalar(db, 'PRAGMA locking_mode'),
    busy_timeout: scalar(db, 'PRAGMA busy_timeout'),
  };
  if (result.journal_mode !== 'wal' || result.synchronous !== 2 ||
      result.locking_mode !== 'exclusive' || result.busy_timeout !== 1000) {
    throw new Error('SQLite pragma readback mismatch');
  }
  return result;
}

// UNIT exports exercise storage only; no exported function can declare native PASS.
function exerciseDatabase(DatabaseSync, { phase, dbPath, canary }, evidence = {}) {
  if (!['write', 'read'].includes(phase) || !/^[a-f0-9]{64}$/.test(canary)) {
    throw new Error('Invalid database phase/canary');
  }
  if (phase === 'write') {
    const fd = fs.openSync(dbPath, 'wx', 0o600);
    fs.closeSync(fd);
  } else if (!fs.lstatSync(dbPath).isFile() || fs.lstatSync(dbPath).isSymbolicLink()) {
    throw new Error('Read requires existing regular database');
  }
  const db = new DatabaseSync(dbPath, { timeout: 1000, readOnly: phase === 'read', allowExtension: false });
  try {
    const sqliteVersion = scalar(db, 'SELECT sqlite_version()');
    const compileOptions = db.prepare('PRAGMA compile_options').all().map(row => Object.values(row)[0]);
    Object.assign(evidence, { sqliteVersion, compileOptions });
    assertSQLiteVersion(sqliteVersion);
    const pragmas = configure(db);
    if (phase === 'write') {
      db.exec('CREATE TABLE canary (id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL); BEGIN IMMEDIATE;');
      try {
        db.prepare('INSERT INTO canary (id, value) VALUES (1, ?)').run(canary);
        db.exec('COMMIT');
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch { /* Preserve original transaction failure. */ }
        throw error;
      }
    }
    if (scalar(db, 'PRAGMA integrity_check') !== 'ok') throw new Error('Database integrity check failed');
    const rows = db.prepare('SELECT id, value FROM canary').all();
    if (rows.length !== 1 || rows[0].id !== 1 || rows[0].value !== canary) {
      throw new Error('Canary mismatch');
    }
    return { sqliteVersion, compileOptions, pragmas, canary: rows[0].value };
  } finally {
    db.close();
  }
}

function parseProbeArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!['--phase', '--db', '--canary', '--receipt', '--run-dir', '--nonce'].includes(key) ||
        result[key] !== undefined || !argv[i + 1] || argv[i + 1].startsWith('--')) {
      throw new Error('Invalid probe arguments');
    }
    result[key] = argv[i + 1];
  }
  if (Object.keys(result).length !== 6) throw new Error('Missing probe arguments');
  return result;
}

function runtimeInfo() {
  return { type: process.type || null, versions: { ...process.versions }, platform: process.platform, arch: process.arch };
}

function configureAppPaths(app, runDir) {
  if (app.isReady()) throw new Error('App paths must be configured before ready');
  for (const [name, directory] of Object.entries({
    home: 'home', appData: 'appdata', userData: 'profile', sessionData: 'cache',
    temp: 'temp', logs: 'logs',
  })) app.setPath(name, path.join(runDir, directory));
  // Electron has no getPath/setPath('cache'); sessionData owns disk cache.
  app.disableHardwareAcceleration();
}

async function main(argv = process.argv.slice(2)) {
  const args = parseProbeArgs(argv);
  const runtime = runtimeInfo();
  const receipt = {
    schemaVersion: 1, phase: args['--phase'], pid: process.pid,
    nonce: args['--nonce'], dbPath: args['--db'], runtime,
    probeSha256: crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
  };
  let app;
  let exitCode = 1;
  try {
    assertRuntime(runtime);
    app = require('electron').app;
    configureAppPaths(app, args['--run-dir']);
    await app.whenReady();
    let DatabaseSync;
    try { ({ DatabaseSync } = require('node:sqlite')); }
    catch (error) {
      if (error.code === 'ERR_UNKNOWN_BUILTIN_MODULE' || error.code === 'MODULE_NOT_FOUND') {
        throw new Blocked('node:sqlite unavailable in this Electron main');
      }
      throw error;
    }
    if (typeof DatabaseSync !== 'function') throw new Blocked('node:sqlite DatabaseSync unavailable');
    Object.assign(receipt, exerciseDatabase(DatabaseSync, {
      phase: args['--phase'], dbPath: args['--db'], canary: args['--canary'],
    }, receipt), { status: 'PASS' });
    exitCode = 0;
  } catch (error) {
    receipt.status = error instanceof Blocked ? 'BLOCKED' : 'ERROR';
    receipt.reason = String(error.message).slice(0, 1024);
    exitCode = error instanceof Blocked ? 78 : 1;
  }
  fs.writeFileSync(args['--receipt'], `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  // The SQLite handle has already closed in finally; no process kill on success.
  if (app) app.exit(exitCode);
  else process.exitCode = exitCode;
}

module.exports = { Blocked, assertRuntime, assertSQLiteVersion, configure, configureAppPaths, exerciseDatabase, parseProbeArgs };
if (require.main === module) main().catch(() => { process.exitCode = 1; });
