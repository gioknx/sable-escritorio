'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const semver = require('../update-auth-windows/node_modules/semver');
const schema = Object.freeze({
  meta: 'CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK (id = 1), schemaVersion INTEGER NOT NULL CHECK (schemaVersion = 1), nonce TEXT NOT NULL) STRICT',
  highwater: 'CREATE TABLE highwater (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL, signature TEXT NOT NULL) STRICT',
});
function demand(ok, reason) { if (!ok) throw new Error(`STORE: ${reason}`); }
function scalar(db, sql) { return Object.values(db.prepare(sql).get())[0]; }
// The assay owns this tree. These checks do NOT provide atomic RW existing-only open
// against an adversary replacing paths between lstat/realpath/open.
function physical(target, directory) {
  const absolute = path.resolve(target);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const component of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const st = fs.lstatSync(current);
    demand(!st.isSymbolicLink(), 'link/junction rejected');
    demand(path.resolve(fs.realpathSync.native(current)) === current, 'nonphysical path');
    demand(current === absolute && !directory ? st.isFile() : st.isDirectory(), 'path type');
    if (current === absolute && !directory) demand(st.nlink === 1, 'hard link rejected');
  }
  return fs.lstatSync(absolute);
}
function paths(directory, existing) {
  demand(typeof directory === 'string' && path.isAbsolute(directory), 'absolute dedicated directory required');
  physical(directory, true);
  const file = path.join(directory, 'policy.sqlite');
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try { physical(file + suffix, false); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  if (existing) demand(physical(file, false).size > 0, 'empty database');
  return file;
}
class Store {
  #db; #verify; #nonce; #snapshot;
  constructor(options, verify, initialEnvelope) {
    demand(typeof options.nonce === 'string' && /^[a-f0-9]{64}$/.test(options.nonce), 'expected nonce required');
    this.#nonce = options.nonce; this.#verify = verify;
    const initial = initialEnvelope !== undefined;
    if (initial) {
      verify(initialEnvelope);
      demand(typeof options.directory === 'string' && path.isAbsolute(options.directory), 'absolute dedicated directory required');
      physical(path.dirname(options.directory), true);
      fs.mkdirSync(options.directory, { mode: 0o700 }); // Exclusive, never recursive/recovery.
    }
    const file = paths(options.directory, !initial);
    if (initial) { const fd = fs.openSync(file, 'wx', 0o600); fs.closeSync(fd); }
    const before = physical(file, false);
    try {
      this.#db = new DatabaseSync(file, { readOnly: false, allowExtension: false, timeout: 1000 });
      const after = physical(file, false);
      demand(before.dev === after.dev && before.ino === after.ino, 'database replaced during open');
      const version = scalar(this.#db, 'SELECT sqlite_version()');
      demand(semver.valid(version) && semver.gte(version, '3.51.3'), 'SQLite >=3.51.3 required');
      this.#db.exec('PRAGMA busy_timeout=1000; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
      demand(scalar(this.#db, 'PRAGMA journal_mode') === 'wal' &&
        scalar(this.#db, 'PRAGMA synchronous') === 2 &&
        scalar(this.#db, 'PRAGMA locking_mode') === 'exclusive' &&
        scalar(this.#db, 'PRAGMA busy_timeout') === 1000, 'pragma readback');
      // A transaction acquires the actual lock; EXCLUSIVE pragma alone is not proof.
      this.#db.exec('BEGIN IMMEDIATE');
      if (initial) {
        this.#db.exec(schema.meta + ';' + schema.highwater);
        this.#db.prepare('INSERT INTO meta VALUES (1, 1, ?)').run(this.#nonce);
        this.#db.prepare('INSERT INTO highwater VALUES (1, ?, ?)').run(initialEnvelope.payload, initialEnvelope.signature);
      }
      this.#snapshot = this.#read();
      this.#db.exec('COMMIT');
      paths(options.directory, true);
    } catch (error) { this.#poison(); throw error; }
  }
  get snapshot() { demand(this.#db, 'closed/poisoned'); return this.#snapshot; }
  #read() {
    const checks = this.#db.prepare('PRAGMA integrity_check').all();
    demand(checks.length === 1 && Object.values(checks[0])[0] === 'ok', 'integrity_check');
    const objects = this.#db.prepare('SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name').all();
    demand(objects.length === 2 && objects.every((row, i) => {
      const name = ['highwater', 'meta'][i];
      return row.type === 'table' && row.name === name && row.tbl_name === name && row.sql === schema[name];
    }), 'complete schema/extra object');
    const tables = this.#db.prepare('PRAGMA table_list').all().filter(row => Object.hasOwn(schema, row.name));
    demand(tables.length === 2 && tables.every(row => row.strict === 1 && row.wr === 0 && row.ncol === 3), 'STRICT tables');
    const meta = this.#db.prepare('SELECT * FROM meta').all();
    demand(meta.length === 1 && meta[0].id === 1 && meta[0].schemaVersion === 1 && meta[0].nonce === this.#nonce, 'meta cardinality/schemaVersion/nonce');
    const high = this.#db.prepare('SELECT * FROM highwater').all();
    demand(high.length === 1 && high[0].id === 1, 'highwater cardinality');
    const envelope = Object.freeze({ payload: high[0].payload, signature: high[0].signature });
    this.#verify(envelope);
    return envelope;
  }
  #rollback() { this.#db.exec('ROLLBACK'); }
  #poison() {
    if (!this.#db) return;
    try { this.#rollback(); } catch { /* Preserve the primary failure. */ }
    const db = this.#db; this.#db = undefined;
    try { db.close(); } catch { /* Preserve the primary failure. */ }
  }
  advance(envelope, accept) {
    demand(this.#db, 'closed/poisoned');
    let high;
    try { this.#db.exec('BEGIN IMMEDIATE'); high = this.#read(); }
    catch (error) { this.#poison(); throw error; }
    // Only candidate-policy rejection before writes can keep this connection usable.
    try { this.#verify(envelope); accept(high); }
    catch (error) {
      try { this.#rollback(); } catch { this.#poison(); }
      throw error;
    }
    try {
      if (envelope.payload !== high.payload || envelope.signature !== high.signature) {
        this.#db.prepare('UPDATE highwater SET payload = ?, signature = ? WHERE id = 1').run(envelope.payload, envelope.signature);
      }
      this.#db.exec('COMMIT');
      this.#snapshot = Object.freeze({ payload: envelope.payload, signature: envelope.signature });
      return this.#snapshot;
    } catch (error) { this.#poison(); throw error; }
  }
  close() {
    if (!this.#db) return;
    const db = this.#db; this.#db = undefined;
    db.close();
  }
}
module.exports = { Store };
