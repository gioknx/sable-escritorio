'use strict';
// UNIT ONLY: real Node SQLite, disk, TLS and Ed25519. No Native claim.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { generateKeyPairSync, sign, createHash } = require('node:crypto');
const { fork, spawn } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const assert = require('node:assert/strict');
const test = require('node:test');
const { Policy } = require('./policy.cjs');
const bytes = Buffer.from('UNIT ONLY inert bytes\n');
const hash = b => createHash('sha512').update(b).digest('base64');
const pair = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
let root, server, origin, envelope, responder, serial = 0;
const nonce = 'a'.repeat(64);
const app = { version: '2.2.1' };
const options = directory => ({ directory, nonce, publicKey, channel: 'stable', feedURL: origin + '/manifest' });
const fresh = () => path.join(root, String(++serial));
function signed(changes = {}, key = pair.privateKey) {
  const payload = JSON.stringify({ appId: 'MINDTECH', channel: 'stable', platform: 'win32', arch: 'x64',
    version: '2.2.3', seq: 2, sha512: hash(bytes), size: bytes.length, url: origin + '/update.exe', ...changes });
  return { payload, signature: sign(null, Buffer.from(payload), key).toString('base64') };
}
function dbFile(directory) { return path.join(directory, 'policy.sqlite'); }
async function closedFixture() {
  const directory = fresh(); envelope = signed();
  (await Policy.initialise(options(directory), app)).close();
  return directory;
}
function inspect(directory, run) {
  const db = new DatabaseSync(dbFile(directory));
  try { return run(db); } finally { db.close(); }
}
function launch(input, env = process.env) {
  const settings = { env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], timeout: 12000 };
  const args = ['worker', JSON.stringify(input)];
  const child = input.mode === 'io' ? spawn('prlimit', ['--fsize=32768:32768', '--', process.execPath,
    __filename, ...args], settings) : fork(__filename, args, settings);
  const messages = []; let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  const first = new Promise((resolve, reject) => {
    child.once('message', resolve); child.once('error', reject);
    child.once('exit', () => { if (!messages.length) reject(new Error('No worker handshake: ' + stderr)); });
  });
  // Avoid an unhandled rejection when a caller only needs the exit transcript.
  first.catch(() => {});
  child.on('message', message => messages.push(message));
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0 && !signal) resolve(messages);
      else reject(new Error(`Worker ${child.pid} failed: ${code}/${signal} ${stderr}`));
    });
  });
  return { child, first, done };
}
async function worker() {
  const input = JSON.parse(process.argv[3]);
  let policy;
  const start = performance.now();
  try {
    if (input.mode === 'io') process.on('SIGXFSZ', () => {}); // Observe SQLite I/O error, not process death.
    policy = new Policy(input.options, input.app || app);
    if (input.mode === 'io') {
      let previous, committed = 0;
      for (let attempt = 0; attempt < 32; attempt++) {
        try { previous = await policy.latest(); committed++; }
        catch (error) {
          assert.ok(previous, 'at least one committed info precedes real I/O failure');
          const frame = /store\.cjs:(\d+):\d+/.exec(error.stack);
          const failureLine = frame && fs.readFileSync(path.join(__dirname, 'store.cjs'), 'utf8').split('\n')[Number(frame[1]) - 1].trim();
          assert.match(failureLine || '', /exec\('COMMIT'\)/, 'the real SQLite error must occur at COMMIT');
          assert.throws(() => policy.guard(previous), /closed\/poisoned/);
          await assert.rejects(policy.latest(), /closed\/poisoned/);
          policy.close(); policy.close();
          process.send({ stage: 'io-poisoned', pid: process.pid, committed, code: error.code,
            errcode: error.errcode, message: error.message, failureLine });
          return;
        }
      }
      throw new Error('Resource ceiling did not trigger a real SQLite commit error');
    } else if (input.mode === 'hold') {
      process.send({ stage: 'ready', pid: process.pid });
      await new Promise(resolve => process.once('message', message => { assert.equal(message, 'close'); resolve(); }));
      policy.close();
      process.send({ stage: 'closed', pid: process.pid });
    } else {
      const info = await policy.latest();
      process.send({ stage: 'accepted', seq: policy.guard(info).seq, pid: process.pid,
        frozen: Object.isFrozen(info), elapsed: performance.now() - start });
    }
  } catch (error) {
    process.send({ stage: 'rejected', pid: process.pid, message: error.message,
      code: error.code, errcode: error.errcode, errstr: error.errstr,
      causeCode: error.cause?.code, elapsed: performance.now() - start });
  } finally { if (policy) policy.close(); process.disconnect(); }
}
if (process.argv[2] === 'worker') {
  worker().catch(error => { console.error(error); process.exitCode = 1; });
} else {
  test.before(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-sqlite-unit-'));
    server = https.createServer({ key: fs.readFileSync(process.env.UNIT_TLS_KEY),
      cert: fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS) }, (req, res) => {
      if (responder) responder(req, res); else res.end(JSON.stringify(envelope));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    origin = `https://127.0.0.1:${server.address().port}`;
  });
  test.beforeEach(() => { envelope = signed(); responder = undefined; });
  test.after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  });
  test('transactional signed highwater: seq2/idempotence and rollback rejection preserve state', async () => {
    const directory = fresh();
    envelope = signed({ seq: 1, version: '2.2.2' });
    const policy = await Policy.initialise(options(directory), app);
    envelope = signed();
    try {
      const info = await policy.latest();
      assert.equal(policy.guard(info).seq, 2);
      assert.equal(policy.guard(await policy.latest()).seq, 2);
      for (const changes of [{ seq: 1 }, { seq: 2, version: '2.2.4' },
        { seq: 3, version: '2.2.2' }, { seq: 3, version: '2.2.3' }]) {
        envelope = signed(changes);
        await assert.rejects(policy.latest(), /AUTH: (rollback|sequence)/);
        assert.equal(policy.guard(info).seq, 2);
        envelope = signed();
        assert.equal(policy.guard(await policy.latest()).seq, 2);
      }
    } finally { policy.close(); }
    const db = new DatabaseSync(path.join(directory, 'policy.sqlite'), { readOnly: true });
    try { assert.equal(db.prepare('SELECT payload FROM highwater').get().payload, signed().payload); }
    finally { db.close(); }
  });
  test('invalid signatures, altered payload and all original signed validations reject without mutation', async () => {
    const directory = fresh(), policy = await Policy.initialise(options(directory), app);
    try {
      const info = await policy.latest();
      const candidates = [signed({}, other.privateKey), { payload: signed().payload },
        { ...signed(), payload: signed().payload.replace('2.2.3', '2.2.4') },
        { ...signed(), signature: '!'.repeat(88) }, { ...signed(), extra: true },
        ...[{ appId: 'OTHER' }, { channel: 'beta' }, { platform: 'linux' }, { arch: 'arm64' },
          { version: '2.2.1' }, { version: 'v2.2.3' }, { seq: 0 }, { seq: 1.2 },
          { seq: Number.MAX_SAFE_INTEGER + 1 }, { size: 0 }, { size: 1024 ** 3 + 1 },
          { sha512: 'bad' }, { url: 'https://example.invalid/update.exe' },
          { url: origin + '/update.zip' }, { url: origin + '/update.exe#fragment' },
          { url: origin.replace('https:', 'http:') + '/update.exe' }, { extra: true }].map(c => signed(c))];
      for (const candidate of candidates) {
        envelope = candidate;
        let emitted = false;
        await assert.rejects(policy.latest().then(info => { emitted = true; return info; }));
        assert.equal(emitted, false); assert.equal(policy.guard(info).seq, 2);
        envelope = signed(); assert.equal(policy.guard(await policy.latest()).seq, 2);
      }
    } finally { policy.close(); }
    inspect(directory, db => assert.equal(db.prepare('SELECT payload FROM highwater').get().payload, signed().payload));
  });
  test('freeze/WeakMap, forged and stale metadata, rehash and idempotent close', async () => {
    const directory = fresh(), policy = await Policy.initialise(options(directory), app);
    const artifact = path.join(root, 'artifact'); fs.writeFileSync(artifact, bytes);
    try {
      const info = await policy.latest(), decoded = policy.guard(info);
      for (const value of [info, info.files, info.files[0], decoded]) assert.equal(Object.isFrozen(value), true);
      assert.equal(Reflect.set(info, 'version', '9.0.0'), false);
      assert.equal(Reflect.set(info.files[0], 'sha512', hash(Buffer.from('bad'))), false);
      assert.throws(() => policy.guard({ ...info }), /metadata/);
      policy.rehash(artifact, info);
      fs.writeFileSync(artifact, Buffer.alloc(bytes.length, 88));
      assert.throws(() => policy.rehash(artifact, info), /SHA512/);
      fs.writeFileSync(artifact, bytes.subarray(1));
      assert.throws(() => policy.rehash(artifact, info), /type\/size/);
      fs.writeFileSync(artifact, bytes);
      const link = path.join(root, 'artifact-link'); fs.symlinkSync(artifact, link);
      assert.throws(() => policy.rehash(link, info), /type\/size/);
      envelope = signed({ seq: 3, version: '2.2.4' });
      const next = await policy.latest();
      assert.throws(() => policy.guard(info), /metadata/);
      assert.throws(() => policy.rehash(artifact, info), /metadata/);
      assert.equal(policy.guard(next).seq, 3);
      policy.currentVersion = '2.2.4';
      assert.throws(() => policy.guard(next), /downgrade/);
      await assert.rejects(policy.latest(), /downgrade/);
      policy.close(); policy.close();
      assert.throws(() => policy.guard(next), /closed/);
      await assert.rejects(policy.latest(), /closed/);
    } finally { policy.close(); }
  });
  test('two concurrent latest re-read committed highwater; out-of-order older response fails closed', async () => {
    const policy = await Policy.initialise(options(fresh()), app);
    try {
      const same = await Promise.all([policy.latest(), policy.latest()]);
      assert.equal(policy.guard(same[0]).seq, 2); assert.equal(policy.guard(same[1]).seq, 2);
      const requests = [];
      let ready; const both = new Promise(resolve => { ready = resolve; });
      responder = (_req, res) => { requests.push(res); if (requests.length === 2) ready(); };
      const older = policy.latest(), newer = policy.latest();
      const rejected = assert.rejects(older, /rollback sequence/);
      await both;
      requests[1].end(JSON.stringify(signed({ seq: 4, version: '2.2.5' })));
      const latest = await newer;
      requests[0].end(JSON.stringify(signed({ seq: 3, version: '2.2.4' })));
      await rejected;
      assert.equal(policy.guard(latest).seq, 4);
    } finally { policy.close(); }
  });
  test('close during pending HTTPS prevents metadata publication', async () => {
    const policy = await Policy.initialise(options(fresh()), app);
    let requested; const ready = new Promise(resolve => { requested = resolve; });
    responder = (_req, res) => requested(res);
    const pending = policy.latest();
    const rejected = assert.rejects(pending, /closed/);
    const res = await ready; policy.close(); res.end(JSON.stringify(signed()));
    await rejected;
  });
  test('strict HTTPS: no redirect, status error, max16KiB and payload bound', async () => {
    const policy = await Policy.initialise(options(fresh()), app);
    try {
      for (const handler of [
        (_req, res) => { res.writeHead(302, { location: origin + '/elsewhere' }); res.end(); },
        (_req, res) => { res.writeHead(503); res.end(); },
        (_req, res) => res.end(' '.repeat(16385)),
        (_req, res) => res.end(JSON.stringify({ payload: 'x'.repeat(8192), signature: signed().signature })),
      ]) {
        responder = handler; await assert.rejects(policy.latest());
        responder = undefined; assert.equal(policy.guard(await policy.latest()).seq, 2);
      }
    } finally { policy.close(); }
  });
  test('explicit init verifies before creating absent exclusive tree; interrupted/empty init never recovers', async () => {
    const directory = fresh(); envelope = signed({}, other.privateKey);
    await assert.rejects(Policy.initialise(options(directory), app), /signature/);
    assert.equal(fs.existsSync(directory), false);
    envelope = signed();
    await assert.rejects(Policy.initialise(options(directory), { version: '2.2.3' }), /downgrade/);
    assert.equal(fs.existsSync(directory), false);
    fs.mkdirSync(directory);
    await assert.rejects(Policy.initialise(options(directory), app), /EEXIST/);
    assert.throws(() => new Policy(options(directory), app), /ENOENT/);
    assert.equal(fs.readdirSync(directory).length, 0);
    fs.writeFileSync(dbFile(directory), '');
    assert.throws(() => new Policy(options(directory), app), /empty/);
    assert.equal(fs.statSync(dbFile(directory)).size, 0);
    await assert.rejects(Policy.initialise(options(directory), app), /EEXIST/);
  });
  test('reopen in distinct Node process verifies signature and accepts same origin/seq2 idempotently', async t => {
    const directory = await closedFixture();
    assert.equal(fs.existsSync(dbFile(directory) + '-wal'), false, 'normal close may remove sidecars');
    const [result] = await launch({ options: options(directory) }).done;
    assert.equal(result.stage, 'accepted'); assert.equal(result.seq, 2); assert.equal(result.frozen, true);
    assert.notEqual(result.pid, process.pid); t.diagnostic(JSON.stringify(result));
    // Stored version can equal installed version: reopen alone must still succeed.
    const policy = new Policy(options(directory), { version: '2.2.3' });
    try { await assert.rejects(policy.latest(), /downgrade/); } finally { policy.close(); }
  });
  test('reopen with wrong key/channel/origin/nonce fails without reset', async () => {
    const directory = await closedFixture();
    const before = fs.readFileSync(dbFile(directory));
    for (const changes of [{ publicKey: other.publicKey.export({ type: 'spki', format: 'pem' }) },
      { channel: 'beta' }, { feedURL: 'https://example.invalid/manifest' }, { nonce: 'b'.repeat(64) }]) {
      assert.throws(() => new Policy({ ...options(directory), ...changes }, app));
      assert.deepEqual(fs.readFileSync(dbFile(directory)), before);
    }
    (new Policy(options(directory), app)).close();
  });
  test('TLS trust is real: separate Node without ephemeral CA rejects self-signed server', async () => {
    const directory = await closedFixture();
    const [result] = await launch({ options: options(directory) }, { ...process.env, NODE_EXTRA_CA_CERTS: '' }).done;
    assert.equal(result.stage, 'rejected'); assert.equal(result.message, 'fetch failed');
    assert.match(result.causeCode, /SELF_SIGNED|UNABLE_TO_VERIFY/);
  });
  test('missing/zero/truncated/header-corrupt DB fixtures block reopen unchanged', async () => {
    for (const kind of ['missing', 'zero', 'truncated', 'header']) {
      const directory = await closedFixture(), file = dbFile(directory);
      const original = fs.readFileSync(file);
      assert.equal(original.subarray(0, 16).toString(), 'SQLite format 3\0');
      if (kind === 'missing') fs.unlinkSync(file);
      if (kind === 'zero') fs.truncateSync(file, 0);
      if (kind === 'truncated') fs.truncateSync(file, 64);
      if (kind === 'header') {
        const altered = Buffer.from(original); altered.fill(0x58, 0, 16); fs.writeFileSync(file, altered);
        assert.equal(fs.readFileSync(file).subarray(0, 16).toString(), 'XXXXXXXXXXXXXXXX');
      }
      const before = fs.existsSync(file) ? fs.readFileSync(file) : null;
      if (kind === 'truncated') assert.equal(before.length, 64);
      assert.throws(() => new Policy(options(directory), app));
      assert.equal(fs.existsSync(file), before !== null);
      if (before) assert.deepEqual(fs.readFileSync(file), before);
      await assert.rejects(Policy.initialise(options(directory), app), /EEXIST/);
    }
  });
  test('complete schema/cardinality and highwater signature fixtures reject without repair', async () => {
    const mutations = [
      db => { db.exec('CREATE TABLE extra (x TEXT) STRICT'); assert.ok(db.prepare("SELECT name FROM sqlite_schema WHERE name='extra'").get()); },
      db => { db.exec('CREATE INDEX extra ON highwater(payload)'); assert.ok(db.prepare("SELECT name FROM sqlite_schema WHERE type='index'").get()); },
      db => { db.exec('DELETE FROM highwater'); assert.equal(db.prepare('SELECT count(*) n FROM highwater').get().n, 0); },
      db => { db.exec('DELETE FROM meta'); assert.equal(db.prepare('SELECT count(*) n FROM meta').get().n, 0); },
      db => { db.prepare('UPDATE highwater SET signature=?').run(Buffer.alloc(64).toString('base64')); assert.equal(db.prepare('SELECT signature FROM highwater').get().signature, Buffer.alloc(64).toString('base64')); },
      db => { db.prepare('UPDATE highwater SET payload=?').run(signed({ seq: 99 }).payload); assert.equal(JSON.parse(db.prepare('SELECT payload FROM highwater').get().payload).seq, 99); },
      db => { db.exec('ALTER TABLE highwater ADD COLUMN version TEXT'); assert.equal(db.prepare('PRAGMA table_info(highwater)').all().length, 4); },
      db => { db.exec('PRAGMA ignore_check_constraints=ON; INSERT INTO highwater SELECT 2,payload,signature FROM highwater'); assert.equal(db.prepare('SELECT count(*) n FROM highwater').get().n, 2); },
    ];
    for (const mutate of mutations) {
      const directory = await closedFixture(); inspect(directory, mutate);
      const before = fs.readFileSync(dbFile(directory));
      assert.throws(() => new Policy(options(directory), app));
      assert.deepEqual(fs.readFileSync(dbFile(directory)), before);
    }
  });
  test('real directory/DB/sidecar links are rejected without following or deleting them', async () => {
    const directory = await closedFixture();
    const alias = fresh(); fs.symlinkSync(directory, alias, 'junction');
    assert.equal(fs.lstatSync(alias).isSymbolicLink(), true);
    assert.throws(() => new Policy(options(alias), app), /link|nonphysical/);
    assert.throws(() => new Policy(options(path.join(alias, 'nested')), app), /link|nonphysical/);
    const target = path.join(root, 'linked-db'); fs.renameSync(dbFile(directory), target);
    fs.symlinkSync(target, dbFile(directory));
    assert.throws(() => new Policy(options(directory), app), /link/);
    assert.equal(fs.lstatSync(dbFile(directory)).isSymbolicLink(), true);
    fs.unlinkSync(dbFile(directory)); fs.renameSync(target, dbFile(directory));
    fs.linkSync(dbFile(directory), target);
    assert.equal(fs.statSync(dbFile(directory)).nlink, 2);
    assert.throws(() => new Policy(options(directory), app), /hard link/);
    fs.unlinkSync(target);
    for (const suffix of ['-wal', '-shm', '-journal']) {
      const side = dbFile(directory) + suffix; fs.symlinkSync(dbFile(directory), side);
      assert.equal(fs.lstatSync(side).isSymbolicLink(), true);
      assert.throws(() => new Policy(options(directory), app), /link/);
      assert.equal(fs.lstatSync(side).isSymbolicLink(), true);
      fs.unlinkSync(side); // Fixture cleanup only, never an operational SQLite recovery.
    }
    (new Policy(options(directory), app)).close();
  });
  test('real exclusive transaction: holder handshake, bounded SQLITE_BUSY, then reopen after close', async t => {
    const directory = await closedFixture();
    const holder = launch({ options: options(directory), mode: 'hold' });
    try {
      const ready = await holder.first;
      assert.equal(ready.stage, 'ready'); assert.notEqual(ready.pid, process.pid);
      const [blocked] = await launch({ options: options(directory) }).done;
      assert.equal(blocked.stage, 'rejected'); assert.equal(blocked.errcode, 5);
      assert.equal(blocked.code, 'ERR_SQLITE_ERROR'); assert.match(blocked.message, /locked/);
      assert.notEqual(blocked.pid, ready.pid); assert.ok(blocked.elapsed < 5000);
      holder.child.send('close');
      const held = await holder.done; assert.equal(held[1].stage, 'closed');
      const [after] = await launch({ options: options(directory) }).done;
      assert.equal(after.stage, 'accepted'); assert.equal(after.seq, 2);
      t.diagnostic(JSON.stringify({ holder: ready, blocked, after }));
    } finally {
      if (holder.child.connected) holder.child.send('close');
      await holder.done;
    }
  });
  test('real resource-limited WAL commit I/O failure poisons instance before emitting info', async t => {
    const directory = await closedFixture();
    let sequence = 2;
    responder = (_req, res) => {
      res.end(JSON.stringify(signed({ seq: sequence, version: `2.2.${sequence + 1}` })));
      sequence++;
    };
    const [result] = await launch({ options: options(directory), mode: 'io' }).done;
    assert.equal(result.stage, 'io-poisoned');
    assert.equal(result.code, 'ERR_SQLITE_ERROR'); assert.equal(result.errcode & 255, 10);
    assert.match(result.message, /I\/O/); assert.ok(result.committed > 0);
    t.diagnostic(JSON.stringify(result));
  });
  test('store verifies candidates in transaction before any write and preserves state on rejection', async () => {
    const directory = await closedFixture();
    const verifier = new Policy(options(directory), app); verifier.close();
    const { Store } = require('./store.cjs');
    const store = new Store(options(directory), value => verifier.decode(value));
    try {
      assert.throws(() => store.advance(signed({}, other.privateKey), () => {}), /signature/);
      assert.equal(store.snapshot.payload, signed().payload);
    } finally { store.close(); }
  });
  test('runtime version evidence; runner rejects empty/skipped/cancelled/old TAP', t => {
    const db = new DatabaseSync(':memory:');
    try { t.diagnostic(JSON.stringify({ node: process.version, sqlite: db.prepare('SELECT sqlite_version() v').get().v })); }
    finally { db.close(); }
    const { completeTAP } = require('./run-unit.cjs');
    const tap = 'TAP version 13\n1..17\n# tests 17\n# pass 17\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
    assert.equal(completeTAP(tap), true);
    const old14 = tap.replaceAll('17', '14');
    for (const broken of ['', old14, tap.replace('# skipped 0', '# skipped 1'), tap.replace('# cancelled 0', '# cancelled 1'),
      tap.replace('# tests 17', '# tests 0'), tap.replace('# todo 0\n', ''), tap.replace('1..17', '1..14'),
      tap.replace('TAP version 13\n', ''), tap + '# pass 17\n']) assert.equal(completeTAP(broken), false);
  });
}
