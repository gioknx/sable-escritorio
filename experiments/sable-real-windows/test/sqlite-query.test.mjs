import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SQLITE_CHECK_PY, databaseDiagnostic, validateDatabaseEvidence } from '../lib/synapse.mjs';

const makeDb = String.raw`import json,sqlite3,sys
c=sqlite3.connect(sys.argv[1])
c.executescript('create table events(event_id text, type text, room_id text); create table event_json(event_id text, room_id text, json text); create table current_state_events(event_id text, room_id text, type text, state_key text); create table devices(user_id text, device_id text, hidden boolean);')
for eid,typ,content in [('$known','m.room.encrypted',{'algorithm':'m.megolm.v1.aes-sha2','ciphertext':'ciphertext-only'}),('$state','m.room.encryption',{'algorithm':'m.megolm.v1.aes-sha2'}),('$plain','m.room.message',{'body':'negative plaintext'})]:
 c.execute('insert into events values(?,?,?)',(eid,typ,'!room'))
 c.execute('insert into event_json values(?,?,?)',(eid,'!room',json.dumps({'event_id':eid,'room_id':'!room','type':typ,'sender':'@u:x','content':content})))
c.execute("insert into current_state_events values('$state','!room','m.room.encryption','')")
c.execute("insert into devices values('@u:x','DEV',0)")
c.commit()`;
const expected = { userId: '@u:x', deviceId: 'DEV' };

test('private JSON query: present, absent, changed ID, plaintext, inconsistent tables and broken database', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sable-query-'));
  const db = join(dir, 'homeserver.db'), program = join(dir, 'query.py');
  try {
    writeFileSync(program, SQLITE_CHECK_PY, { mode: 0o600 });
    execFileSync('python3', ['-c', makeDb, db]);
    const run = (id = '$known') => spawnSync('python3', [program], { input: JSON.stringify([db, '!room', id, '@u:x', 'secret-canary-not-in-db']), encoding: 'utf8' });
    const known = run(); assert.equal(known.status, 0, known.stderr);
    const evidence = JSON.parse(known.stdout);
    assert.equal(validateDatabaseEvidence(evidence, expected).ok, true);
    const diagnostic = databaseDiagnostic(evidence, expected);
    assert.equal(diagnostic.identifiersMatch, true);
    for (const forbidden of ['$known', '@u:x', 'ciphertext-only', 'secret-canary']) assert.equal(JSON.stringify(diagnostic).includes(forbidden), false);
    for (const id of ['$absent', 'known', '$known-altered']) {
      const result = run(id); assert.equal(result.status, 0);
      const evidence = JSON.parse(result.stdout);
      assert.equal(evidence.eventFound, false);
      assert.equal(validateDatabaseEvidence(evidence, expected).ok, false);
      assert.equal(evidence.roomEventTypesSeen['m.room.encrypted'], 1);
    }
    const plain = JSON.parse(run('$plain').stdout);
    assert.equal(plain.eventFound, true);
    assert.equal(validateDatabaseEvidence(plain, expected).ok, false);
    execFileSync('python3', ['-c', "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"delete from event_json where event_id='$known'\"); c.commit()", db]);
    const inconsistent = run(); assert.notEqual(inconsistent.status, 0);
    assert.equal(inconsistent.stdout, ''); assert.match(inconsistent.stderr, /queryError/);
    writeFileSync(db, 'not a sqlite database');
    const broken = run(); assert.notEqual(broken.status, 0); assert.equal(broken.stdout, '');
    rmSync(db);
    const missing = run(); assert.notEqual(missing.status, 0); assert.equal(missing.stdout, '');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('legacy shell path changes a dollar event ID; stdin JSON preserves all identifiers', () => {
  const values = ['!room', '$known', '@u:x', "space quote ' dollar $ backslash \\ Unicode ç"];
  const old = execFileSync('sh', ['-c', `python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' !room $known @u:x`], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.notDeepEqual(JSON.parse(old), values.slice(0, 3));
  const received = execFileSync('python3', ['-c', 'import json,sys; print(json.dumps(json.load(sys.stdin)))'], { input: JSON.stringify(values), encoding: 'utf8' });
  assert.deepEqual(JSON.parse(received), values);
});

test('public database diagnostic reports only allowlisted values: private text from any database field never survives', () => {
  const canary = 'private-query-canary-0123456789abcdef', room = '!private-room', user = '@private-user:escritorio.localhost';
  const hostile = { eventFound: true, roomEventTypesSeen: { 'm.room.encrypted': 1, [canary]: 2, [room]: 3 },
    eventType: canary, hasBody: canary, contentAlgorithm: canary, roomEncryption: `${canary}${room}`, sender: user,
    devices: [user], identifiersMatch: canary, databaseConsistent: canary, canaryPlaintextInDatabase: canary };
  const text = JSON.stringify(databaseDiagnostic(hostile, { userId: user, deviceId: 'DEV' }));
  for (const secret of [canary, room, user, '$']) assert.equal(text.includes(secret), false, `${secret} leaked`);
  const diagnostic = JSON.parse(text);
  assert.deepEqual(diagnostic.roomEventTypesSeen, { 'm.room.encrypted': 1, other: 5 });
  assert.deepEqual([diagnostic.eventType, diagnostic.contentAlgorithm, diagnostic.roomEncryption], ['other', 'other', 'other']);
  assert.deepEqual([diagnostic.hasBody, diagnostic.identifiersMatch, diagnostic.databaseConsistent, diagnostic.canaryPlaintextInDatabase], [null, null, null, null]);
  const real = databaseDiagnostic({ eventFound: true, roomEventTypesSeen: { 'm.room.encrypted': 1 }, eventType: 'm.room.encrypted', hasBody: false,
    contentAlgorithm: 'm.megolm.v1.aes-sha2', roomEncryption: 'm.megolm.v1.aes-sha2', identifiersMatch: true, databaseConsistent: true,
    sender: user, devices: ['DEV'], canaryPlaintextInDatabase: false }, { userId: user, deviceId: 'DEV' });
  assert.equal(real.eventType, 'm.room.encrypted'); assert.equal(real.contentAlgorithm, 'm.megolm.v1.aes-sha2'); assert.equal(real.senderMatches, true);
});
