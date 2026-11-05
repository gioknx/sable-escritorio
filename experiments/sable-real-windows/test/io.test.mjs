import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { asarPackageVersion } from '../lib/asar.mjs';
import { builderConfig, checkFuses, readFuses, verifyRecipe, verifySource } from '../lib/build.mjs';
import { PublicEvidence, secretScan } from '../lib/evidence.mjs';
import { compareInventory, hashFile, inventory } from '../lib/inventory.mjs';
import { CONSOLIDATED_LAYOUT, NATIVE, PRE_0015_BUILDER_YML, SOURCE_PINS, UPDATES_RESOURCE } from '../lib/pins.mjs';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SQLITE_CHECK_PY, generateSecrets, homeserverConfig, registrationMac, secretValues, validateDatabaseEvidence } from '../lib/synapse.mjs';
import { main } from '../driver.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const temp = () => mkdtempSync(join(tmpdir(), 'sable-wt-'));
// Provas e fonte reais da mãe (somente leitura). Ausentes => o teste falha, não pula.
const PROOF = process.env.SABLE_PROOF_ROOT ?? '/home/gio/mind/run/sable-ronald-20261102/sable-real-source-proof-20261104';
const SOURCE = process.env.SABLE_SOURCE_ROOT ?? '/home/gio/mind/run/sable-ronald-20261102/download-fonte';

test('driver outside Windows: BLOCKED exit 78 as a real process', () => {
  const r = spawnSync(process.execPath, [join(here, '..', 'driver.mjs')], { encoding: 'utf8' });
  assert.equal(r.status, 78);
  assert.equal(JSON.parse(r.stdout).status, 'BLOCKED');
  assert.equal(JSON.parse(r.stdout).nativeAuthorization, false);
});
test('driver on win32 with missing inputs: ERROR before touching anything', async () => {
  assert.equal(await main(['--out', 'C:\\o'], 'win32', 'x64'), 1);
});

test('asar: reads package.json of the published app.asar (real bytes)', () => {
  const asar = join(PROOF, 'published-selected/resources/app.asar');
  assert.equal(hashFile(asar), '9637cca0b6c6dde82c3a173169638729bc2919a063486caca6408dc147a25585');
  assert.deepEqual(asarPackageVersion(asar), { version: '2.2.1', main: 'dist/main.cjs', name: '@sable/electron' });
  for (const [name, sha] of Object.entries(NATIVE)) {
    assert.equal(hashFile(join(PROOF, 'published-selected/resources/app.asar.unpacked/dist', `${name}.node`)), sha);
  }
});

// O snapshot de leitura é pré-0015 e sem workspace electron/ instalado: os demais pins batem e cada falta é
// recusada com erro concreto. No Windows a mãe entrega a fonte consolidada e instalada.
test('real pre-0015 source: only 0015 consolidation and tool installation are refused', async () => {
  const r = await verifySource(SOURCE);
  assert.deepEqual(r.problems, ['pin drift electron/electron-builder.yml',
    ...['electron-builder 26.18.0', 'electron-updater 6.8.11', 'esbuild 0.28.2', 'electron 45.0.0']
      .map(s => s.split(' ')).map(([n, v]) => `electron/node_modules/${n} version null != ${v}`),
    '0015 layout missing electron/src/update-runtime-modules.d.ts',
    ...['policy', 'store', 'update-auth', 'bootstrap'].map(n => `0015 layout missing electron/desktop-update/runtime/${n}.cjs`),
    '0015 main.ts pending-update guard absent']);
});

test('post-0015 builder yml pin equals the mother generator applied to the real original', async () => {
  const original = join(SOURCE, 'electron/electron-builder.yml');
  assert.equal(hashFile(original), PRE_0015_BUILDER_YML);
  const { builderSource } = await import(join(here, '../../gerar-patch-desktop-update.mjs'));
  const patched = builderSource(readFileSync(original, 'utf8'));
  assert.equal(createHash('sha256').update(patched).digest('hex'), SOURCE_PINS['electron/electron-builder.yml']);
  assert.match(patched, /- from: \.\n {4}to: \.\n {4}filter:\n {6}- mindtech-updates\.json/);
  assert.equal(UPDATES_RESOURCE, 'electron/mindtech-updates.json');
});

test('inventory: full compare, NSIS extras only by name, links refused', () => {
  const a = temp(), b = temp();
  try {
    for (const d of [a, b]) { mkdirSync(join(d, 'resources')); writeFileSync(join(d, 'resources/app.asar'), 'x'); writeFileSync(join(d, 'Sable.exe'), 'e'); }
    writeFileSync(join(b, 'Uninstall Sable.exe'), 'u');
    assert.equal(compareInventory(inventory(a), inventory(b), ['Uninstall Sable.exe']).equal, true);
    writeFileSync(join(b, 'resources/app.asar'), 'y');
    assert.deepEqual(compareInventory(inventory(a), inventory(b), ['Uninstall Sable.exe']).changed, ['resources/app.asar']);
    writeFileSync(join(b, 'other.dll'), 'o');
    assert.deepEqual(compareInventory(inventory(a), inventory(b), ['Uninstall Sable.exe']).extra, ['other.dll']);
    symlinkSync(join(a, 'Sable.exe'), join(b, 'link'));
    assert.throws(() => inventory(b), /link refused/);
  } finally { rmSync(a, { recursive: true }); rmSync(b, { recursive: true }); }
});

test('fuses: wire parse and after-pack expectations', () => {
  const wire = s => Buffer.concat([Buffer.from('xxdL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), Buffer.from([1, s.length]), Buffer.from(s), Buffer.from('yy')]);
  assert.deepEqual(checkFuses(readFuses(wire('01001100'))), []);
  assert.deepEqual(checkFuses(readFuses(wire('11001100'))), ['fuse 0']);
  assert.throws(() => readFuses(Buffer.from('none')), /sentinel/);
});

test('builder config extends the original stable config; NSIS-only comes from CLI', () => {
  const c = builderConfig('C:\\s', { version: '2.2.2', output: 'C:\\o', updatesJson: 'C:\\k\\u.json', electronZip: 'C:\\e.zip' });
  assert.match(c.extends, /^file:.*electron-builder\.stable\.yml$/);
  assert.deepEqual(c.extraMetadata, { version: '2.2.2', main: 'dist/ensaio-entry.cjs' });
  assert.equal(c.electronVersion, '45.0.0');
  assert.equal(c.appId, undefined); assert.equal(c.afterPack, undefined); assert.equal(c.asar, undefined);
  assert.equal(c.win, undefined); assert.equal(c.extraResources, undefined);
});

test('recipe: native bytes must be the published pins; wrong recipe is refused with concrete problems', () => {
  const r = temp(), s = temp();
  try {
    writeFileSync(join(s, 'a.ts'), 'a');
    const native = Object.fromEntries(Object.keys(NATIVE).map(n => [n, { path: join(PROOF, 'published-selected/resources/app.asar.unpacked/dist', `${n}.node`), sha256: NATIVE[n] }]));
    for (const rel of CONSOLIDATED_LAYOUT) { mkdirSync(dirname(join(s, rel)), { recursive: true }); writeFileSync(join(s, rel), rel); }
    const listed = ['a.ts', ...CONSOLIDATED_LAYOUT].map(path => ({ path, sha256: hashFile(join(s, path)) }));
    const base = { schema: 1, patch: { name: '0015', sha256: 'a'.repeat(64) }, nativeModules: native,
      frontendInputs: [{ path: 'a.ts', sha256: hashFile(join(s, 'a.ts')) }], sourceFiles: listed };
    writeFileSync(join(r, 'recipe.json'), JSON.stringify(base));
    assert.deepEqual(verifyRecipe(r, s).problems, []);
    rmSync(join(r, 'recipe.json'));
    writeFileSync(join(r, 'recipe.json'), JSON.stringify({ ...base, sourceFiles: listed.filter(f => !f.path.endsWith('bootstrap.cjs')) }));
    assert.deepEqual(verifyRecipe(r, s).problems, ['sourceFiles lacks 0015 electron/desktop-update/runtime/bootstrap.cjs']);
    rmSync(join(r, 'recipe.json'));
    writeFileSync(join(r, 'recipe.json'), JSON.stringify({ ...base, nativeModules: { ...native, sable_node: { path: join(s, 'a.ts'), sha256: NATIVE.sable_node } } }));
    assert.deepEqual(verifyRecipe(r, s).problems, ['native sable_node bytes differ']);
  } finally { rmSync(r, { recursive: true }); rmSync(s, { recursive: true }); }
});

test('evidence: allowlist, per-run secrets in utf8/utf16, generic token patterns, audit removes strays', () => {
  const out = temp();
  try {
    const secrets = generateSecrets(), e = new PublicEvidence(out);
    e.registerSecrets(secretValues(secrets));
    assert.throws(() => e.write('profile.json', {}), /allowlist/);
    assert.throws(() => e.write('seed.json', { x: secrets.password }), /secret scan/);
    assert.ok(secretScan(Buffer.from(`a${secrets.registrationSharedSecret}`, 'utf16le'), secretValues(secrets)).length);
    assert.ok(secretScan(Buffer.from('{"access_token": "abc"}'), []).length);
    assert.ok(secretScan(Buffer.from('syt_ZW5zYWlv_abcdefghijkl'), []).length);
    e.write('seed.json', { userId: '@ensaio-1:escritorio.localhost' });
    writeFileSync(join(out, 'stray.txt'), 'x');
    assert.deepEqual(e.audit(), ['stray.txt']);
    assert.deepEqual(readdirSync(out), ['seed.json']);
  } finally { rmSync(out, { recursive: true }); }
});

test('synapse: loopback-only listener, federation off, registration MAC equals Python hmac', () => {
  const s = generateSecrets(), c = homeserverConfig(s, '/var/lib/x');
  assert.deepEqual(c.listeners.map(l => [l.bind_addresses, l.resources.flatMap(r => r.names)]), [[['127.0.0.1'], ['client']]]);
  assert.deepEqual(c.federation_domain_whitelist, []); assert.equal(c.enable_registration, false);
  const py = execFileSync('python3', ['-c', 'import hmac,hashlib,sys; k,n,u,p=sys.argv[1:5]; print(hmac.new(k.encode(), b"\\x00".join([n.encode(),u.encode(),p.encode(),b"notadmin"]), hashlib.sha1).hexdigest())',
    s.registrationSharedSecret, 'nonce123', s.username, s.password], { encoding: 'utf8' }).trim();
  assert.equal(registrationMac(s.registrationSharedSecret, 'nonce123', s.username, s.password), py);
});

test('synapse sqlite check runs in Python against Synapse-named tables and detects plaintext', () => {
  const d = temp();
  try {
    const db = join(d, 'homeserver.db');
    execFileSync('python3', ['-c', `import sqlite3,json,sys
c=sqlite3.connect(sys.argv[1])
c.executescript("create table events(event_id text, type text, room_id text); create table event_json(event_id text, room_id text, json text); create table current_state_events(event_id text, room_id text, type text, state_key text); create table devices(user_id text, device_id text, hidden boolean default 0);")
c.execute("insert into events values('$e','m.room.encrypted','!r')"); c.execute("insert into event_json values('$e','!r',?)",(json.dumps({'sender':'@u:x','content':{'algorithm':'m.megolm.v1.aes-sha2','ciphertext':'zz'}}),))
c.execute("insert into events values('$s','m.room.encryption','!r')"); c.execute("insert into event_json values('$s','!r',?)",(json.dumps({'content':{'algorithm':'m.megolm.v1.aes-sha2'}}),))
c.execute("insert into current_state_events values('$s','!r','m.room.encryption','')"); c.execute("insert into devices values('@u:x','DEV',0)"); c.execute("insert into devices values('@u:x','MASTERKEY',1)")
c.commit()`, db]);
    const out = JSON.parse(execFileSync('python3', ['-c', SQLITE_CHECK_PY], { input: JSON.stringify([db, '!r', '$e', '@u:x', 'canary-abc']), encoding: 'utf8' }));
    assert.deepEqual(validateDatabaseEvidence(out, { userId: '@u:x', deviceId: 'DEV' }), { ok: true, problems: [] });
    execFileSync('python3', ['-c', 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("insert into devices values(\'@u:x\',\'NEW\',0)"); c.execute("create table t(x text)"); c.execute("insert into t values(\'canary-abc\')"); c.commit()', db]);
    const leaked = JSON.parse(execFileSync('python3', ['-c', SQLITE_CHECK_PY], { input: JSON.stringify([db, '!r', '$e', '@u:x', 'canary-abc']), encoding: 'utf8' }));
    assert.deepEqual(validateDatabaseEvidence(leaked, { userId: '@u:x', deviceId: 'DEV' }).problems,
      ['canary plaintext present in server database', 'device set is not exactly the Sable device']);
  } finally { rmSync(d, { recursive: true }); }
});

test('feed: real desktop-update bootstrap/Policy accept our signed envelope over HTTPS with a separate CA', () => {
  const runtime = join(here, '../../desktop-update/runtime/bootstrap.cjs');
  assert.ok(existsSync(join(here, '../../desktop-update/node_modules/semver/package.json')), 'npm ci in ../desktop-update first');
  const d = temp();
  try {
    const r = spawnSync(process.execPath, [join(here, 'feed-child.mjs'), d, runtime], { encoding: 'utf8', timeout: 60000,
      env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: join(d, 'ca.pem'), SABLE_FEED_CHILD: '1' } });
    assert.equal(r.status, 0, r.stderr.slice(-2000));
    const result = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.deepEqual(result, { initialised: true, latest: '2.2.3', resourceKeys: 'channel,feedURL,publicKey,schema', tamperedBytes: true });
  } finally { rmSync(d, { recursive: true }); }
});
