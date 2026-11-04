// UNIT do wrapper de ensaio sem Electron: validação de ensaio-launch.json, --updated, env privado, testemunha
// e fronteira TLS real em Node (tls.setDefaultCACertificates). Não é prova Native.
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { loadLaunch, writeWitness, KEYS } = createRequire(import.meta.url)('../entry/ensaio-launch.cjs');
const sha = b => createHash('sha256').update(b).digest('hex');
const ssl = (...args) => execFileSync('openssl', args, { stdio: 'ignore' });

function makeCa(dir, name) {
  ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', `/CN=${name}`,
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-keyout', join(dir, `${name}.key`), '-out', join(dir, `${name}.pem`));
  return join(dir, `${name}.pem`);
}
function makeLeaf(dir, ca, name) {
  const k = s => join(dir, `${name}.${s}`);
  ssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', k('key'), '-out', k('csr'));
  writeFileSync(k('ext'), 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n');
  ssl('x509', '-req', '-in', k('csr'), '-CA', join(dir, `${ca}.pem`), '-CAkey', join(dir, `${ca}.key`), '-CAcreateserial',
    '-days', '1', '-extfile', k('ext'), '-out', k('pem'));
  return { key: readFileSync(k('key')), cert: readFileSync(k('pem')) };
}

// Layout igual ao do driver: <root>\i\Sable.exe, <root>\ensaio-launch.json, p\roaming com marcador.
function layout() {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), 'se-')));
  for (const d of ['i', 'p', 'p/home', 'p/roaming', 'p/local', 'p/temp', 'k']) mkdirSync(join(root, d));
  const nonce = 'a1'.repeat(16);
  writeFileSync(join(root, 'p/roaming/.sable-ensaio-root'), nonce);
  const caPem = makeCa(join(root, 'k'), 'ca');
  const value = { schema: 1, nonce, root, appData: join(root, 'p/roaming'), localAppData: join(root, 'p/local'),
    home: join(root, 'p/home'), temp: join(root, 'p/temp'), caPem, caSha256: sha(readFileSync(caPem)), cdpPort: 9301, cdpPortUpdated: 9302 };
  const write = v => { rmSync(join(root, 'ensaio-launch.json'), { force: true }); writeFileSync(join(root, 'ensaio-launch.json'), JSON.stringify(v)); };
  write(value);
  return { root, value, write, exe: join(root, 'i', 'Sable.exe'), done: () => rmSync(root, { recursive: true, force: true }) };
}

test('launch: valid file gives private env, seed port without --updated and updated port only with genuine --updated', () => {
  const l = layout();
  try {
    const seed = loadLaunch(l.exe, [l.exe]);
    assert.equal(seed.updated, false); assert.equal(seed.cdpPort, 9301);
    assert.deepEqual(seed.env, { USERPROFILE: l.value.home, HOME: l.value.home, APPDATA: l.value.appData,
      LOCALAPPDATA: l.value.localAppData, TEMP: l.value.temp, TMP: l.value.temp });
    const reopened = loadLaunch(l.exe, [l.exe, '--updated']);
    assert.equal(reopened.updated, true); assert.equal(reopened.cdpPort, 9302);
    assert.equal(loadLaunch(l.exe, [l.exe, '--updated=1']).updated, false);
    assert.equal(loadLaunch(l.exe, ['--updated']).updated, false); // argv[0] não conta
    assert.equal(Object.keys(l.value).sort().join(), KEYS);
  } finally { l.done(); }
});

test('launch: refuses schema, root, nonce/marker, ports, outside/symlink/hardlink paths, CA pin and non-CA certificate', () => {
  const l = layout();
  const refuse = (mutate, re) => { const v = structuredClone(l.value); mutate(v); l.write(v); assert.throws(() => loadLaunch(l.exe, [l.exe]), re); };
  try {
    refuse(v => { v.extra = 1; }, /launch schema/);
    refuse(v => { v.root = `${v.root}x`; }, /launch root/);
    refuse(v => { v.nonce = 'b2'.repeat(16); }, /marker/);
    refuse(v => { v.cdpPortUpdated = v.cdpPort; }, /cdp ports/);
    refuse(v => { v.temp = tmpdir(); }, /inside root/);
    refuse(v => { v.home = `${v.root}/p/../p/home`; }, /absolute canonical/);
    refuse(v => { v.home = 'p/home'; }, /absolute canonical/);
    symlinkSync(join(l.root, 'p/home'), join(l.root, 'p/link'));
    refuse(v => { v.home = join(v.root, 'p/link'); }, /physical path/);
    refuse(v => { v.caSha256 = '0'.repeat(64); }, /ca pin/);
    linkSync(l.value.caPem, join(l.root, 'k', 'hard.pem'));
    refuse(() => {}, /ca regular single-link file/);
    rmSync(join(l.root, 'k', 'hard.pem'));
    const leaf = makeLeaf(join(l.root, 'k'), 'ca', 'leaf');
    writeFileSync(join(l.root, 'k', 'leafonly.pem'), leaf.cert);
    refuse(v => { v.caPem = join(v.root, 'k', 'leafonly.pem'); v.caSha256 = sha(leaf.cert); }, /valid CA/);
    writeFileSync(join(l.root, 'k', 'withkey.pem'), Buffer.concat([readFileSync(l.value.caPem), leaf.key]));
    refuse(v => { v.caPem = join(v.root, 'k', 'withkey.pem'); v.caSha256 = sha(readFileSync(join(v.root, 'k', 'withkey.pem'))); }, /PEM certificate only/);
    l.write(l.value);
    assert.equal(loadLaunch(l.exe, [l.exe]).cdpPort, 9301);
  } finally { l.done(); }
});

test('witness: written once per PID with nonce, argv mode, port and code hashes', () => {
  const l = layout();
  try {
    const code = join(l.root, 'code');
    mkdirSync(code);
    for (const n of ['ensaio-entry.cjs', 'ensaio-launch.cjs', 'main.cjs']) writeFileSync(join(code, n), n);
    const launch = loadLaunch(l.exe, [l.exe, '--updated']);
    const w = writeWitness(launch, { pid: 4242, ppid: 4000, execPath: l.exe, codeDir: code });
    const disk = JSON.parse(readFileSync(join(l.value.appData, 'ensaio-witness', '4242.json'), 'utf8'));
    assert.deepEqual(disk, w);
    assert.equal(w.updated, true); assert.equal(w.cdpPort, 9302); assert.equal(w.nonce, l.value.nonce);
    assert.equal(w.code['main.cjs'], sha('main.cjs'));
    assert.throws(() => writeWitness(launch, { pid: 4242, ppid: 1, execPath: l.exe, codeDir: code }), /EEXIST/);
  } finally { l.done(); }
});

test('TLS boundary in real Node: only the pinned CA becomes trusted, other CA and wrong hostname still rejected', async () => {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'se-tls-')));
  const servers = [];
  try {
    makeCa(dir, 'a'); makeCa(dir, 'b');
    const serve = leaf => new Promise(resolve => { const s = createServer(leaf, (_q, r) => r.end('ok')); servers.push(s); s.listen(0, '127.0.0.1', () => resolve(s.address().port)); });
    const portA = await serve(makeLeaf(dir, 'a', 'la')), portB = await serve(makeLeaf(dir, 'b', 'lb'));
    const run = env => new Promise((resolve, reject) => {
      const c = spawn(process.execPath, [join(here, 'tls-child.cjs'), join(dir, 'a.pem'), `https://127.0.0.1:${portA}/`,
        `https://127.0.0.1:${portB}/`, `https://localhost:${portA}/`], { env: { PATH: process.env.PATH, ...env } });
      let out = '', err = '';
      c.stdout.on('data', d => { out += d; }); c.stderr.on('data', d => { err += d; });
      c.on('close', code => code === 0 ? resolve(JSON.parse(out)) : reject(new Error(err.slice(-1000))));
    });
    const fresh = await run({});
    assert.notEqual(fresh.before, 'ok');
    assert.equal(fresh.first.alreadyPresent, false);
    assert.equal(fresh.second.alreadyPresent, true);
    assert.equal(fresh.second.count, fresh.first.count);
    assert.equal(fresh.fetchA, 'ok'); assert.equal(fresh.httpsA, 'ok');
    assert.match(fresh.fetchB, /UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED|UNABLE_TO_GET_ISSUER/);
    assert.match(fresh.fetchWrongName, /ERR_TLS_CERT_ALTNAME_INVALID/);
    // Seed com NODE_EXTRA_CA_CERTS da mesma CA: dedupe, sem duplicar.
    const seeded = await run({ NODE_EXTRA_CA_CERTS: join(dir, 'a.pem') });
    assert.equal(seeded.before, 'ok'); assert.equal(seeded.first.alreadyPresent, true);
    assert.equal(seeded.fetchA, 'ok'); assert.notEqual(seeded.fetchB, 'ok');
  } finally {
    for (const s of servers) { s.closeAllConnections(); s.close(); }
    rmSync(dir, { recursive: true, force: true });
  }
});

test('wrapper refuses to run without tls.setDefaultCACertificates (never disables verification)', () => {
  const r = spawnSync(process.execPath, ['-e', `const tls=require('node:tls'); delete tls.setDefaultCACertificates;
    const { installCa } = require(${JSON.stringify(join(here, '../entry/ensaio-launch.cjs'))});
    try { installCa({ pem: '', sha256: '', fingerprint256: '' }); console.log('installed'); } catch (e) { console.log(e.message); }`], { encoding: 'utf8' });
  assert.equal(r.stdout.trim(), 'ENSAIO_LAUNCH: tls.setDefaultCACertificates unavailable in this runtime');
});
