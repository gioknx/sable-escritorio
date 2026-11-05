// UNIT real dos passos de CI do ensaio (ci/fetch-inputs.mjs e ci/windows-steps.mjs) e do driver BLOCKED fora do Windows.
// Sem rede: só regras de URL/redirecionamento recusadas antes de qualquer conexão e fluxos/arquivos reais locais.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { PINNED, PYPI_JSON, checkCipherInputs, fetchPublic, saveVerified, selectWheel } from '../ci/fetch-inputs.mjs';
import { PNPM, auditPublic, checkPnpmLock, checkResult, childEnv, installSource, parseCli, toolchain, writeDiagnostic, writePsScripts } from '../ci/windows-steps.mjs';
import { PUBLIC_FILES } from '../lib/evidence.mjs';
import { ELECTRON, SYNAPSE, WSL_ROOTFS } from '../lib/pins.mjs';
import { REQUIRED } from '../lib/verdict.mjs';
import { PS } from '../lib/windows.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dirs = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), 'sable-ci-')); dirs.push(d); return d; };
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const sha = b => createHash('sha256').update(b).digest('hex');
const code = async p => { try { await p; } catch (e) { return e.code; } return null; };

const URL_OK = 'https://github.com/gioknx/sable-escritorio/releases/download/ensaio-test-1/input.sealed';
test('cipher inputs: exact public release asset URL of this repo, lowercase sha256, bounded size', () => {
  assert.deepEqual(checkCipherInputs({ url: URL_OK, sha256: 'a'.repeat(64), size: '1048576' }), { url: URL_OK, sha256: 'a'.repeat(64), size: 1048576 });
  for (const url of ['http://github.com/gioknx/sable-escritorio/releases/download/t/f', 'https://github.com/other/sable-escritorio/releases/download/t/f',
    'https://github.com/gioknx/sable-escritorio/releases/download/../f', 'https://github.com/gioknx/sable-escritorio/releases/download/t/f?x=1',
    'https://github.com/gioknx/sable-escritorio/releases/latest/download/f', 'https://api.github.com/repos/gioknx/sable-escritorio/releases/assets/1',
    'https://user:pw@github.com/gioknx/sable-escritorio/releases/download/t/f', `${URL_OK}/extra`])
    assert.throws(() => checkCipherInputs({ url, sha256: 'a'.repeat(64), size: '100' }), /cipher url/, url);
  assert.throws(() => checkCipherInputs({ url: URL_OK, sha256: 'A'.repeat(64), size: '100' }), /sha256/);
  for (const size of ['47', '0', '-1', '1e6', '2147483649', '']) assert.throws(() => checkCipherInputs({ url: URL_OK, sha256: 'a'.repeat(64), size }), /size/, size);
});

test('pinned downloads: official URLs and pins from lib/pins.mjs; wheel URL only from PyPI JSON with exact name and digest', () => {
  assert.deepEqual(PINNED.map(p => [p.url, p.sha256, p.file]), [
    [`https://github.com/electron/electron/releases/download/v45.0.0/${ELECTRON.archive}`, ELECTRON.archiveSha256, ELECTRON.archive],
    [WSL_ROOTFS.url, WSL_ROOTFS.sha256, 'ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz']]);
  assert.equal(PYPI_JSON, 'https://pypi.org/pypi/matrix-synapse/1.162.0/json');
  const good = { filename: SYNAPSE.wheel, url: `https://files.pythonhosted.org/packages/aa/bb/${SYNAPSE.wheel}`, digests: { sha256: SYNAPSE.wheelSha256 }, packagetype: 'bdist_wheel' };
  const meta = urls => ({ info: { version: '1.162.0' }, urls });
  assert.equal(selectWheel(meta([{ ...good, filename: 'matrix_synapse-1.162.0.tar.gz' }, good])).url, good.url);
  for (const [m, msg] of [[meta([{ ...good, digests: { sha256: 'f'.repeat(64) } }]), /published sha256/], [meta([{ ...good, url: good.url.replace('https', 'http') }]), /host\/name/],
    [meta([{ ...good, url: `https://evil.example/${SYNAPSE.wheel}` }]), /host\/name/], [meta([good, good]), /listed once/], [meta([]), /listed once/],
    [{ info: { version: '1.161.0' }, urls: [good] }, /version differs/], [{}, /urls absent/]]) assert.throws(() => selectWheel(m), msg);
});

test('fetchPublic refuses non-HTTPS, foreign hosts and embedded credentials before any connection', async () => {
  assert.equal(await code(fetchPublic('http://github.com/x', ['github.com'])), 'url not allowed: github.com');
  assert.equal(await code(fetchPublic('https://evil.example/x', ['github.com'])), 'url not allowed: evil.example');
  assert.equal(await code(fetchPublic('https://u:p@github.com/x', ['github.com'])), 'url not allowed: github.com');
});

test('saveVerified: exact size and sha256 before publish; partial removed; existing destination preserved', async () => {
  const d = temp(), bytes = randomBytes(300000), out = join(d, 'file.bin');
  assert.deepEqual(await saveVerified(Readable.from([bytes.subarray(0, 1000), bytes.subarray(1000)]), out, { sha256: sha(bytes), maxBytes: bytes.length, exactSize: bytes.length }),
    { file: out, sha256: sha(bytes), size: bytes.length });
  assert.ok(readFileSync(out).equals(bytes));
  assert.equal(await code(saveVerified(Readable.from([bytes]), out, { sha256: sha(bytes), maxBytes: bytes.length })), 'output already exists');
  assert.equal(await code(saveVerified(Readable.from([bytes]), join(d, 'a'), { sha256: 'a'.repeat(64), maxBytes: bytes.length })), 'download sha256 differs from pin');
  assert.equal(await code(saveVerified(Readable.from([bytes]), join(d, 'b'), { sha256: sha(bytes), maxBytes: bytes.length - 1 })), 'download over size limit');
  assert.equal(await code(saveVerified(Readable.from([bytes]), join(d, 'c'), { sha256: sha(bytes), maxBytes: bytes.length, exactSize: bytes.length + 1 })), 'download size differs from expected');
  assert.deepEqual(readdirSync(d), ['file.bin']);
});

test('child env for npm/pnpm: Windows base plus private profile; key, tokens and NODE_OPTIONS never pass', () => {
  const env = childEnv({ PATH: '/bin', SystemRoot: 'C:\\Windows', SABLE_TEST_INPUT_KEY: 'k'.repeat(44), GITHUB_TOKEN: 'x', ACTIONS_RUNTIME_TOKEN: 'y',
    NODE_OPTIONS: '--require x', NODE_EXTRA_CA_CERTS: 'ca', npm_config_registry: 'https://evil.example', HTTPS_PROXY: 'p' }, 'C:\\t');
  assert.deepEqual(Object.keys(env).sort(), ['APPDATA', 'COREPACK_ENABLE_NETWORK', 'HOME', 'LOCALAPPDATA', 'PATH', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE', 'npm_config_cache'].sort());
  assert.equal(env.COREPACK_ENABLE_NETWORK, '0');
  assert.ok(env.npm_config_cache.startsWith('C:\\t'));
});

test('pnpm identity: the npm hidden lockfile must carry the pinned integrity for pnpm and the win32-x64 binary package', () => {
  const prefix = temp(), nm = join(prefix, 'node_modules');
  const lock = { packages: { 'node_modules/pnpm': { version: PNPM.version, integrity: PNPM.integrity }, [`node_modules/${PNPM.exe}`]: { version: PNPM.version, integrity: PNPM.exeIntegrity } } };
  mkdirSync(join(nm, 'pnpm'), { recursive: true }); mkdirSync(join(nm, '@pnpm', 'exe.win32-x64'), { recursive: true });
  writeFileSync(join(nm, 'pnpm', 'package.json'), JSON.stringify({ version: PNPM.version }));
  writeFileSync(join(nm, '@pnpm', 'exe.win32-x64', 'package.json'), JSON.stringify({ version: PNPM.version }));
  writeFileSync(join(nm, '.package-lock.json'), JSON.stringify(lock));
  assert.deepEqual(checkPnpmLock(prefix), []);
  lock.packages['node_modules/pnpm'].integrity = 'sha512-other';
  writeFileSync(join(nm, '.package-lock.json'), JSON.stringify(lock));
  assert.deepEqual(checkPnpmLock(prefix), ['install: pnpm identity differs from pin']);
});

test('PowerShell scripts are written verbatim for AST parsing; existing dir refused', () => {
  const d = join(temp(), 'ps');
  assert.deepEqual(writePsScripts(d), Object.keys(PS));
  for (const [name, script] of Object.entries(PS)) assert.equal(readFileSync(join(d, `${name}.ps1`), 'utf8'), script);
  assert.throws(() => writePsScripts(d), { code: 'EEXIST' });
});

test('Windows-only steps refuse elsewhere instead of pretending', async () => {
  assert.equal(await code(toolchain({ platform: 'linux', arch: 'x64', version: 'v24.22.0' })), 'toolchain: requires Windows x64 runner');
  assert.equal(await code(toolchain({ platform: 'win32', arch: 'x64', version: 'v24.20.0' })), 'toolchain: node v24.20.0 != v24.22.0');
  if (process.platform !== 'win32') assert.equal(await code(installSource({ sourceRoot: '/x', tools: '/y' })), 'install: requires Windows x64 Node 24.22.0');
  assert.throws(() => parseCli(['install-source', '--source-root', 'rel', '--tools-dir', '/t']), /absolute/);
  assert.throws(() => parseCli(['result']), /usage/);
});

test('pre-driver diagnostic: only when the driver produced nothing; allowlisted, non-authorizing, enum outcomes', () => {
  const d = temp(), out = join(d, 'out');
  assert.deepEqual(writeDiagnostic(out, { SABLE_STEP_DECRYPT: 'failure', SABLE_STEP_PREPARE: 'skipped', SABLE_STEP_X: '$(evil)', OTHER: 'success' }), { written: true });
  assert.deepEqual(readdirSync(out), ['diagnostics.json']);
  const diag = JSON.parse(readFileSync(join(out, 'diagnostics.json'), 'utf8'));
  assert.deepEqual(diag, { classification: 'PUBLIC_NON_AUTHORIZING_DIAGNOSTIC', nativeAuthorization: false, stage: 'pre-driver', driverStarted: false,
    steps: { decrypt: 'failure', prepare: 'skipped', x: 'unknown' } });
  assert.deepEqual(writeDiagnostic(out, {}), { written: false, reason: 'public output already produced by driver' });
  assert.equal(auditPublic(out).ok, true);
});

test('artifact audit: driver allowlist only, regular single-link files, JSON/PNG shape, secret patterns, 25 MiB total', () => {
  const out = temp();
  writeFileSync(join(out, 'result.json'), '{"status":"ERROR"}');
  writeFileSync(join(out, 'account.png'), Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), randomBytes(64)]));
  const ok = auditPublic(out);
  assert.equal(ok.ok, true); assert.deepEqual(ok.files.map(f => f.name), ['account.png', 'result.json']);
  const check = (setup, pattern) => {
    const o = temp(); writeFileSync(join(o, 'result.json'), '{}'); setup(o);
    const r = auditPublic(o); assert.equal(r.ok, false); assert.ok(r.problems.some(p => pattern.test(p)), r.problems.join('|'));
  };
  check(o => writeFileSync(join(o, 'app.asar'), 'x'), /not allowlisted: app.asar/);
  check(o => writeFileSync(join(o, 'electron.zip'), 'x'), /not allowlisted/);
  check(o => symlinkSync(join(o, 'result.json'), join(o, 'build.json')), /single-link regular file: build.json/);
  check(o => { const priv = join(temp(), 'secret.json'); writeFileSync(priv, '{}'); linkSync(priv, join(o, 'seed.json')); }, /single-link regular file: seed.json/);
  check(o => mkdirSync(join(o, 'chain.json')), /single-link regular file: chain.json/);
  check(o => writeFileSync(join(o, 'build.json'), 'not json'), /not JSON: build.json/);
  check(o => writeFileSync(join(o, 'account.png'), 'GIF89a'), /not PNG/);
  check(o => writeFileSync(join(o, 'seed.json'), JSON.stringify({ password: 'hunter2hunter2' })), /secret pattern: seed.json/);
  check(o => writeFileSync(join(o, 'restore.json'), JSON.stringify({ k: '-----BEGIN PRIVATE KEY-----' })), /secret pattern/);
  check(o => { for (const n of ['build.json', 'seed.json', 'chain.json', 'installed.json']) writeFileSync(join(o, n), `"${'a'.repeat(7 * 1024 * 1024)}"`); }, /total over 25 MiB/);
  assert.throws(() => auditPublic(join(out, 'absent')), /public output absent/);
  assert.ok(PUBLIC_FILES.every(n => /\.(json|png)$/.test(n)));
});

test('result gate reads the driver verdict literally: PASS, nativeAuthorization and every REQUIRED link true', () => {
  const out = temp(), write = r => writeFileSync(join(out, 'result.json'), JSON.stringify(r));
  const pass = { status: 'PASS', nativeAuthorization: true, missing: [], checks: Object.fromEntries(REQUIRED.map(n => [n, true])) };
  write(pass); assert.deepEqual(checkResult(out).problems, []);
  for (const [r, msg] of [[{ ...pass, status: 'ERROR' }, /status ERROR/], [{ ...pass, nativeAuthorization: false }, /nativeAuthorization/],
    [{ ...pass, checks: { ...pass.checks, decryptedSameEvent: false } }, /required decryptedSameEvent/], [{ ...pass, checks: { ...pass.checks, extra: true } }, /unknown check extra/],
    [{ ...pass, missing: ['x'] }, /missing links/], [{ ...pass, cleanupErrors: ['x'] }, /cleanup/], [{ ...pass, refusedArtifacts: ['x'] }, /refused/]]) {
    write(r); assert.ok(checkResult(out).problems.some(p => msg.test(p)), String(msg));
  }
  rmSync(join(out, 'result.json'));
  assert.deepEqual(checkResult(out).problems, ['result.json absent']);
});

test('driver outside Windows with the full workflow argument set: BLOCKED exit 78, no argument problems', () => {
  const args = ['--source-root', 'D:\\a\\_temp\\sr-1-1\\i\\source', '--recipe-root', 'D:\\a\\_temp\\sr-1-1\\i\\recipe',
    '--electron-zip', `D:\\a\\_temp\\sr-1-1\\d\\${ELECTRON.archive}`, '--wsl-rootfs', 'D:\\a\\_temp\\sr-1-1\\d\\ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz',
    '--synapse-wheel', `D:\\a\\_temp\\sr-1-1\\d\\${SYNAPSE.wheel}`, '--out', 'D:\\a\\_temp\\sp-1-1'];
  assert.notEqual(process.platform, 'win32', 'this UNIT is the non-Windows BLOCKED path; never run the real driver here');
  const r = spawnSync(process.execPath, [join(here, '..', 'driver.mjs'), ...args], { encoding: 'utf8' });
  assert.equal(r.status, 78);
  assert.deepEqual(JSON.parse(r.stdout), { status: 'BLOCKED', nativeAuthorization: false,
    reason: 'Requires disposable Windows x64 runner with WSL1; Node UNIT is not Native', argumentProblems: [] });
  assert.equal(existsSync('D:\\a\\_temp\\sp-1-1'), false);
});

test('manual workflow stays bound to the driver allowlist, pinned file names, key scoping and existing action pins', () => {
  const yml = readFileSync(join(here, '..', '..', '..', '.github', 'workflows', 'sable-real-windows.yml'), 'utf8');
  const uploads = [...yml.matchAll(/sp-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}\/([^\s/]+)$/gm)].map(m => m[1]);
  assert.deepEqual(uploads, [...PUBLIC_FILES]);
  for (const file of [ELECTRON.archive, 'ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz', SYNAPSE.wheel]) assert.ok(yml.includes(`'d\\${file}'`), file);
  assert.equal(yml.match(/secrets\./g).length, 1);
  const keyLine = yml.split('\n').findIndex(l => l.includes('secrets.SABLE_TEST_INPUT_KEY'));
  assert.match(yml.split('\n').slice(keyLine - 3, keyLine).join('\n'), /id: decrypt\n\s+env:/);
  assert.ok(!/GITHUB_TOKEN|github\.token|persist-credentials: true|pull_request|push:/.test(yml));
  for (const pin of ['actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02']) assert.ok(yml.includes(pin), pin);
  // Two jobs: the small query-only job and the complete rehearsal; every action in both is pinned by full SHA.
  assert.deepEqual([...yml.matchAll(/uses: (\S+)/g)].map(m => m[1].split('@')[1].length), [40, 40, 40, 40, 40, 40]);
  const queryJob = yml.slice(yml.indexOf('  sable-real-query:'), yml.indexOf('  sable-real:'));
  assert.ok(queryJob.includes('ci/query-only.mjs') && !/secrets\.|cipher|driver\.mjs|electron|install-source/i.test(queryJob), 'query job has no key, private input or Sable build');
  assert.match(yml, /node-version: 24\.22\.0/); assert.match(yml, /timeout-minutes: 45/); assert.match(yml, /runs-on: windows-latest/);
});
