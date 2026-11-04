// UNIT real de ci/prepare-input.mjs: tar.gz reais (GNU tar do sistema, formatos gnu e pax) e cabeçalhos tar
// adversariais escritos byte a byte. Pins sintéticos só pelo parâmetro de prepare(); a CLI usa os pins reais.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { PNPM_PACKAGE_MANAGER, PrepareError, pathProblem, prepare, publicProblems } from '../ci/prepare-input.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dirs = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), 'sable-prep-')); dirs.push(d); return d; };
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const sha = b => createHash('sha256').update(b).digest('hex');

const NODE_BYTES = randomBytes(4096), FOX_BYTES = randomBytes(2048);
const BUILD = Buffer.from('// build.mjs sintético\n'), MAIN = Buffer.from('await preparePendingUpdateBeforeStart();\n'), APP = Buffer.from('export const app = 1;\n');
const LONG = `src/${'deep-directory-name/'.repeat(5)}${'x'.repeat(40)}.ts`; // > 100 chars: GNU 'L' / pax path
const PINS = Object.freeze({
  NATIVE: { sable_node: sha(NODE_BYTES), sable_audiofox: sha(FOX_BYTES) },
  SOURCE_PINS: { 'electron/build.mjs': sha(BUILD) },
  CONSOLIDATED_LAYOUT: ['electron/src/main.ts'],
});

// Árvore lógica do bundle; `tweak` muda o que um caso precisa.
function bundleFiles(tweak = x => x) {
  const source = {
    'package.json': Buffer.from(JSON.stringify({ name: 'sable', packageManager: PNPM_PACKAGE_MANAGER })),
    'pnpm-lock.yaml': Buffer.from("lockfileVersion: '9.0'\n"),
    'electron/build.mjs': BUILD, 'electron/src/main.ts': MAIN, 'src/app.ts': APP, [LONG]: Buffer.from('long\n'),
  };
  const t = tweak({
    source, manifestExtra: [], manifestDrop: [], manifestOverride: {},
    template: {
      schema: 1, patch: { name: '0015-desktop-update.patch', sha256: 'c'.repeat(64) },
      nativeModules: { sable_node: { path: 'native/sable_node.node', sha256: PINS.NATIVE.sable_node },
        sable_audiofox: { path: 'native/sable_audiofox.node', sha256: PINS.NATIVE.sable_audiofox } },
      frontendInputs: [{ path: 'src/app.ts', sha256: sha(APP) }],
      sourceFiles: [{ path: 'electron/src/main.ts', sha256: sha(MAIN) }, { path: 'electron/build.mjs', sha256: sha(BUILD) }],
    },
    native: { 'sable_node.node': NODE_BYTES, 'sable_audiofox.node': FOX_BYTES },
  });
  const files = [];
  for (const [rel, bytes] of Object.entries(t.source)) {
    files.push([`source/${rel}`, bytes]);
  }
  const listed = Object.entries(t.source).filter(([rel]) => !t.manifestDrop.includes(rel))
    .map(([path, bytes]) => ({ path, sha256: sha(bytes), size: bytes.length, ...(t.manifestOverride[path] ?? {}) }));
  files.push(['source-manifest.json', Buffer.from(JSON.stringify({ schema: 1, files: [...listed, ...t.manifestExtra] }))]);
  for (const [name, bytes] of Object.entries(t.native)) files.push([`native/${name}`, bytes]);
  files.push(['recipe/recipe.template.json', Buffer.from(JSON.stringify(t.template))]);
  files.push(['proof/published-native-identity.json', Buffer.from('{"synthetic":true}')]);
  return { files, template: t.template };
}

function realTarGz(files, format) {
  const d = temp(), tree = join(d, 'tree');
  for (const [rel, bytes] of files) { mkdirSync(dirname(join(tree, rel)), { recursive: true }); writeFileSync(join(tree, rel), bytes); }
  const archive = join(d, `bundle-${format}.tar.gz`);
  execFileSync('tar', ['-C', tree, `--format=${format}`, '-czf', archive, 'source', 'native', 'recipe', 'proof', 'source-manifest.json']);
  return { d, archive };
}

// ---- tar escrito byte a byte (casos que um tar comum não produz) ----
function header(name, { type = '0', size = 0, linkname = '', posix = false, prefix = '' } = {}) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100, 'latin1'); h.write('0000000\0', 108, 'latin1'); h.write('0000000\0', 116, 'latin1');
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1'); h.write('00000000000\0', 136, 'latin1');
  h.write(type, 156, 'latin1'); h.write(linkname, 157, 100, 'utf8');
  if (posix) { h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1'); h.write(prefix, 345, 155, 'utf8'); }
  else h.write('ustar  \0', 257, 'latin1');
  h.fill(0x20, 148, 156);
  let sum = 0; for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const pad = n => Buffer.alloc((512 - (n % 512)) % 512);
const entry = (name, data = '', opts = {}) => { const d = Buffer.from(data); return Buffer.concat([header(name, { ...opts, size: d.length }), d, pad(d.length)]); };
function paxEntry(records) {
  const body = Buffer.concat(records.map(([k, v]) => {
    const rest = ` ${k}=${v}\n`; let n = Buffer.byteLength(rest) + 1;
    while (String(n).length + Buffer.byteLength(rest) !== n) n++;
    return Buffer.from(`${n}${rest}`);
  }));
  return Buffer.concat([header('PaxHeader', { type: 'x', size: body.length, posix: true }), body, pad(body.length)]);
}
const END = Buffer.alloc(1024);
function craftedTarGz(parts, { gzip = true } = {}) {
  const d = temp(), archive = join(d, 'crafted.tar.gz'), raw = Buffer.concat([...parts, END]);
  writeFileSync(archive, gzip ? gzipSync(raw) : raw);
  return { d, archive };
}
// Nomes > 99 bytes vão por cabeçalho pax 'path', como um tar pax real.
const toParts = files => files.map(([n, b]) => n.length > 99 ? Buffer.concat([paxEntry([['path', n]]), entry('pax-short-name', b)]) : entry(n, b));

async function refused(archive, d) {
  const root = join(d, 'in');
  try { await prepare({ archive, root }, PINS); } catch (e) {
    assert.ok(e instanceof PrepareError, String(e?.stack));
    assert.equal(existsSync(root), false, 'root must not exist after refusal');
    assert.deepEqual(readdirSync(d).filter(n => n.endsWith('.tar')), [], 'temporary tar removed');
    return e.problems;
  }
  assert.fail('prepare accepted');
}

for (const format of ['gnu', 'pax']) {
  test(`real ${format} tar.gz: extracts, verifies manifest/pins and writes recipe.json with only native paths absolutized`, async () => {
    const { files, template } = bundleFiles();
    const { d, archive } = realTarGz(files, format), root = join(d, 'in');
    const r = await prepare({ archive, root }, PINS);
    assert.equal(r.ok, true); assert.equal(r.sourceRoot, join(root, 'source')); assert.equal(r.sourceFiles, 6);
    for (const [rel, bytes] of files) assert.ok(readFileSync(join(root, ...rel.split('/'))).equals(bytes), rel);
    const recipe = JSON.parse(readFileSync(join(root, 'recipe', 'recipe.json'), 'utf8'));
    assert.deepEqual(Object.keys(recipe), Object.keys(template));
    assert.deepEqual({ ...recipe, nativeModules: null }, { ...template, nativeModules: null });
    assert.deepEqual(recipe.nativeModules, { sable_node: { path: join(root, 'native', 'sable_node.node'), sha256: PINS.NATIVE.sable_node },
      sable_audiofox: { path: join(root, 'native', 'sable_audiofox.node'), sha256: PINS.NATIVE.sable_audiofox } });
    assert.equal(r.recipeSha256, sha(readFileSync(join(root, 'recipe', 'recipe.json'))));
    assert.deepEqual(readdirSync(d).sort(), [`bundle-${format}.tar.gz`, 'in', 'tree']);
  });
}

test('existing root is preserved and refused; relative paths refused', async () => {
  const { d, archive } = realTarGz(bundleFiles().files, 'gnu'), root = join(d, 'in');
  mkdirSync(root); writeFileSync(join(root, 'keep'), 'x');
  await assert.rejects(prepare({ archive, root }, PINS), e => e.problems[0] === 'root already exists');
  assert.deepEqual(readdirSync(root), ['keep']);
  await assert.rejects(prepare({ archive: 'bundle.tar.gz', root: join(d, 'other') }, PINS), e => e.problems[0] === 'archive and root must be absolute');
});

test('not gzip, bad checksum, truncation, trailing data and missing end are refused before extraction', async () => {
  const base = toParts(bundleFiles().files);
  let c = craftedTarGz(base, { gzip: false });
  assert.deepEqual(await refused(c.archive, c.d), ['archive is not gzip']);
  const broken = Buffer.from(base[0]); broken[0] ^= 1;
  c = craftedTarGz([broken, ...base.slice(1)]);
  assert.deepEqual(await refused(c.archive, c.d), ['tar: header checksum']);
  const d = temp(), archive = join(d, 'trunc.tar.gz');
  writeFileSync(archive, gzipSync(Buffer.concat(base).subarray(0, 700)));
  assert.match((await refused(archive, d))[0], /^tar: (truncated|missing end-of-archive)$/);
  c = craftedTarGz([...base, END, Buffer.from('junk'), pad(4)]);
  assert.deepEqual(await refused(c.archive, c.d), ['tar: data after end-of-archive']);
});

test('adversarial entries are all refused by listing, before any byte is extracted', async () => {
  const base = toParts(bundleFiles().files);
  const cases = [
    [[entry('source/link', '', { type: '2', linkname: '/etc/passwd' })], /entry type "2" refused/],
    [[entry('source/hard', '', { type: '1', linkname: 'source/package.json' })], /entry type "1" refused/],
    [[entry('source/dev', '', { type: '3' })], /entry type "3" refused/],
    [[header('global', { type: 'g', size: 0, posix: true })], /entry type "g" refused/],
    [[paxEntry([['linkpath', '/etc/passwd']]), entry('source/l')], /pax link\/sparse refused/],
    [[entry('../escape', 'x')], /empty, \. or \.\. segment/],
    [[entry('source/../../escape', 'x')], /empty, \. or \.\. segment/],
    [[entry('/abs', 'x')], /absolute path/],
    [[entry('C:/x', 'x')], /forbidden character/],
    [[entry('source/a\\..\\..\\x', 'x')], /forbidden character/],
    [[entry('source/file.txt:stream', 'x')], /forbidden character/],
    [[entry('source/CON.txt', 'x')], /Windows reserved device name/],
    [[entry('source/trailing.', 'x')], /segment ends with dot or space/],
    [[entry('source/Package.json', 'x')], /duplicate or case-colliding/],
    [[entry('source/package.json/inner', 'x')], /file used as directory/],
    [[entry('source/node_modules/x/index.js', 'x')], /dependency\/VCS directory/],
    [[entry('source/.git/config', 'x')], /dependency\/VCS directory/],
    [[entry('source/.env.production', 'x')], /credential-like file/],
    [[entry('source/deploy/server.pem', 'x')], /credential-like file/],
    [[entry('source/.npmrc', 'x')], /credential-like file/],
    [[entry('source/electron/dist/main.cjs', 'x')], /pre-existing Electron stage output/],
    [[entry('source/electron/mindtech-updates.json', '{}')], /pre-existing Electron stage output/],
    [[entry('native/other.node', 'x')], /native\/ accepts only/],
    [[entry('recipe/recipe.json', '{}')], /recipe\/ accepts only recipe.template.json/],
    [[entry('proof/sub/x.json', '{}')], /proof\/ accepts only/],
    [[entry('top.txt', 'x')], /unexpected top-level entry/],
  ];
  for (const [extra, pattern] of cases) {
    const { d, archive } = craftedTarGz([...base, ...extra]);
    const problems = await refused(archive, d);
    assert.ok(problems.some(p => pattern.test(p)), `${pattern}: ${problems.join(' | ')}`);
    assert.equal(existsSync(join(d, '..', 'escape')), false);
  }
  // Ausência de entrada obrigatória também é recusada na listagem.
  const { d, archive } = craftedTarGz(base.filter((_, i) => bundleFiles().files[i][0] !== 'native/sable_audiofox.node'));
  assert.deepEqual(await refused(archive, d), ['missing required entry: native/sable_audiofox.node']);
});

test('pax path and ustar prefix are honored for names (still validated)', async () => {
  const files = bundleFiles().files;
  const parts = files.map(([n, b]) => n.length > 99
    ? Buffer.concat([paxEntry([['path', n], ['mtime', '1.5'], ['uname', 'ignored']]), entry('ignored-short-name', b)])
    : entry(n, b));
  let c = craftedTarGz(parts);
  assert.equal((await prepare({ archive: c.archive, root: join(c.d, 'in') }, PINS)).ok, true);
  const prefixed = files.map(([n, b]) => { const cut = n.lastIndexOf('/'); return n.length > 99 ? Buffer.concat([header(n.slice(cut + 1), { size: b.length, posix: true, prefix: n.slice(0, cut) }), b, pad(b.length)]) : entry(n, b); });
  c = craftedTarGz(prefixed);
  assert.equal((await prepare({ archive: c.archive, root: join(c.d, 'in') }, PINS)).ok, true);
  c = craftedTarGz([...toParts(files), paxEntry([['path', '../evil']]), entry('source/innocent', 'x')]);
  assert.ok((await refused(c.archive, c.d)).some(p => p.startsWith('empty, . or .. segment')));
});

test('content checks after listing: manifest bijection/hashes, packageManager, pins and recipe are exact; root removed', async () => {
  const cases = [
    [t => ({ ...t, manifestDrop: ['src/app.ts'] }), /manifest: source file not listed src\/app.ts/],
    [t => ({ ...t, manifestExtra: [{ path: 'src/ghost.ts', sha256: 'a'.repeat(64), size: 1 }] }), /manifest: listed file absent src\/ghost.ts/],
    [t => ({ ...t, manifestOverride: { 'src/app.ts': { sha256: 'b'.repeat(64) } } }), /manifest: sha256 differs src\/app.ts/],
    [t => ({ ...t, manifestOverride: { 'src/app.ts': { size: 1 } } }), /manifest: size differs src\/app.ts/],
    [t => ({ ...t, manifestOverride: { 'src/app.ts': { extra: 1 } } }), /manifest: malformed entry src\/app.ts/],
    [t => ({ ...t, source: { ...t.source, 'package.json': Buffer.from('{"packageManager":"pnpm@11.0.0"}') } }), /packageManager must be exactly pnpm@12.15.0/],
    [t => ({ ...t, source: { ...t.source, 'electron/build.mjs': Buffer.from('drift') } }), /source: build pin drift electron\/build.mjs/],
    [t => ({ ...t, native: { ...t.native, 'sable_node.node': randomBytes(10) } }), /recipe: native sable_node bytes differ/],
    [t => ({ ...t, template: { ...t.template, nativeModules: { ...t.template.nativeModules, sable_node: { path: '/abs/sable_node.node', sha256: PINS.NATIVE.sable_node } } } }), /recipe: native sable_node must be native\/sable_node.node/],
    [t => ({ ...t, template: { ...t.template, nativeModules: { ...t.template.nativeModules, extra: { path: 'native/x', sha256: 'a'.repeat(64) } } } }), /nativeModules must name exactly/],
    [t => ({ ...t, template: { ...t.template, frontendInputs: [{ path: 'src/app.ts', sha256: 'd'.repeat(64) }] } }), /frontendInputs not in manifest with same sha256 src\/app.ts/],
    [t => ({ ...t, template: { ...t.template, frontendInputs: [{ path: '../src/app.ts', sha256: sha(APP) }] } }), /frontendInputs malformed/],
    [t => ({ ...t, template: { ...t.template, sourceFiles: [{ path: 'electron/build.mjs', sha256: sha(BUILD) }] } }), /sourceFiles lacks 0015 electron\/src\/main.ts/],
    [t => ({ ...t, template: { ...t.template, frontendInputs: [] } }), /frontendInputs empty/],
    [t => ({ ...t, template: { ...t.template, patch: { name: 'p', sha256: 'short' } } }), /recipe: patch identity/],
    [t => ({ ...t, template: { ...t.template, command: 'rm -rf /' } }), /recipe: schema/],
  ];
  for (const [tweak, pattern] of cases) {
    const { d, archive } = realTarGz(bundleFiles(tweak).files, 'gnu');
    const problems = await refused(archive, d);
    assert.ok(problems.some(p => pattern.test(p)), `${pattern}: ${problems.join(' | ')}`);
  }
});

test('path rules and public problem classes keep private names out of the CI log', () => {
  assert.equal(pathProblem('source/ok/file.ts'), null);
  for (const bad of ['', '/x', 'a//b', 'a/./b', 'a/../b', 'C:x', 'a\\b', 'a/nul', 'a/aux.js', 'a/x ', 'a/COM1.txt', 'a/\u0001', `a/${'x'.repeat(256)}`, 'y'.repeat(201)])
    assert.notEqual(pathProblem(bad), null, JSON.stringify(bad));
  assert.deepEqual(publicProblems(['manifest: sha256 differs src/secret-name.ts', 'manifest: size differs other', 'recipe: schema']), ['manifest', 'recipe']);
});

test('CLI with production pins refuses the synthetic bundle and prints only problem classes', () => {
  const { d, archive } = realTarGz(bundleFiles(t => ({ ...t, manifestDrop: ['src/app.ts'] })).files, 'gnu');
  const cli = join(here, '..', 'ci', 'prepare-input.mjs');
  const r = spawnSync(process.execPath, [cli, '--archive', archive, '--root', join(d, 'in')], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  const report = JSON.parse(r.stderr);
  assert.equal(report.ok, false);
  assert.ok(report.problems.includes('manifest') && report.problems.includes('recipe') && report.problems.includes('source'), r.stderr);
  assert.ok(!r.stderr.includes('src/app.ts'));
  assert.equal(existsSync(join(d, 'in')), false);
  const detailed = spawnSync(process.execPath, [cli, '--archive', archive, '--root', join(d, 'in'), '--details'], { encoding: 'utf8' });
  assert.ok(detailed.stderr.includes('manifest: source file not listed src/app.ts'));
});
