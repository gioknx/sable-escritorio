#!/usr/bin/env node
// Prepara a entrada privada já decifrada (bundle tar.gz da mãe) para o driver, sem confiar nos metadados do arquivo:
//  1. gunzip limitado para temporário privado; 2. lista TODOS os cabeçalhos tar e valida nomes/tipos/política antes
//  de extrair qualquer byte; 3. extrai só arquivos regulares e diretórios em raiz nova; 4. confere source-manifest.json
//  (bijeção com source/, sha256 e tamanho completos), pins de build, packageManager, nativos publicados e
//  recipe.template.json; 5. grava recipe/recipe.json igual ao template, trocando APENAS nativeModules.*.path
//  (native/<nome>.node -> absoluto sob a raiz). Conteúdo do bundle é dado: nada nele é executado aqui.
// Contrato do bundle (raiz do tar): source/ (fonte consolidada 0015, sem node_modules/.git/credenciais),
// native/{sable_node,sable_audiofox}.node, recipe/recipe.template.json, proof/*.json (opcional),
// source-manifest.json = {schema:1, files:[{path,sha256,size}]} com caminhos relativos a source/.
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, createReadStream, createWriteStream, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readSync,
  realpathSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { createGunzip } from 'node:zlib';
import { CONSOLIDATED_LAYOUT, NATIVE, SOURCE_PINS } from '../lib/pins.mjs';

export const PNPM_PACKAGE_MANAGER = 'pnpm@12.15.0';
// Pins de produção do ensaio; os testes passam pins sintéticos pelo parâmetro (a CLI não tem opção para trocá-los).
export const DEFAULT_PINS = Object.freeze({ NATIVE, SOURCE_PINS, CONSOLIDATED_LAYOUT });
export const LIMITS = Object.freeze({
  tarBytes: 4 * 1024 ** 3, entries: 200000, fileBytes: 1024 ** 3, paxBytes: 1 << 20, relPath: 200, segment: 255,
  manifestBytes: 64 << 20, recipeBytes: 16 << 20, proofBytes: 4 << 20, absolutePath: 259,
});
const BLOCK = 512;

export class PrepareError extends Error {
  constructor(problems) { super(problems[0] ?? 'prepare failed'); this.problems = problems; }
}

// ---------- nomes ----------
const BAD_CHARS = /[\u0000-\u001f\u007f<>:"|?*\\]/;
const RESERVED = /^(con|prn|aux|nul|conin\$|conout\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(\..*)?$/i;
// Relativo POSIX, sem absoluto/drive/UNC/ADS, sem . ou .., sem nomes que o Windows reescreve ou reserva.
export function pathProblem(rel) {
  if (typeof rel !== 'string' || rel === '') return 'empty path';
  if (rel.length > LIMITS.relPath) return 'path too long';
  if (rel.startsWith('/')) return 'absolute path';
  for (const s of rel.split('/')) {
    if (s === '' || s === '.' || s === '..') return 'empty, . or .. segment';
    if (s.length > LIMITS.segment) return 'segment too long';
    if (BAD_CHARS.test(s)) return 'forbidden character (control, backslash, drive/ADS colon or Windows reserved)';
    if (/[. ]$/.test(s)) return 'segment ends with dot or space';
    if (RESERVED.test(s)) return 'Windows reserved device name';
  }
  return null;
}

const FORBIDDEN_SEGMENTS = new Set(['node_modules', '.git', '.hg', '.svn', '.pnpm-store']);
const FORBIDDEN_NAMES = new Set(['.npmrc', '.yarnrc', '.yarnrc.yml', '.netrc', '.pypirc', '.git-credentials', '.dockercfg']);
const FORBIDDEN_EXT = /\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)$/i;
const FORBIDDEN_PREFIX = /^(id_rsa|id_dsa|id_ecdsa|id_ed25519)/i;
const STAGE_PRESENT = ['electron/dist', 'electron/release', 'electron/mindtech-updates.json'];
// Política por caminho relativo à raiz do bundle. Retorna problema ou null.
export function policyProblem(rel, type, size) {
  const segs = rel.split('/'), top = segs[0];
  if (rel === 'source-manifest.json') return type === 'file' ? null : 'source-manifest.json must be a file';
  if (top === 'native') {
    if (segs.length === 1) return type === 'dir' ? null : 'native must be a directory';
    return segs.length === 2 && type === 'file' && Object.hasOwn(NATIVE, segs[1].replace(/\.node$/, '')) && segs[1].endsWith('.node')
      ? null : 'native/ accepts only the published module files';
  }
  if (top === 'recipe') {
    if (segs.length === 1) return type === 'dir' ? null : 'recipe must be a directory';
    return rel === 'recipe/recipe.template.json' && type === 'file' ? null : 'recipe/ accepts only recipe.template.json';
  }
  if (top === 'proof') {
    if (segs.length === 1) return type === 'dir' ? null : 'proof must be a directory';
    return segs.length === 2 && type === 'file' && segs[1].endsWith('.json') && size <= LIMITS.proofBytes ? null : 'proof/ accepts only bounded *.json files';
  }
  if (top !== 'source') return 'unexpected top-level entry';
  if (segs.length === 1) return type === 'dir' ? null : 'source must be a directory';
  const inner = segs.slice(1), lower = inner.map(s => s.toLowerCase()), name = lower.at(-1), innerRel = lower.join('/');
  if (lower.some(s => FORBIDDEN_SEGMENTS.has(s))) return 'source contains dependency/VCS directory';
  if (type === 'file' && (FORBIDDEN_NAMES.has(name) || name === '.env' || name.startsWith('.env.') || FORBIDDEN_EXT.test(name) || FORBIDDEN_PREFIX.test(name)))
    return 'source contains credential-like file';
  if (STAGE_PRESENT.some(p => innerRel === p || innerRel.startsWith(`${p}/`))) return 'source contains pre-existing Electron stage output';
  return null;
}

// ---------- tar ----------
const isZero = b => { for (const x of b) if (x !== 0) return false; return true; };
const utf8 = new TextDecoder('utf-8', { fatal: true });
const cstr = b => { const end = b.indexOf(0); return end < 0 ? b : b.subarray(0, end); };
function octal(field, label) {
  if (field[0] & 0x80) throw new PrepareError([`tar: ${label} uses base-256 (over limit)`]);
  const text = cstr(field).toString('latin1').trim();
  if (!/^[0-7]{1,12}$/.test(text)) throw new PrepareError([`tar: ${label} not octal`]);
  return Number.parseInt(text, 8);
}
function headerChecksum(h) {
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
  return sum;
}
function readExact(fd, buffer, pos) {
  let off = 0;
  while (off < buffer.length) {
    const n = readSync(fd, buffer, off, buffer.length - off, pos + off);
    if (n <= 0) throw new PrepareError(['tar: truncated']);
    off += n;
  }
  return buffer;
}
function paxRecords(bytes) {
  const out = {};
  let pos = 0;
  while (pos < bytes.length) {
    const space = bytes.indexOf(0x20, pos);
    if (space < 0) throw new PrepareError(['tar: malformed pax record']);
    const lenText = bytes.subarray(pos, space).toString('latin1');
    if (!/^[1-9][0-9]{0,6}$/.test(lenText)) throw new PrepareError(['tar: malformed pax record']);
    const len = Number(lenText), end = pos + len;
    if (end > bytes.length || bytes[end - 1] !== 0x0a) throw new PrepareError(['tar: malformed pax record']);
    let record;
    try { record = utf8.decode(bytes.subarray(space + 1, end - 1)); } catch { throw new PrepareError(['tar: pax record not UTF-8']); }
    const eq = record.indexOf('=');
    if (eq <= 0) throw new PrepareError(['tar: malformed pax record']);
    out[record.slice(0, eq)] = record.slice(eq + 1);
    pos = end;
  }
  return out;
}

// Lista todas as entradas do tar sem extrair: {name, type:'file'|'dir', size, offset}. Links, devices, sparse,
// pax global e linkpath são recusados; dono/modo/mtime são ignorados (metadado não confiável).
export function listTar(fd, totalBytes) {
  const entries = [], header = Buffer.alloc(BLOCK);
  let pos = 0, pending = {};
  for (;;) {
    if (pos + BLOCK > totalBytes) throw new PrepareError(['tar: missing end-of-archive']);
    readExact(fd, header, pos);
    if (isZero(header)) {
      if (Object.keys(pending).length) throw new PrepareError(['tar: extended header without entry']);
      if (pos + 2 * BLOCK > totalBytes || !isZero(readExact(fd, Buffer.alloc(BLOCK), pos + BLOCK))) throw new PrepareError(['tar: malformed end-of-archive']);
      const rest = Buffer.alloc(1 << 16);
      for (let p = pos + 2 * BLOCK; p < totalBytes; p += rest.length) {
        const view = rest.subarray(0, Math.min(rest.length, totalBytes - p));
        if (!isZero(readExact(fd, view, p))) throw new PrepareError(['tar: data after end-of-archive']);
      }
      return entries;
    }
    if (octal(header.subarray(148, 156), 'checksum') !== headerChecksum(header)) throw new PrepareError(['tar: header checksum']);
    const magic = header.subarray(257, 265).toString('latin1');
    const posix = magic === 'ustar\u000000', gnu = magic === 'ustar  \u0000';
    if (!posix && !gnu) throw new PrepareError(['tar: only ustar/pax/gnu headers accepted']);
    const type = String.fromCharCode(header[156] || 0x30), size = octal(header.subarray(124, 136), 'size');
    const dataAt = pos + BLOCK, next = dataAt + Math.ceil(size / BLOCK) * BLOCK;
    if (next > totalBytes) throw new PrepareError(['tar: truncated']);
    if (type === 'x' || type === 'L') {
      if (size > LIMITS.paxBytes) throw new PrepareError(['tar: extended header too large']);
      const data = readExact(fd, Buffer.alloc(size), dataAt);
      if (type === 'L') {
        if (pending.longName !== undefined) throw new PrepareError(['tar: repeated long name']);
        try { pending.longName = utf8.decode(cstr(data)); } catch { throw new PrepareError(['tar: name not UTF-8']); }
      } else {
        if (pending.pax) throw new PrepareError(['tar: repeated pax header']);
        const pax = paxRecords(data);
        if ('linkpath' in pax || Object.keys(pax).some(k => k.startsWith('GNU.sparse'))) throw new PrepareError(['tar: pax link/sparse refused']);
        if (pax.size !== undefined && !/^[0-9]{1,13}$/.test(pax.size)) throw new PrepareError(['tar: pax size']);
        pending.pax = pax;
      }
      pos = next;
      continue;
    }
    if (type !== '0' && type !== '5') throw new PrepareError([`tar: entry type ${JSON.stringify(type)} refused (only regular files and directories)`]);
    let name;
    if (pending.pax?.path !== undefined) name = pending.pax.path;
    else if (pending.longName !== undefined) name = pending.longName;
    else {
      try {
        const base = utf8.decode(cstr(header.subarray(0, 100))), prefix = posix ? utf8.decode(cstr(header.subarray(345, 500))) : '';
        name = prefix ? `${prefix}/${base}` : base;
      } catch { throw new PrepareError(['tar: name not UTF-8']); }
    }
    let realSize = size;
    if (pending.pax?.size !== undefined) {
      realSize = Number(pending.pax.size);
      if (realSize !== size) throw new PrepareError(['tar: pax size differs from header (unsupported)']);
    }
    pending = {};
    if (type === '5' && realSize !== 0) throw new PrepareError(['tar: directory with data']);
    if (realSize > LIMITS.fileBytes) throw new PrepareError(['tar: entry over size limit']);
    if (name.startsWith('./')) name = name.slice(2);
    if (type === '5' && name.endsWith('/')) name = name.slice(0, -1);
    if (name !== '' && name !== '.') {
      entries.push({ name, type: type === '5' ? 'dir' : 'file', size: realSize, offset: dataAt });
      if (entries.length > LIMITS.entries) throw new PrepareError(['tar: too many entries']);
    }
    pos = next;
  }
}

// Validação completa da lista (antes de extrair): nomes, política, duplicatas sem distinção de caixa (NTFS),
// conflito arquivo/diretório, presença obrigatória e comprimento absoluto na raiz de destino.
export function validateEntries(entries, root) {
  const problems = [], files = new Map(), dirs = new Set(), explicitDirs = new Set();
  const key = p => p.normalize('NFC').toLowerCase();
  for (const e of entries) {
    const where = String(e.name).slice(0, 160);
    const bad = pathProblem(e.name) ?? policyProblem(e.name, e.type, e.size);
    if (bad) { problems.push(`${bad}: ${where}`); continue; }
    if (root && join(root, ...e.name.split('/')).length > LIMITS.absolutePath) { problems.push(`absolute path over Windows limit: ${where}`); continue; }
    const k = key(e.name), segs = k.split('/');
    for (let i = 1; i < segs.length; i++) {
      const anc = segs.slice(0, i).join('/');
      if (files.has(anc)) problems.push(`file used as directory: ${where}`);
      dirs.add(anc);
    }
    if (e.type === 'file') {
      if (files.has(k) || dirs.has(k)) problems.push(`duplicate or case-colliding entry: ${where}`);
      files.set(k, e.name);
    } else {
      if (files.has(k) || explicitDirs.has(k)) problems.push(`duplicate or case-colliding entry: ${where}`);
      explicitDirs.add(k); dirs.add(k);
    }
  }
  for (const k of files.keys()) if (dirs.has(k)) problems.push(`file used as directory: ${files.get(k).slice(0, 160)}`);
  const present = new Set(entries.filter(e => e.type === 'file').map(e => e.name));
  for (const required of ['source-manifest.json', 'recipe/recipe.template.json', 'source/package.json', 'source/pnpm-lock.yaml',
    ...Object.keys(NATIVE).map(n => `native/${n}.node`)]) if (!present.has(required)) problems.push(`missing required entry: ${required}`);
  return [...new Set(problems)];
}

async function gunzipBounded(archive, target) {
  const head = Buffer.alloc(2), fd = openSync(archive, 'r');
  try { readSync(fd, head, 0, 2, 0); } finally { closeSync(fd); }
  if (head[0] !== 0x1f || head[1] !== 0x8b) throw new PrepareError(['archive is not gzip']);
  let total = 0;
  const cap = new Transform({ transform(chunk, _e, done) {
    total += chunk.length;
    done(total > LIMITS.tarBytes ? new PrepareError(['decompressed archive over limit']) : null, chunk);
  } });
  try {
    await pipeline(createReadStream(archive), createGunzip(), cap, createWriteStream(target, { flags: 'wx', mode: 0o600 }));
  } catch (error) {
    if (error instanceof PrepareError) throw error;
    throw new PrepareError([`gunzip: ${error?.code ?? 'failed'}`]);
  }
  return total;
}

function extract(fd, entries, root) {
  const buffer = Buffer.allocUnsafe(1 << 20), prefix = root + sep;
  for (const e of entries) {
    const full = join(root, ...e.name.split('/'));
    if (!full.startsWith(prefix)) throw new PrepareError([`confinement: ${e.name.slice(0, 160)}`]);
    if (e.type === 'dir') { mkdirSync(full, { recursive: true }); continue; }
    mkdirSync(dirname(full), { recursive: true });
    const out = openSync(full, 'wx', 0o600);
    try {
      let left = e.size, pos = e.offset;
      while (left > 0) {
        const n = readSync(fd, buffer, 0, Math.min(buffer.length, left), pos);
        if (n <= 0) throw new PrepareError(['tar: truncated']);
        let off = 0;
        while (off < n) off += writeSync(out, buffer, off, n - off);
        pos += n; left -= n;
      }
    } finally { closeSync(out); }
  }
}

// ---------- conteúdo ----------
const HEX64 = /^[0-9a-f]{64}$/;
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join() === [...keys].sort().join();
export function sha256File(file) {
  const h = createHash('sha256'), fd = openSync(file, 'r'), buffer = Buffer.allocUnsafe(1 << 20);
  try { let pos = 0, n; while ((n = readSync(fd, buffer, 0, buffer.length, pos)) > 0) { h.update(buffer.subarray(0, n)); pos += n; } }
  finally { closeSync(fd); }
  return h.digest('hex');
}
function readJson(file, max, label) {
  const st = lstatSync(file);
  if (!st.isFile() || st.size > max) throw new PrepareError([`${label}: not a bounded regular file`]);
  try { return JSON.parse(readFileSync(file, 'utf8')); } catch { throw new PrepareError([`${label}: invalid JSON`]); }
}

// source-manifest.json: bijeção exata (com caixa) com os arquivos de source/ no tar; sha256 e tamanho recomputados.
export function checkManifest(root, manifest, sourceFiles) {
  const problems = [];
  if (!exactKeys(manifest, ['schema', 'files']) || manifest.schema !== 1 || !Array.isArray(manifest.files)) return { problems: ['manifest: schema'], byPath: new Map() };
  const byPath = new Map();
  for (const f of manifest.files) {
    if (!exactKeys(f, ['path', 'sha256', 'size']) || pathProblem(f.path) || !HEX64.test(f.sha256 ?? '') || !Number.isSafeInteger(f.size) || f.size < 0) {
      problems.push(`manifest: malformed entry ${String(f?.path).slice(0, 160)}`); continue;
    }
    if (byPath.has(f.path)) problems.push(`manifest: duplicate ${f.path.slice(0, 160)}`);
    byPath.set(f.path, f);
  }
  const present = new Map(sourceFiles.map(e => [e.name.slice('source/'.length), e]));
  for (const [path, e] of present) {
    const f = byPath.get(path);
    if (!f) { problems.push(`manifest: source file not listed ${path.slice(0, 160)}`); continue; }
    if (f.size !== e.size) { problems.push(`manifest: size differs ${path.slice(0, 160)}`); continue; }
    if (sha256File(join(root, 'source', ...path.split('/'))) !== f.sha256) problems.push(`manifest: sha256 differs ${path.slice(0, 160)}`);
  }
  for (const path of byPath.keys()) if (!present.has(path)) problems.push(`manifest: listed file absent ${path.slice(0, 160)}`);
  return { problems, byPath };
}

// recipe.template.json -> recipe.json: mesmas chaves e valores; só nativeModules.*.path vira absoluto sob a raiz.
export function checkRecipe(root, template, byPath, { NATIVE, CONSOLIDATED_LAYOUT } = DEFAULT_PINS) {
  const problems = [];
  if (!exactKeys(template, ['schema', 'patch', 'nativeModules', 'frontendInputs', 'sourceFiles']) || template.schema !== 1) return { problems: ['recipe: schema'] };
  if (!exactKeys(template.patch, ['name', 'sha256']) || typeof template.patch.name !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(template.patch.name)
    || !HEX64.test(template.patch.sha256 ?? '')) problems.push('recipe: patch identity');
  const nativeModules = {};
  if (!exactKeys(template.nativeModules, Object.keys(NATIVE))) problems.push('recipe: nativeModules must name exactly the published modules');
  else for (const [name, pin] of Object.entries(NATIVE)) {
    const entry = template.nativeModules[name];
    if (!exactKeys(entry, ['path', 'sha256']) || entry.path !== `native/${name}.node` || entry.sha256 !== pin) { problems.push(`recipe: native ${name} must be native/${name}.node with the published pin`); continue; }
    const full = join(root, 'native', `${name}.node`);
    if (sha256File(full) !== pin) problems.push(`recipe: native ${name} bytes differ from published pin`);
    nativeModules[name] = { path: full, sha256: pin };
  }
  for (const list of ['frontendInputs', 'sourceFiles']) {
    if (!Array.isArray(template[list]) || template[list].length === 0) { problems.push(`recipe: ${list} empty`); continue; }
    const seen = new Set();
    for (const item of template[list]) {
      const where = String(item?.path).slice(0, 160);
      if (!exactKeys(item, ['path', 'sha256']) || pathProblem(item.path) || !HEX64.test(item.sha256 ?? '')) { problems.push(`recipe: ${list} malformed ${where}`); continue; }
      if (seen.has(item.path)) problems.push(`recipe: ${list} duplicate ${where}`);
      seen.add(item.path);
      if (byPath.get(item.path)?.sha256 !== item.sha256) problems.push(`recipe: ${list} not in manifest with same sha256 ${where}`);
    }
  }
  const listed = new Set((Array.isArray(template.sourceFiles) ? template.sourceFiles : []).map(i => i?.path));
  for (const rel of CONSOLIDATED_LAYOUT) if (!listed.has(rel)) problems.push(`recipe: sourceFiles lacks 0015 ${rel}`);
  return { problems, recipe: { ...template, nativeModules } };
}

export function checkSource(root, byPath, { SOURCE_PINS } = DEFAULT_PINS) {
  const problems = [];
  for (const [rel, sha] of Object.entries(SOURCE_PINS)) if (byPath.get(rel)?.sha256 !== sha) problems.push(`source: build pin drift ${rel}`);
  let pkg;
  try { pkg = JSON.parse(readFileSync(join(root, 'source', 'package.json'), 'utf8')); } catch { problems.push('source: package.json invalid'); }
  if (pkg && pkg.packageManager !== PNPM_PACKAGE_MANAGER) problems.push(`source: packageManager must be exactly ${PNPM_PACKAGE_MANAGER}`);
  return problems;
}

export async function prepare({ archive, root }, pins = DEFAULT_PINS) {
  if (!isAbsolute(archive) || !isAbsolute(root)) throw new PrepareError(['archive and root must be absolute']);
  const parent = realpathSync.native(dirname(root));
  root = join(parent, basename(root));
  if (lstatSync(root, { throwIfNoEntry: false })) throw new PrepareError(['root already exists']);
  const st = lstatSync(archive, { throwIfNoEntry: false });
  if (!st?.isFile()) throw new PrepareError(['archive must be a regular file']);
  const tar = join(parent, `.${basename(root)}.${randomBytes(8).toString('hex')}.tar`);
  let created = false;
  try {
    const tarBytes = await gunzipBounded(archive, tar);
    const fd = openSync(tar, 'r');
    try {
      if (fstatSync(fd).size !== tarBytes) throw new PrepareError(['tar changed']);
      const entries = listTar(fd, tarBytes);
      const listProblems = validateEntries(entries, root);
      if (listProblems.length) throw new PrepareError(listProblems);
      mkdirSync(root); created = true;
      extract(fd, entries, root);
      const sourceFiles = entries.filter(e => e.type === 'file' && e.name.startsWith('source/'));
      const manifestFile = join(root, 'source-manifest.json');
      const { problems: mp, byPath } = checkManifest(root, readJson(manifestFile, LIMITS.manifestBytes, 'manifest'), sourceFiles);
      const sp = checkSource(root, byPath, pins);
      const templateFile = join(root, 'recipe', 'recipe.template.json');
      const { problems: rp, recipe } = checkRecipe(root, readJson(templateFile, LIMITS.recipeBytes, 'recipe'), byPath, pins);
      const problems = [...mp, ...sp, ...rp];
      if (problems.length) throw new PrepareError(problems);
      const recipeFile = join(root, 'recipe', 'recipe.json');
      writeFileSync(recipeFile, JSON.stringify(recipe, null, 1), { flag: 'wx', mode: 0o600 });
      return { ok: true, root, sourceRoot: join(root, 'source'), recipeRoot: join(root, 'recipe'), sourceFiles: sourceFiles.length,
        tarBytes, manifestSha256: sha256File(manifestFile), templateSha256: sha256File(templateFile), recipeSha256: sha256File(recipeFile),
        patch: recipe.patch };
    } finally { closeSync(fd); }
  } catch (error) {
    if (created) rmSync(root, { recursive: true, force: true });
    throw error;
  } finally {
    rmSync(tar, { force: true });
  }
}

export function parseCli(argv) {
  const values = {}, allowed = ['--archive', '--root'];
  let details = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--details') { details = true; continue; }
    if (!allowed.includes(argv[i]) || Object.hasOwn(values, argv[i]) || typeof argv[i + 1] !== 'string' || !argv[i + 1] || argv[i + 1].startsWith('--'))
      throw new PrepareError(['usage: prepare-input.mjs --archive <plain bundle.tar.gz> --root <new absolute dir> [--details]']);
    values[argv[i]] = argv[++i];
  }
  if (!values['--archive'] || !values['--root']) throw new PrepareError(['usage: prepare-input.mjs --archive <plain bundle.tar.gz> --root <new absolute dir> [--details]']);
  return { archive: values['--archive'], root: values['--root'], details };
}

// Log público do CI: só a classe de cada problema (texto antes de ':') e a contagem; nomes privados só com --details.
export function publicProblems(problems) {
  return [...new Set(problems.map(p => String(p).split(':')[0].slice(0, 120)))].slice(0, 20);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  let details = false;
  try {
    const o = parseCli(process.argv.slice(2)); details = o.details;
    console.log(JSON.stringify(await prepare(o)));
  } catch (error) {
    const problems = error instanceof PrepareError ? error.problems : [`io: ${error?.code ?? 'unexpected'}`];
    console.error(JSON.stringify({ ok: false, count: problems.length, problems: details ? problems.slice(0, 200) : publicProblems(problems) }));
    process.exitCode = 1;
  }
}
