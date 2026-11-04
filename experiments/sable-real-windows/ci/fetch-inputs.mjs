#!/usr/bin/env node
// Downloads públicos do ensaio, sem credencial: HTTPS em todos os saltos, hosts permitidos por item, redirecionamento
// manual limitado, tamanho limitado durante o fluxo, sha256 conferido antes da publicação por link exclusivo.
//   cipher --url <asset de prerelease gioknx/sable-escritorio> --sha256 <hex> --size <n> --output <arquivo novo>
//   pinned --output-dir <dir existente>   (Electron, rootfs WSL e wheel Synapse de lib/pins.mjs; wheel via JSON do PyPI)
import { createHash, randomBytes } from 'node:crypto';
import { createWriteStream, linkSync, lstatSync, rmSync } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { ELECTRON, SYNAPSE, WSL_ROOTFS } from '../lib/pins.mjs';
import { MAX_BLOB_BYTES, OVERHEAD } from './sealed-input.mjs';

const GITHUB_RELEASE_HOSTS = Object.freeze(['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']);
export const CIPHER_URL = /^https:\/\/github\.com\/gioknx\/sable-escritorio\/releases\/download\/([A-Za-z0-9._-]{1,128})\/([A-Za-z0-9._-]{1,128})$/;
const HEX64 = /^[0-9a-f]{64}$/;

export class FetchError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new FetchError(code); };

export function checkCipherInputs({ url, sha256, size }) {
  const m = CIPHER_URL.exec(url ?? '');
  if (!m || [m[1], m[2]].some(s => s === '.' || s === '..')) fail('cipher url must be an exact gioknx/sable-escritorio release asset URL');
  if (!HEX64.test(sha256 ?? '')) fail('cipher sha256 must be 64 lowercase hex');
  if (!/^[1-9][0-9]{1,10}$/.test(String(size ?? '')) || Number(size) < OVERHEAD || Number(size) > MAX_BLOB_BYTES) fail('cipher size out of bounds');
  return { url, sha256, size: Number(size) };
}

export const PINNED = Object.freeze([
  { name: 'electron', file: ELECTRON.archive, sha256: ELECTRON.archiveSha256, maxBytes: 400 << 20, hosts: GITHUB_RELEASE_HOSTS,
    url: `https://github.com/electron/electron/releases/download/v${ELECTRON.version}/${ELECTRON.archive}` },
  { name: 'wslRootfs', file: basename(new URL(WSL_ROOTFS.url).pathname), sha256: WSL_ROOTFS.sha256, maxBytes: 1024 << 20,
    hosts: ['cloud-images.ubuntu.com'], url: WSL_ROOTFS.url },
]);
export const PYPI_JSON = `https://pypi.org/pypi/matrix-synapse/${SYNAPSE.version}/json`;

// URL do wheel só a partir do JSON oficial do PyPI: nome exato, sha256 publicado igual ao pin, HTTPS em files.pythonhosted.org.
export function selectWheel(metadata) {
  const urls = Array.isArray(metadata?.urls) ? metadata.urls : fail('pypi: urls absent');
  if (metadata?.info?.version !== SYNAPSE.version) fail('pypi: version differs');
  const matches = urls.filter(u => u?.filename === SYNAPSE.wheel);
  if (matches.length !== 1) fail('pypi: exact wheel filename not listed once');
  const [w] = matches;
  if (w.digests?.sha256 !== SYNAPSE.wheelSha256) fail('pypi: published sha256 differs from pin');
  let url;
  try { url = new URL(w.url); } catch { fail('pypi: wheel url invalid'); }
  if (url.protocol !== 'https:' || url.hostname !== 'files.pythonhosted.org' || basename(url.pathname) !== SYNAPSE.wheel) fail('pypi: wheel url host/name');
  return { name: 'synapseWheel', file: SYNAPSE.wheel, sha256: SYNAPSE.wheelSha256, maxBytes: 100 << 20, hosts: ['files.pythonhosted.org'], url: url.href };
}

// Grava um fluxo em temporário exclusivo; publica por link só com tamanho/sha256 esperados; destino existente preservado.
export async function saveVerified(readable, output, { sha256, maxBytes, exactSize }) {
  if (lstatSync(output, { throwIfNoEntry: false })) fail('output already exists');
  const temp = join(dirname(output), `.${basename(output)}.${randomBytes(8).toString('hex')}.part`);
  const hash = createHash('sha256');
  let bytes = 0;
  const meter = new Transform({ transform(chunk, _e, done) {
    bytes += chunk.length; hash.update(chunk);
    done(bytes > maxBytes || (exactSize !== undefined && bytes > exactSize) ? new FetchError('download over size limit') : null, chunk);
  } });
  try {
    await pipeline(readable, meter, createWriteStream(temp, { flags: 'wx', mode: 0o600 }));
    if (exactSize !== undefined && bytes !== exactSize) fail('download size differs from expected');
    const digest = hash.digest('hex');
    if (digest !== sha256) fail('download sha256 differs from pin');
    try { linkSync(temp, output); } catch (e) { if (e.code === 'EEXIST') fail('output already exists'); throw e; }
    return { file: output, sha256: digest, size: bytes };
  } catch (error) {
    if (error instanceof FetchError) throw error;
    throw new FetchError(`download: ${error?.code ?? 'stream failed'}`);
  } finally {
    rmSync(temp, { force: true });
  }
}

// GET sem cabeçalho de credencial; cada salto deve ser HTTPS e host permitido. Retorna a resposta final 200.
export async function fetchPublic(url, hosts, { maxRedirects = 5, timeoutMs = 600000 } = {}) {
  let current = new URL(url);
  const signal = AbortSignal.timeout(timeoutMs);
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (current.protocol !== 'https:' || !hosts.includes(current.hostname) || current.username || current.password) fail(`url not allowed: ${current.hostname}`);
    let response;
    try { response = await fetch(current, { redirect: 'manual', signal, headers: { 'user-agent': 'sable-escritorio-ensaio' } }); }
    catch (e) { fail(`network: ${e?.cause?.code ?? e?.name ?? 'failed'}`); }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location) fail('redirect without location');
      current = new URL(location, current);
      continue;
    }
    if (response.status !== 200 || !response.body) { await response.body?.cancel(); fail(`http status ${response.status}`); }
    return response;
  }
  fail('too many redirects');
}

async function download(item, output, exactSize) {
  const response = await fetchPublic(item.url, item.hosts);
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > item.maxBytes) { await response.body.cancel(); fail('download over size limit'); }
  return saveVerified(Readable.fromWeb(response.body), output, { sha256: item.sha256, maxBytes: item.maxBytes, exactSize });
}

export async function fetchCipher({ url, sha256, size, output }) {
  const c = checkCipherInputs({ url, sha256, size });
  if (!isAbsolute(output)) fail('output must be absolute');
  return download({ url: c.url, sha256: c.sha256, maxBytes: c.size, hosts: GITHUB_RELEASE_HOSTS }, output, c.size);
}

export async function fetchPinned(outputDir) {
  if (!isAbsolute(outputDir) || !lstatSync(outputDir, { throwIfNoEntry: false })?.isDirectory()) fail('output dir must be an existing absolute directory');
  const metadata = await fetchPublic(PYPI_JSON, ['pypi.org']);
  const text = await metadata.text();
  if (text.length > 8 << 20) fail('pypi: metadata too large');
  let json;
  try { json = JSON.parse(text); } catch { fail('pypi: metadata not JSON'); }
  const result = {};
  for (const item of [...PINNED, selectWheel(json)]) result[item.name] = { url: item.url, ...(await download(item, join(outputDir, item.file))) };
  return result;
}

const USAGE = 'usage: cipher --url <url> --sha256 <hex> --size <n> --output <file> | pinned --output-dir <dir>';
export function parseCli(argv) {
  const [command, ...rest] = argv;
  const spec = { cipher: ['--url', '--sha256', '--size', '--output'], pinned: ['--output-dir'] }[command] ?? fail(USAGE);
  const values = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!spec.includes(rest[i]) || Object.hasOwn(values, rest[i]) || typeof rest[i + 1] !== 'string' || !rest[i + 1] || rest[i + 1].startsWith('--')) fail(USAGE);
    values[rest[i]] = rest[i + 1];
  }
  if (spec.some(k => !Object.hasOwn(values, k))) fail(USAGE);
  return { command, values };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const { command, values: v } = parseCli(process.argv.slice(2));
    const result = command === 'cipher'
      ? await fetchCipher({ url: v['--url'], sha256: v['--sha256'], size: v['--size'], output: v['--output'] })
      : await fetchPinned(v['--output-dir']);
    console.log(JSON.stringify({ ok: true, command, result }));
  } catch (error) {
    console.error(JSON.stringify({ ok: false, error: error instanceof FetchError ? error.code : 'unexpected' }));
    process.exitCode = 1;
  }
}
