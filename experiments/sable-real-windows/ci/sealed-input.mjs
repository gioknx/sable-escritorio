#!/usr/bin/env node
// Envelope selado da entrada privada do ensaio (bundle tar.gz). Formato SABLE-TI v1:
//   header 32 bytes = magic "SABLE-TI" | version u8 = 1 | alg u8 = 1 (AES-256-GCM) | reserved u16 = 0
//                     | nonce 12 bytes (CSPRNG) | plaintextLength u64 big-endian
//   ciphertext (plaintextLength bytes) | tag 16 bytes
//   AAD = DOMAIN || header. Chave: 32 bytes, base64 canônico (44 chars, um "\n" final opcional).
// Chave só por arquivo (seal) ou variável de ambiente (open); nunca argv. Saída gravada em temporário exclusivo
// no mesmo diretório e publicada por link exclusivo apenas depois da tag GCM aceita; destino existente é preservado.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readSync, rmSync, writeSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const MAGIC = Buffer.from('SABLE-TI', 'ascii');
export const VERSION = 1;
export const ALG_AES_256_GCM = 1;
export const DOMAIN = Buffer.from('mindtech/sable-escritorio/sealed-test-input/v1\0', 'utf8');
export const HEADER_BYTES = 32;
export const TAG_BYTES = 16;
export const NONCE_BYTES = 12;
export const OVERHEAD = HEADER_BYTES + TAG_BYTES;
// Teto de asset de release do GitHub (2 GiB) para o blob inteiro.
export const MAX_BLOB_BYTES = 2 * 1024 * 1024 * 1024;
export const MAX_PLAINTEXT_BYTES = MAX_BLOB_BYTES - OVERHEAD;
const CHUNK = 1 << 20;

export class SealError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new SealError(code); };

export function parseKey(text) {
  if (typeof text !== 'string') fail('key absent');
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  if (!/^[A-Za-z0-9+/]{43}=$/.test(body)) fail('key not canonical base64 of 32 bytes');
  const key = Buffer.from(body, 'base64');
  if (key.length !== 32 || key.toString('base64') !== body) fail('key not canonical base64 of 32 bytes');
  return key;
}

export function readKeyFile(file) {
  const st = lstatSync(file, { throwIfNoEntry: false });
  if (!st || !st.isFile() || st.size > 64) fail('key file must be a regular file of at most 64 bytes');
  const fd = openSync(file, 'r');
  try {
    const bytes = Buffer.alloc(st.size);
    if (readSync(fd, bytes, 0, st.size, 0) !== st.size) fail('key file changed while reading');
    return parseKey(bytes.toString('utf8'));
  } finally { closeSync(fd); }
}

// Lê e remove a variável do próprio processo: nada filho herda a chave.
export function readKeyEnv(name, env = process.env) {
  if (!/^[A-Z_][A-Z0-9_]{0,63}$/.test(name ?? '')) fail('key env name');
  const value = env[name];
  delete env[name];
  if (value === undefined || value === '') fail('key env absent');
  return parseKey(value);
}

export function encodeHeader(nonce, length) {
  if (nonce.length !== NONCE_BYTES) fail('nonce size');
  const header = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(header, 0);
  header[8] = VERSION; header[9] = ALG_AES_256_GCM; header.writeUInt16BE(0, 10);
  nonce.copy(header, 12);
  header.writeBigUInt64BE(BigInt(length), 24);
  return header;
}

export function decodeHeader(header, blobSize) {
  if (header.length !== HEADER_BYTES || !header.subarray(0, 8).equals(MAGIC)) fail('not a SABLE-TI blob');
  if (header[8] !== VERSION) fail('unsupported version');
  if (header[9] !== ALG_AES_256_GCM || header.readUInt16BE(10) !== 0) fail('unsupported algorithm or reserved bits');
  const length = header.readBigUInt64BE(24);
  if (length > BigInt(MAX_PLAINTEXT_BYTES)) fail('declared length over limit');
  if (blobSize !== undefined && BigInt(blobSize) !== length + BigInt(OVERHEAD)) fail('blob truncated or extended');
  return { nonce: Buffer.from(header.subarray(12, 24)), length: Number(length) };
}

const aad = header => Buffer.concat([DOMAIN, header]);

function regularFile(file, label, max) {
  const st = lstatSync(file, { throwIfNoEntry: false });
  if (!st || !st.isFile()) fail(`${label} must be an existing regular file`);
  if (st.size > max) fail(`${label} over size limit`);
  return st.size;
}

// Temporário exclusivo ao lado do destino; publicação por link (falha se o destino existir); limpeza em qualquer erro.
function exclusiveOutput(output, produce) {
  if (lstatSync(output, { throwIfNoEntry: false })) fail('output already exists');
  const temp = join(dirname(output), `.${basename(output)}.${randomBytes(8).toString('hex')}.part`);
  let fd = openSync(temp, 'wx', 0o600), result;
  try {
    result = produce(bytes => { let off = 0; while (off < bytes.length) off += writeSync(fd, bytes, off); });
    fsyncSync(fd); closeSync(fd); fd = null;
    try { linkSync(temp, output); } catch (e) { if (e.code === 'EEXIST') fail('output already exists'); throw e; }
    return result;
  } finally {
    if (fd !== null) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

function eachChunk(fd, start, length, fn) {
  const buffer = Buffer.allocUnsafe(CHUNK);
  let pos = start, left = length;
  while (left > 0) {
    const n = readSync(fd, buffer, 0, Math.min(CHUNK, left), pos);
    if (n <= 0) fail('input changed while reading');
    fn(buffer.subarray(0, n)); pos += n; left -= n;
  }
}

export function seal({ input, output, key, maxBytes = MAX_PLAINTEXT_BYTES }) {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('key must be 32 bytes');
  const size = regularFile(input, 'input', Math.min(maxBytes, MAX_PLAINTEXT_BYTES));
  const nonce = randomBytes(NONCE_BYTES), header = encodeHeader(nonce, size);
  const fd = openSync(input, 'r');
  try {
    if (fstatSync(fd).size !== size) fail('input changed while reading');
    return exclusiveOutput(output, write => {
      const blobHash = createHash('sha256'), plainHash = createHash('sha256');
      const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
      cipher.setAAD(aad(header));
      const emit = bytes => { blobHash.update(bytes); write(bytes); };
      emit(header);
      eachChunk(fd, 0, size, chunk => { plainHash.update(chunk); emit(cipher.update(chunk)); });
      const tail = cipher.final();
      if (tail.length) emit(tail);
      emit(cipher.getAuthTag());
      return { sha256: blobHash.digest('hex'), size: size + OVERHEAD, plaintextSha256: plainHash.digest('hex'), plaintextSize: size };
    });
  } finally { closeSync(fd); }
}

const HEX64 = /^[0-9a-f]{64}$/;
export function open({ input, output, key, expectSha256, expectSize, expectPlaintextSha256, maxBytes = MAX_PLAINTEXT_BYTES }) {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('key must be 32 bytes');
  for (const v of [expectSha256, expectPlaintextSha256]) if (v !== undefined && !HEX64.test(v)) fail('expected sha256 must be 64 lowercase hex');
  if (expectSize !== undefined && (!Number.isSafeInteger(expectSize) || expectSize < OVERHEAD)) fail('expected size invalid');
  const limit = Math.min(maxBytes, MAX_PLAINTEXT_BYTES) + OVERHEAD;
  const size = regularFile(input, 'input', limit);
  if (size < OVERHEAD) fail('blob truncated or extended');
  if (expectSize !== undefined && size !== expectSize) fail('blob size differs from expected');
  const fd = openSync(input, 'r');
  try {
    if (fstatSync(fd).size !== size) fail('input changed while reading');
    const header = Buffer.alloc(HEADER_BYTES);
    if (readSync(fd, header, 0, HEADER_BYTES, 0) !== HEADER_BYTES) fail('blob truncated or extended');
    const { nonce, length } = decodeHeader(header, size);
    if (length > maxBytes) fail('declared length over limit');
    // SHA do blob conferido antes de qualquer decifração.
    if (expectSha256 !== undefined) {
      const h = createHash('sha256');
      eachChunk(fd, 0, size, chunk => h.update(chunk));
      if (h.digest('hex') !== expectSha256) fail('blob sha256 differs from expected');
    }
    const tag = Buffer.alloc(TAG_BYTES);
    if (readSync(fd, tag, 0, TAG_BYTES, size - TAG_BYTES) !== TAG_BYTES) fail('blob truncated or extended');
    return exclusiveOutput(output, write => {
      const blobHash = createHash('sha256').update(header), plainHash = createHash('sha256');
      const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
      decipher.setAAD(aad(header));
      decipher.setAuthTag(tag);
      eachChunk(fd, HEADER_BYTES, length, chunk => {
        blobHash.update(chunk);
        const plain = decipher.update(chunk); plainHash.update(plain); write(plain);
      });
      try { const tail = decipher.final(); if (tail.length) { plainHash.update(tail); write(tail); } }
      catch { fail('authentication failed (wrong key, tampered or truncated blob)'); }
      blobHash.update(tag);
      const sha256 = blobHash.digest('hex'), plaintextSha256 = plainHash.digest('hex');
      if (expectSha256 !== undefined && sha256 !== expectSha256) fail('input changed while reading');
      if (expectPlaintextSha256 !== undefined && plaintextSha256 !== expectPlaintextSha256) fail('plaintext sha256 differs from expected');
      return { sha256, size, plaintextSha256, plaintextSize: length };
    });
  } finally { closeSync(fd); }
}

const OPTIONS = {
  seal: { required: ['--input', '--output', '--key-file'], optional: ['--max-bytes'] },
  open: { required: ['--input', '--output', '--key-env'], optional: ['--expect-sha256', '--expect-size', '--expect-plaintext-sha256', '--max-bytes'] },
};
export function parseCli(argv) {
  const [command, ...rest] = argv, spec = OPTIONS[command];
  if (!spec) fail('usage: seal --input <tar.gz> --output <blob> --key-file <file> | open --input <blob> --output <tar.gz> --key-env <NAME> [--expect-sha256 hex] [--expect-size n] [--expect-plaintext-sha256 hex] [--max-bytes n]');
  const values = {};
  for (let i = 0; i < rest.length; i += 2) {
    const name = rest[i], value = rest[i + 1];
    if (![...spec.required, ...spec.optional].includes(name)) fail(`unknown option ${String(name).slice(0, 32)}`);
    if (Object.hasOwn(values, name)) fail(`repeated option ${name}`);
    if (typeof value !== 'string' || value === '' || value.startsWith('--')) fail(`missing value for ${name}`);
    values[name] = value;
  }
  for (const name of spec.required) if (!Object.hasOwn(values, name)) fail(`missing ${name}`);
  const int = name => {
    if (values[name] === undefined) return undefined;
    if (!/^[1-9][0-9]{0,15}$/.test(values[name]) || !Number.isSafeInteger(Number(values[name]))) fail(`${name} must be a positive integer`);
    return Number(values[name]);
  };
  return { command, input: values['--input'], output: values['--output'], keyFile: values['--key-file'], keyEnv: values['--key-env'],
    expectSha256: values['--expect-sha256'], expectSize: int('--expect-size'), expectPlaintextSha256: values['--expect-plaintext-sha256'],
    maxBytes: int('--max-bytes') };
}

export function cli(argv, env = process.env) {
  try {
    const o = parseCli(argv);
    const maxBytes = o.maxBytes ?? MAX_PLAINTEXT_BYTES;
    const result = o.command === 'seal'
      ? seal({ input: o.input, output: o.output, key: readKeyFile(o.keyFile), maxBytes })
      : open({ input: o.input, output: o.output, key: readKeyEnv(o.keyEnv, env), maxBytes,
        expectSha256: o.expectSha256, expectSize: o.expectSize, expectPlaintextSha256: o.expectPlaintextSha256 });
    return { code: 0, report: { ok: true, op: o.command, format: 'SABLE-TI/1 AES-256-GCM', ...result } };
  } catch (error) {
    // Só códigos fixos; nunca a chave, nunca stack.
    const reason = error instanceof SealError ? error.code : `io: ${error?.code ?? 'unexpected'}`;
    return { code: 1, report: { ok: false, error: reason } };
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const { code, report } = cli(process.argv.slice(2));
  (code === 0 ? console.log : console.error)(JSON.stringify(report));
  process.exitCode = code;
}
