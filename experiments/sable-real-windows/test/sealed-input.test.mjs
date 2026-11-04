// UNIT real (crypto e arquivos do Node, sem mock) do envelope SABLE-TI v1 de ci/sealed-input.mjs.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DOMAIN, HEADER_BYTES, MAGIC, OVERHEAD, TAG_BYTES, cli, open, parseKey, readKeyEnv, seal } from '../ci/sealed-input.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'ci', 'sealed-input.mjs');
const dirs = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), 'sable-seal-')); dirs.push(d); return d; };
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const sha = b => createHash('sha256').update(b).digest('hex');
const keyB64 = () => randomBytes(32).toString('base64');
const errorOf = fn => { try { fn(); } catch (e) { return e.code; } return null; };
const onlyFiles = (d, expected) => assert.deepEqual(readdirSync(d).sort(), [...expected].sort());

function fixture(size = 3 * 1024 * 1024 + 7) {
  const d = temp(), plain = randomBytes(size), input = join(d, 'bundle.tar.gz'), blob = join(d, 'bundle.sealed');
  writeFileSync(input, plain);
  const k = keyB64(), key = parseKey(k);
  return { d, plain, input, blob, k, key, sealed: seal({ input, output: blob, key }) };
}

test('round trip over several chunks: layout, header, AAD-bound tag and hashes are exact', () => {
  const f = fixture();
  const bytes = readFileSync(f.blob);
  assert.equal(bytes.length, f.plain.length + OVERHEAD);
  assert.deepEqual(f.sealed, { sha256: sha(bytes), size: bytes.length, plaintextSha256: sha(f.plain), plaintextSize: f.plain.length });
  assert.ok(bytes.subarray(0, 8).equals(MAGIC));
  assert.equal(bytes[8], 1); assert.equal(bytes[9], 1); assert.equal(bytes.readUInt16BE(10), 0);
  assert.equal(bytes.readBigUInt64BE(24), BigInt(f.plain.length));
  // Decifração independente com a especificação documentada: AAD = DOMAIN || header.
  const d = createDecipheriv('aes-256-gcm', f.key, bytes.subarray(12, 24), { authTagLength: 16 });
  d.setAAD(Buffer.concat([DOMAIN, bytes.subarray(0, HEADER_BYTES)]));
  d.setAuthTag(bytes.subarray(bytes.length - TAG_BYTES));
  assert.ok(Buffer.concat([d.update(bytes.subarray(HEADER_BYTES, bytes.length - TAG_BYTES)), d.final()]).equals(f.plain));
  const out = join(f.d, 'out.tar.gz');
  const opened = open({ input: f.blob, output: out, key: f.key, expectSha256: f.sealed.sha256, expectSize: f.sealed.size, expectPlaintextSha256: f.sealed.plaintextSha256 });
  assert.deepEqual(opened, f.sealed);
  assert.ok(readFileSync(out).equals(f.plain));
  onlyFiles(f.d, ['bundle.tar.gz', 'bundle.sealed', 'out.tar.gz']);
});

test('empty plaintext and fresh nonce per seal', () => {
  const d = temp(), input = join(d, 'empty'), key = parseKey(keyB64());
  writeFileSync(input, '');
  const a = seal({ input, output: join(d, 'a'), key }), b = seal({ input, output: join(d, 'b'), key });
  assert.equal(a.size, OVERHEAD);
  assert.notEqual(a.sha256, b.sha256);
  assert.notDeepEqual(readFileSync(join(d, 'a')).subarray(12, 24), readFileSync(join(d, 'b')).subarray(12, 24));
  open({ input: join(d, 'a'), output: join(d, 'plain'), key });
  assert.equal(statSync(join(d, 'plain')).size, 0);
});

test('key must be canonical base64 of exactly 32 bytes; one trailing LF allowed', () => {
  const k = keyB64(), alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  assert.equal(parseKey(`${k}\n`).length, 32);
  // Último caractere com os 2 bits de preenchimento ≠ 0: o Node decodifica os mesmos 32 bytes, mas não é canônico.
  const loose = `${k.slice(0, 42)}${alphabet[alphabet.indexOf(k[42]) | 1]}=`;
  assert.ok(Buffer.from(loose, 'base64').equals(Buffer.from(k, 'base64')));
  assert.equal(errorOf(() => parseKey(undefined)), 'key absent');
  for (const bad of ['', randomBytes(31).toString('base64'), randomBytes(33).toString('base64'), ` ${k}`, `${k}\n\n`, `${k}\r\n`,
    k.replace(/=$/, ''), loose, `${k.slice(0, 42)}-=`]) {
    assert.equal(errorOf(() => parseKey(bad)), 'key not canonical base64 of 32 bytes', JSON.stringify(bad.length));
  }
});

test('key env is read once and removed from the environment; absent env fails', () => {
  const env = { SABLE_TEST_INPUT_KEY: keyB64(), OTHER: 'x' };
  assert.equal(readKeyEnv('SABLE_TEST_INPUT_KEY', env).length, 32);
  assert.deepEqual(Object.keys(env), ['OTHER']);
  assert.equal(errorOf(() => readKeyEnv('SABLE_TEST_INPUT_KEY', env)), 'key env absent');
  assert.equal(errorOf(() => readKeyEnv('bad-name', {})), 'key env name');
});

test('wrong key: authentication fails, no output and no partial file remain', () => {
  const f = fixture(70000);
  assert.equal(errorOf(() => open({ input: f.blob, output: join(f.d, 'out'), key: parseKey(keyB64()) })), 'authentication failed (wrong key, tampered or truncated blob)');
  onlyFiles(f.d, ['bundle.tar.gz', 'bundle.sealed']);
});

test('tamper anywhere (ciphertext, tag, nonce, length, magic, version, reserved) is refused without output', () => {
  const f = fixture(5000), original = readFileSync(f.blob);
  const cases = [
    [HEADER_BYTES + 100, 'authentication failed (wrong key, tampered or truncated blob)'],
    [original.length - 1, 'authentication failed (wrong key, tampered or truncated blob)'],
    [15, 'authentication failed (wrong key, tampered or truncated blob)'],
    [0, 'not a SABLE-TI blob'],
    [8, 'unsupported version'],
    [9, 'unsupported algorithm or reserved bits'],
    [11, 'unsupported algorithm or reserved bits'],
    [31, 'blob truncated or extended'],
  ];
  for (const [at, code] of cases) {
    const bad = Buffer.from(original); bad[at] ^= 0x01;
    const file = join(f.d, `bad-${at}`);
    writeFileSync(file, bad);
    assert.equal(errorOf(() => open({ input: file, output: join(f.d, `out-${at}`), key: f.key })), code, `byte ${at}`);
    assert.equal(existsSync(join(f.d, `out-${at}`)), false);
    rmSync(file);
  }
  onlyFiles(f.d, ['bundle.tar.gz', 'bundle.sealed']);
});

test('truncation, extension and a rewritten length field are refused', () => {
  const f = fixture(4096), original = readFileSync(f.blob);
  const shortened = join(f.d, 'short'), longer = join(f.d, 'long'), relabeled = join(f.d, 'relabeled'), tiny = join(f.d, 'tiny');
  writeFileSync(shortened, original.subarray(0, original.length - 1));
  writeFileSync(longer, Buffer.concat([original, Buffer.from([0])]));
  writeFileSync(tiny, original.subarray(0, OVERHEAD - 1));
  // Comprimento reescrito para casar com o arquivo truncado: o header está no AAD, a tag recusa.
  const r = Buffer.from(original.subarray(0, original.length - 16)); r.writeBigUInt64BE(BigInt(4096 - 16), 24);
  writeFileSync(relabeled, r);
  for (const file of [shortened, longer, tiny]) assert.equal(errorOf(() => open({ input: file, output: join(f.d, 'o'), key: f.key })), 'blob truncated or extended');
  assert.equal(errorOf(() => open({ input: relabeled, output: join(f.d, 'o'), key: f.key })), 'authentication failed (wrong key, tampered or truncated blob)');
  assert.equal(existsSync(join(f.d, 'o')), false);
});

test('expected sha256/size are checked before decryption; plaintext sha optional', () => {
  const f = fixture(2048), out = join(f.d, 'out');
  assert.equal(errorOf(() => open({ input: f.blob, output: out, key: f.key, expectSha256: 'a'.repeat(64) })), 'blob sha256 differs from expected');
  assert.equal(errorOf(() => open({ input: f.blob, output: out, key: f.key, expectSize: f.sealed.size + 1 })), 'blob size differs from expected');
  assert.equal(errorOf(() => open({ input: f.blob, output: out, key: f.key, expectSha256: 'A'.repeat(64) })), 'expected sha256 must be 64 lowercase hex');
  assert.equal(errorOf(() => open({ input: f.blob, output: out, key: f.key, expectPlaintextSha256: 'b'.repeat(64) })), 'plaintext sha256 differs from expected');
  assert.equal(existsSync(out), false);
});

test('existing destination is preserved for seal and open; inputs must be regular files', () => {
  const f = fixture(1024), out = join(f.d, 'existing');
  writeFileSync(out, 'keep');
  assert.equal(errorOf(() => open({ input: f.blob, output: out, key: f.key })), 'output already exists');
  assert.equal(errorOf(() => seal({ input: f.input, output: out, key: f.key })), 'output already exists');
  assert.equal(readFileSync(out, 'utf8'), 'keep');
  symlinkSync(f.blob, join(f.d, 'link'));
  assert.equal(errorOf(() => open({ input: join(f.d, 'link'), output: join(f.d, 'x'), key: f.key })), 'input must be an existing regular file');
  assert.equal(errorOf(() => seal({ input: f.d, output: join(f.d, 'x'), key: f.key })), 'input must be an existing regular file');
  onlyFiles(f.d, ['bundle.tar.gz', 'bundle.sealed', 'existing', 'link']);
});

test('bounded sizes: seal and open refuse over --max-bytes', () => {
  const f = fixture(1000);
  assert.equal(errorOf(() => seal({ input: f.input, output: join(f.d, 'x'), key: f.key, maxBytes: 999 })), 'input over size limit');
  assert.equal(errorOf(() => open({ input: f.blob, output: join(f.d, 'x'), key: f.key, maxBytes: 999 })), 'input over size limit');
  assert.equal(existsSync(join(f.d, 'x')), false);
});

test('CLI as real processes: key only from file/env, never echoed; strict options', () => {
  const f = fixture(200000), keyFile = join(f.d, 'key.b64');
  writeFileSync(keyFile, `${f.k}\n`, { mode: 0o600 });
  const sealed = spawnSync(process.execPath, [CLI, 'seal', '--input', f.input, '--output', join(f.d, 'cli.sealed'), '--key-file', keyFile], { encoding: 'utf8' });
  assert.equal(sealed.status, 0, sealed.stderr);
  const report = JSON.parse(sealed.stdout);
  assert.equal(report.ok, true); assert.equal(report.size, f.plain.length + OVERHEAD);
  const opened = spawnSync(process.execPath, [CLI, 'open', '--input', join(f.d, 'cli.sealed'), '--output', join(f.d, 'cli.tar.gz'), '--key-env', 'SABLE_TEST_INPUT_KEY',
    '--expect-sha256', report.sha256, '--expect-size', String(report.size)], { encoding: 'utf8', env: { PATH: process.env.PATH, SABLE_TEST_INPUT_KEY: f.k } });
  assert.equal(opened.status, 0, opened.stderr);
  assert.ok(readFileSync(join(f.d, 'cli.tar.gz')).equals(f.plain));
  const wrong = spawnSync(process.execPath, [CLI, 'open', '--input', join(f.d, 'cli.sealed'), '--output', join(f.d, 'w'), '--key-env', 'SABLE_TEST_INPUT_KEY'],
    { encoding: 'utf8', env: { PATH: process.env.PATH, SABLE_TEST_INPUT_KEY: keyB64() } });
  assert.equal(wrong.status, 1);
  assert.deepEqual(JSON.parse(wrong.stderr), { ok: false, error: 'authentication failed (wrong key, tampered or truncated blob)' });
  for (const r of [sealed, opened, wrong]) assert.ok(!(r.stdout + r.stderr).includes(f.k) && !(r.stdout + r.stderr).includes(f.k.slice(0, 20)));
  assert.equal(existsSync(join(f.d, 'w')), false);
  for (const argv of [['open', '--input', f.blob, '--output', join(f.d, 'y'), '--key', f.k], ['seal', '--input', f.input, '--input', f.input, '--output', 'y', '--key-file', keyFile],
    ['open', '--input', f.blob, '--output', join(f.d, 'y')], ['decrypt'], ['open', '--input', f.blob, '--output', join(f.d, 'y'), '--key-env', 'K', '--expect-size', '-1']]) {
    const r = cli(argv, { K: f.k });
    assert.equal(r.code, 1, argv.join(' '));
    assert.ok(!JSON.stringify(r.report).includes(f.k));
  }
  assert.equal(existsSync(join(f.d, 'y')), false);
});
