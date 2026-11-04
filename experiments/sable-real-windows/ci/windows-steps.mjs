#!/usr/bin/env node
// Passos do workflow manual sable-real-windows.yml que não são o driver. Nenhum recebe a chave do envelope.
//   toolchain                                   Node 24.22.0 x64, pwsh 7 64-bit, openssl presente; mede wsl.exe --status
//   ps-parse --output-dir <novo>                grava os scripts PS de lib/windows.mjs e só os parseia (AST), sem executar
//   install-source --source-root <s> --tools-dir <novo>
//                                               pnpm 12.15.0 por npm (prefixo privado, integridade pinada), depois
//                                               pnpm install --frozen-lockfile --ignore-scripts na fonte; env allowlist
//   diagnostic --out <publico>                  se o driver não criou a saída pública, grava diagnostics.json não autorizante
//   artifact --out <publico>                    allowlist/limites antes do upload (nunca cria PASS)
//   result --out <publico>                      exige PASS e TODOS os elos REQUIRED de lib/verdict.mjs, sem reinterpretar
import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { verifySource } from '../lib/build.mjs';
import { PUBLIC_FILES, PublicEvidence, secretScan } from '../lib/evidence.mjs';
import { allowlistEnv } from '../lib/guards.mjs';
import { REQUIRED } from '../lib/verdict.mjs';
import { PS } from '../lib/windows.mjs';

const run = promisify(execFile);
export const NODE_VERSION = 'v24.22.0';
export const REGISTRY = 'https://registry.npmjs.org/';
// Identidade medida no registry oficial em 2026-11-04 (npm view ... dist.integrity).
export const PNPM = Object.freeze({
  version: '12.15.0',
  integrity: 'sha512-s5UdbW/0qfE9x89WzSjSuOs328ycaOUuHhGRhz6p+CoBcoerULqtxczElPA2xnwOR+sTYIwvo29HcRth6hKOYQ==',
  exe: '@pnpm/exe.win32-x64',
  exeIntegrity: 'sha512-nrd+Tp1We1DGj4DGG5Bea9lZNh9y1PjlLBdEwdInS4D0h0UIDtM7JaGGGDJhNzIwcHASyihWI7HLV+dtG+fhYg==',
});
export const PUBLIC_TOTAL_BYTES = 25 * 1024 * 1024;
const PUBLIC_FILE_BYTES = 8 * 1024 * 1024;
const OUTCOMES = new Set(['success', 'failure', 'cancelled', 'skipped']);

export class StepError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new StepError(code); };

// ---------- toolchain ----------
export async function toolchain({ platform = process.platform, arch = process.arch, version = process.version } = {}) {
  if (platform !== 'win32' || arch !== 'x64') fail('toolchain: requires Windows x64 runner');
  if (version !== NODE_VERSION) fail(`toolchain: node ${version} != ${NODE_VERSION}`);
  const ps = await run('pwsh', ['-NoProfile', '-NonInteractive', '-Command',
    "$ErrorActionPreference='Stop'; ConvertTo-Json -Compress -InputObject @{major=$PSVersionTable.PSVersion.Major;is64=[Environment]::Is64BitProcess;os64=[Environment]::Is64BitOperatingSystem;openssl=@(Get-Command openssl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.Source })}"],
  { timeout: 60000, windowsHide: true }).then(r => JSON.parse(r.stdout), () => fail('toolchain: pwsh absent or failed'));
  if (ps.major !== 7 || ps.is64 !== true || ps.os64 !== true) fail('toolchain: pwsh 7 64-bit required');
  if (!ps.openssl?.length) fail('toolchain: openssl absent from PATH (no install performed)');
  const openssl = await run('openssl', ['version'], { timeout: 30000, windowsHide: true }).then(r => r.stdout.trim().slice(0, 200), () => fail('toolchain: openssl version failed'));
  if (!openssl.startsWith('OpenSSL ')) fail('toolchain: openssl identity unexpected');
  // Só medida: WSL1 é exigido pelo driver no import; aqui não se habilita nem reinicia nada.
  const wsl = await new Promise(resolve => execFile('wsl.exe', ['--status'], { env: { ...process.env, WSL_UTF8: '1' }, timeout: 60000, windowsHide: true },
    (error, stdout) => resolve({ exitCode: error ? (error.code ?? 'spawn-error') : 0, text: String(stdout ?? '').replace(/\0/g, '').slice(0, 512) })));
  return { node: version, arch, pwshMajor: ps.major, opensslPath: ps.openssl[0], openssl, wslStatus: wsl };
}

// ---------- PowerShell AST ----------
const PARSE_PS = `$ErrorActionPreference='Stop'; $bad=@(); $files=@(Get-ChildItem -LiteralPath $env:ENSAIO_PS_DIR -Filter *.ps1)
foreach($f in $files){ $t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e); foreach($x in @($e)){ if($x){ $bad+=@{file=$f.Name;line=$x.Extent.StartLineNumber;message=$x.Message} } } }
ConvertTo-Json -Compress -Depth 3 -InputObject @{count=$files.Count;errors=@($bad)}`;
export function writePsScripts(dir) {
  mkdirSync(dir);
  const written = [];
  for (const [name, script] of Object.entries(PS)) {
    if (!/^[A-Za-z0-9]+$/.test(name)) fail('ps: unexpected script name');
    writeFileSync(join(dir, `${name}.ps1`), script, { flag: 'wx' });
    written.push(name);
  }
  return written;
}
export async function psParse(dir) {
  const written = writePsScripts(dir);
  const { stdout } = await run('pwsh', ['-NoProfile', '-NonInteractive', '-Command', PARSE_PS],
    { env: { ...allowlistEnv(process.env, {}), ENSAIO_PS_DIR: dir }, timeout: 120000, windowsHide: true }).catch(() => fail('ps: pwsh parser failed'));
  const parsed = JSON.parse(stdout);
  if (parsed.count !== written.length) fail('ps: not every script was parsed');
  if (parsed.errors.length) return { ok: false, scripts: written, errors: parsed.errors.slice(0, 50) };
  return { ok: true, scripts: written, errors: [] };
}

// ---------- pnpm + dependências da fonte ----------
export function npmCli(execPath = process.execPath) {
  const candidates = [join(dirname(execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'), join(dirname(execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js')];
  return candidates.find(c => existsSync(c)) ?? fail('install: npm-cli.js beside node not found');
}

// Ambiente dos filhos: só a base Windows + perfil/cache privados. Chave do envelope, tokens CI e NODE_OPTIONS nunca entram.
export function childEnv(source, tools) {
  return allowlistEnv(source, {
    USERPROFILE: join(tools, 'home'), HOME: join(tools, 'home'), APPDATA: join(tools, 'appdata'), LOCALAPPDATA: join(tools, 'local'),
    TEMP: join(tools, 'temp'), TMP: join(tools, 'temp'), npm_config_cache: join(tools, 'npm-cache'), COREPACK_ENABLE_NETWORK: '0',
  });
}

function runLogged(args, { cwd, env, log, timeout }) {
  return new Promise(resolve => {
    const fd = openSync(log, 'wx', 0o600);
    const child = spawn(process.execPath, args, { cwd, env, stdio: ['ignore', fd, fd], windowsHide: true, shell: false });
    const timer = setTimeout(() => child.kill(), timeout);
    child.once('error', () => { clearTimeout(timer); closeSync(fd); resolve('spawn-error'); });
    child.once('close', code => { clearTimeout(timer); closeSync(fd); resolve(code); });
  });
}

export function checkPnpmLock(prefix) {
  const lock = JSON.parse(readFileSync(join(prefix, 'node_modules', '.package-lock.json'), 'utf8'));
  const problems = [];
  for (const [name, integrity] of [['pnpm', PNPM.integrity], [PNPM.exe, PNPM.exeIntegrity]]) {
    const entry = lock.packages?.[`node_modules/${name}`];
    if (entry?.version !== PNPM.version || entry?.integrity !== integrity) problems.push(`install: ${name} identity differs from pin`);
    const pkg = join(prefix, 'node_modules', ...name.split('/'), 'package.json');
    if (!existsSync(pkg) || JSON.parse(readFileSync(pkg, 'utf8')).version !== PNPM.version) problems.push(`install: ${name} not installed at ${PNPM.version}`);
  }
  return problems;
}

export async function installSource({ sourceRoot, tools }) {
  if (process.platform !== 'win32' || process.arch !== 'x64' || process.version !== NODE_VERSION) fail('install: requires Windows x64 Node 24.22.0');
  if (!isAbsolute(sourceRoot) || !isAbsolute(tools) || !lstatSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) fail('install: absolute existing source root and new tools dir required');
  mkdirSync(tools);
  for (const d of ['home', 'appdata', 'local', 'temp', 'npm-cache', 'prefix', 'store', 'log']) mkdirSync(join(tools, d));
  const env = childEnv(process.env, tools), prefix = join(tools, 'prefix');
  // Logs ficam na raiz privada (podem nomear dependências); o console público recebe só o código de saída.
  const npmExit = await runLogged([npmCli(), 'install', '--prefix', prefix, '--ignore-scripts', '--no-audit', '--no-fund', '--no-update-notifier',
    `--registry=${REGISTRY}`, `pnpm@${PNPM.version}`], { cwd: prefix, env, log: join(tools, 'log', 'npm.log'), timeout: 600000 });
  if (npmExit !== 0) fail(`install: npm install pnpm exit ${npmExit}`);
  const lockProblems = checkPnpmLock(prefix);
  if (lockProblems.length) fail(lockProblems.join('; '));
  const pnpmEntry = join(prefix, 'node_modules', 'pnpm', 'bin', 'pnpm.mjs');
  const pnpmExit = await runLogged([pnpmEntry, 'install', '--frozen-lockfile', '--ignore-scripts', `--registry=${REGISTRY}`, '--store-dir', join(tools, 'store')],
    { cwd: sourceRoot, env, log: join(tools, 'log', 'pnpm.log'), timeout: 1500000 });
  if (pnpmExit !== 0) fail(`install: pnpm install --frozen-lockfile exit ${pnpmExit}`);
  const source = await verifySource(sourceRoot);
  if (!source.ok) fail(`install: verifySource ${source.problems.join('; ').slice(0, 1024)}`);
  return { pnpm: PNPM.version, entry: 'pnpm/bin/pnpm.mjs', verifySource: 'ok' };
}

// ---------- saída pública ----------
export function writeDiagnostic(out, env = process.env) {
  if (lstatSync(out, { throwIfNoEntry: false })) return { written: false, reason: 'public output already produced by driver' };
  const steps = {};
  for (const [key, value] of Object.entries(env)) {
    const m = /^SABLE_STEP_([A-Z0-9_]{1,40})$/.exec(key);
    if (m) steps[m[1].toLowerCase()] = OUTCOMES.has(value) ? value : 'unknown';
  }
  mkdirSync(out);
  new PublicEvidence(out).write('diagnostics.json', { classification: 'PUBLIC_NON_AUTHORIZING_DIAGNOSTIC', nativeAuthorization: false,
    stage: 'pre-driver', driverStarted: false, steps });
  return { written: true };
}

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
export function auditPublic(out) {
  const st = lstatSync(out, { throwIfNoEntry: false });
  if (!st?.isDirectory()) fail('artifact: public output absent');
  const problems = [], files = [];
  let total = 0;
  for (const name of readdirSync(out).sort()) {
    const full = join(out, name), s = lstatSync(full);
    if (!PUBLIC_FILES.includes(name)) { problems.push(`not allowlisted: ${name.slice(0, 64)}`); continue; }
    if (!s.isFile() || s.nlink !== 1) { problems.push(`not a single-link regular file: ${name}`); continue; }
    if (s.size > PUBLIC_FILE_BYTES) { problems.push(`too large: ${name}`); continue; }
    total += s.size;
    const bytes = readFileSync(full);
    if (name.endsWith('.png')) { if (!bytes.subarray(0, 8).equals(PNG)) problems.push(`not PNG: ${name}`); }
    else if (name.endsWith('.json')) { try { JSON.parse(bytes.toString('utf8')); } catch { problems.push(`not JSON: ${name}`); } }
    else problems.push(`unexpected type: ${name}`);
    if (secretScan(bytes, []).length) problems.push(`secret pattern: ${name}`);
    files.push({ name, size: s.size, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  if (total > PUBLIC_TOTAL_BYTES) problems.push('public total over 25 MiB');
  if (!files.length) problems.push('no public file');
  return { ok: problems.length === 0, problems, files, totalBytes: total };
}

// Leitura literal do result.json do driver: PASS só com status/nativeAuthorization/missing e cada elo REQUIRED true.
export function checkResult(out) {
  const file = join(out, 'result.json'), st = lstatSync(file, { throwIfNoEntry: false });
  if (!st?.isFile() || st.size > PUBLIC_FILE_BYTES) return { ok: false, problems: ['result.json absent'] };
  let r;
  try { r = JSON.parse(readFileSync(file, 'utf8')); } catch { return { ok: false, problems: ['result.json invalid'] }; }
  const problems = [];
  if (r.status !== 'PASS') problems.push(`status ${String(r.status).slice(0, 16)}`);
  if (r.nativeAuthorization !== true) problems.push('nativeAuthorization not true');
  if (!Array.isArray(r.missing) || r.missing.length) problems.push('missing links reported');
  const checks = r.checks && typeof r.checks === 'object' ? r.checks : {};
  for (const name of REQUIRED) if (checks[name] !== true) problems.push(`required ${name} not true`);
  for (const name of Object.keys(checks)) if (!REQUIRED.includes(name)) problems.push(`unknown check ${name.slice(0, 64)}`);
  if (r.refusedArtifacts?.length) problems.push('artifacts refused by driver audit');
  if (r.cleanupErrors?.length) problems.push('driver cleanup errors');
  return { ok: problems.length === 0, problems, status: r.status ?? null, launchMode: r.launchMode ?? null };
}

const SPEC = { toolchain: [], 'ps-parse': ['--output-dir'], 'install-source': ['--source-root', '--tools-dir'], diagnostic: ['--out'], artifact: ['--out'], result: ['--out'] };
export function parseCli(argv) {
  const [command, ...rest] = argv, spec = SPEC[command] ?? fail(`usage: ${Object.keys(SPEC).join(' | ')}`);
  const values = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!spec.includes(rest[i]) || Object.hasOwn(values, rest[i]) || typeof rest[i + 1] !== 'string' || !rest[i + 1] || rest[i + 1].startsWith('--')) fail(`usage: ${command} ${spec.join(' <v> ')} <v>`);
    values[rest[i]] = rest[i + 1];
  }
  if (spec.some(k => !Object.hasOwn(values, k))) fail(`usage: ${command} ${spec.join(' <v> ')} <v>`);
  for (const v of Object.values(values)) if (!isAbsolute(v)) fail('paths must be absolute');
  return { command, values };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const { command, values: v } = parseCli(process.argv.slice(2));
    const result = {
      toolchain: () => toolchain(),
      'ps-parse': () => psParse(v['--output-dir']),
      'install-source': () => installSource({ sourceRoot: v['--source-root'], tools: v['--tools-dir'] }),
      diagnostic: () => writeDiagnostic(v['--out']),
      artifact: () => auditPublic(v['--out']),
      result: () => checkResult(v['--out']),
    }[command];
    const value = await result();
    console.log(JSON.stringify({ command, ...value }));
    if (value.ok === false) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify({ ok: false, error: error instanceof StepError ? error.code : `unexpected ${error?.code ?? ''}`.trim() }));
    process.exitCode = 1;
  }
}
