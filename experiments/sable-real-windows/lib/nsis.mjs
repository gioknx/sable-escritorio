import { win32 } from 'node:path';
import { PRODUCT_EXE } from './pins.mjs';

// Regras do CommandLineToArgvW (barras antes de aspas, aspas duplas) para ler o que o CIM reporta.
export function splitWindowsCommandLine(line) {
  const args = [];
  let i = 0;
  while (i < line.length) {
    while (line[i] === ' ' || line[i] === '\t') i++;
    if (i >= line.length) break;
    let arg = '', quoted = false;
    for (; i < line.length; i++) {
      const c = line[i];
      if (c === '\\') {
        let n = 0;
        while (line[i + n] === '\\') n++;
        if (line[i + n] === '"') {
          arg += '\\'.repeat(n >> 1);
          if (n % 2) { arg += '"'; i += n; } else i += n - 1;
        } else { arg += '\\'.repeat(n); i += n - 1; }
        continue;
      }
      if (c === '"') { if (quoted && line[i + 1] === '"') { arg += '"'; i++; } else quoted = !quoted; continue; }
      if (!quoted && (c === ' ' || c === '\t')) break;
      arg += c;
    }
    args.push(arg);
  }
  return args;
}

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && win32.normalize(a).toLowerCase() === win32.normalize(b).toLowerCase();
export const insideWin = (root, child) => {
  const rel = win32.relative(root, child);
  return !!rel && !rel.startsWith('..') && !win32.isAbsolute(rel);
};

// Bridge real: update-auth emite /S; SableNsisUpdater acrescenta --updated, --force-run opcional e /D=<dir físico> por último, sem aspas.
export function validateInstallerCommand(commandLine, installer, installDir) {
  const problems = [];
  if (/\s/.test(installDir)) problems.push('installDir contains whitespace; /D cannot be quoted');
  const argv = splitWindowsCommandLine(commandLine ?? '');
  if (!same(argv[0], installer)) problems.push('argv0 is not the observed cached installer');
  const rest = argv.slice(1), want = ['/S', '--updated', '--force-run', `/D=${installDir}`];
  if (rest.length !== want.length || rest.some((a, k) => k < 3 ? a !== want[k] : !same(a.slice(3), installDir) || !a.startsWith('/D=')))
    problems.push(`unexpected installer arguments: ${JSON.stringify(rest).slice(0, 512)}`);
  if (!(commandLine ?? '').trimEnd().toLowerCase().endsWith(` /d=${installDir}`.toLowerCase())) problems.push('/D is not the last unquoted token');
  return { ok: problems.length === 0, problems, argv: argv.length };
}

const isMain = row => typeof row.commandLine === 'string' && !/\s--type=/.test(row.commandLine);
const time = value => (typeof value === 'string' ? Date.parse(value) : NaN);
const argsOf = row => splitWindowsCommandLine(row.commandLine ?? '').slice(1);

// Janela após o exit do instalador para a criação assíncrona via shell (ExecShellAsUser).
export const LAUNCH_WINDOW_MS = 10000;
// Assinante do explorer.exe da caixa de entrada do Windows (Authenticode/catálogo).
const MICROSOFT_WINDOWS = rdn => rdn.CN === 'Microsoft Windows' && rdn.O === 'Microsoft Corporation';
function parseSubject(subject) {
  const out = {};
  for (const part of String(subject ?? '').split(/,\s*(?=[A-Z]+=)/)) {
    const k = part.indexOf('=');
    if (k > 0) out[part.slice(0, k).trim()] = part.slice(k + 1).trim();
  }
  return out;
}

// rows: amostras CIM do observador {pid,parent,executable,commandLine,created,sid,sessionId,sha256?,sha512?,parentFacts?};
// exits: Map pid -> {exitCode, exitedAt}. Dois modos aceitos, nunca "qualquer pai":
//  direct: pai real do app reaberto = PID do instalador observado;
//  nsis-shell-broker: pai = explorer.exe canônico, assinado Microsoft (Valid), mesmo SID/sessão, criado antes do app.
// Em ambos: app exato no diretório instalado, args exatamente ['--updated'], hash = 2.2.3, PID não criado pelo driver,
// criação entre início do instalador e exit + janela, driver sem lançar app depois do instalador, instalador
// filho do seed com comando NSIS exato, payload SHA512 autenticado e exit 0 observados pelo SO.
export function validateProcessChain(rows, exits, o) {
  const problems = [], byPid = new Map();
  for (const row of rows) if (Number.isInteger(row.pid) && row.pid > 0 && !byPid.has(row.pid)) byPid.set(row.pid, row);
  const all = [...byPid.values()];
  const appExe = win32.join(o.installDir, PRODUCT_EXE);
  const driverPids = new Set(o.driverSpawns.map(s => s.pid));
  const seed = byPid.get(o.seedPid);
  if (!seed || !same(seed.executable, appExe) || argsOf(seed).length !== 0) problems.push('relaunched seed not observed with genuine image/argv');
  const installers = all.filter(r => r.parent === o.seedPid && insideWin(o.cacheRoot, r.executable) && /\.exe$/i.test(r.executable));
  if (installers.length !== 1) problems.push(`expected exactly one installer child of seed, saw ${installers.length}`);
  const installer = installers[0];
  const updatedMains = all.filter(r => same(r.executable, appExe) && isMain(r) && argsOf(r).includes('--updated'));
  if (updatedMains.length !== 1) problems.push(`expected exactly one app main with --updated, saw ${updatedMains.length}`);
  const reopened = updatedMains[0];
  let launchMode = null;
  if (installer) {
    problems.push(...validateInstallerCommand(installer.commandLine, installer.executable, o.installDir).problems);
    if (installer.sha512 !== o.expectedInstallerSha512) problems.push('installer image is not the authenticated payload');
    if (driverPids.has(installer.pid)) problems.push('installer pid was spawned by driver');
    const exit = exits.get(installer.pid);
    if (!exit) problems.push('installer exit not observed');
    else if (exit.exitCode !== 0) problems.push(`installer exit ${exit.exitCode}`);
    const lateSpawn = o.driverSpawns.filter(s => same(s.image, appExe) && time(s.at) >= time(installer.created));
    if (lateSpawn.length) problems.push('driver launched the app after the installer started');
    if (reopened) {
      const a = argsOf(reopened);
      if (a.length !== 1 || a[0] !== '--updated') problems.push(`reopened args not NSIS StartApp: ${JSON.stringify(a).slice(0, 256)}`);
      if (driverPids.has(reopened.pid) || reopened.pid === o.seedPid || reopened.pid === installer.pid) problems.push('reopened pid not new');
      if (reopened.sha256 !== o.expectedExeSha256) problems.push('reopened image hash is not the 2.2.3 executable');
      const created = time(reopened.created), start = time(installer.created), end = exit ? time(exit.exitedAt) + LAUNCH_WINDOW_MS : NaN;
      if (!(created >= start && created <= end)) problems.push('reopened creation outside installer lifetime window');
      const ids = [seed, installer, reopened].filter(Boolean);
      if (ids.some(r => typeof r.sid !== 'string' || r.sid !== reopened.sid)) problems.push('user SID differs across chain');
      if (ids.some(r => !Number.isInteger(r.sessionId) || r.sessionId !== reopened.sessionId)) problems.push('session differs across chain');
      if (reopened.parent === installer.pid) launchMode = 'direct';
      else {
        const p = reopened.parentFacts;
        const brokerProblems = [];
        if (!p || p.pid !== reopened.parent) brokerProblems.push('parent facts not observed');
        else {
          if (!same(p.executable, o.explorerPath)) brokerProblems.push('parent is not the canonical explorer.exe');
          if (p.signatureStatus !== 'Valid' || !MICROSOFT_WINDOWS(parseSubject(p.signer))) brokerProblems.push('parent signature is not valid Microsoft Windows');
          if (p.sid !== reopened.sid || p.sessionId !== reopened.sessionId) brokerProblems.push('parent SID/session differs');
          if (!(time(p.created) < created)) brokerProblems.push('parent not created before reopened app');
          if (driverPids.has(p.pid) || byPid.has(p.pid)) brokerProblems.push('parent pid belongs to ensaio processes');
        }
        if (brokerProblems.length) problems.push(`reopened parent is neither installer nor genuine shell broker: ${brokerProblems.join('; ')}`);
        else launchMode = 'nsis-shell-broker';
      }
    }
  }
  const strayMains = all.filter(r => same(r.executable, appExe) && isMain(r) && r.pid !== o.seedPid && r.pid !== reopened?.pid
    && !o.driverSpawns.some(s => s.pid === r.pid && installer && time(s.at) < time(installer.created)));
  if (strayMains.length) problems.push(`app main processes outside chain: ${strayMains.map(r => r.pid).join(',')}`);
  const mains = all.filter(r => same(r.executable, appExe) && isMain(r))
    .map(r => ({ pid: r.pid, parent: r.parent, args: argsOf(r).slice(0, 4), created: r.created ?? null }));
  const ok = problems.length === 0 && launchMode !== null;
  return { ok, launchMode: ok ? launchMode : null, problems, installer: installer ?? null, reopened: reopened ?? null, mains };
}
