import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { win32 } from 'node:path';
import { SYNAPSE } from './pins.mjs';

// C:\a\b -> /mnt/c/a/b (montagem drvfs padrão da WSL1).
export function mntPath(windowsPath) {
  const m = /^([A-Za-z]):\\(.*)$/.exec(win32.normalize(windowsPath));
  if (!m) throw new Error('wsl: drive-absolute path required');
  return `/mnt/${m[1].toLowerCase()}/${m[2].split('\\').filter(Boolean).join('/')}`;
}
const shq = s => `'${String(s).replace(/'/g, `'\\''`)}'`;

export const DATA = '/var/lib/sable-ensaio';
export const VENV = '/opt/sable-ensaio/venv';

function wsl(args, env, { input, timeout = 900000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile('wsl.exe', args, { env: { ...env, WSL_UTF8: '1' }, timeout, maxBuffer: 1 << 24, windowsHide: true },
      (error, stdout, stderr) => error ? reject(new Error(`wsl ${args[0]}: ${String(stderr || error.message).slice(-1024)}`)) : resolve(stdout));
    if (input !== undefined) child.stdin.end(input);
  });
}
const inDistro = (name, script, env, options) => wsl(['-d', name, '-u', 'root', '--', 'sh', '-ec', script], env, options);

// WSL1 explícita, sem reboot e sem serviço externo de Matrix. Rootfs e wheel já conferidos por hash pelo driver.
export async function importDistro({ name, installDir, rootfs }, env) {
  await wsl(['--import', name, installDir, rootfs, '--version', '1'], env);
  const listed = await wsl(['--list', '--verbose'], env);
  const row = listed.split(/\r?\n/).find(l => l.replace('*', '').trim().split(/\s+/)[0] === name);
  if (!row || row.trim().split(/\s+/).pop() !== '1') throw new Error('wsl: distro is not WSL1');
  return { wslVersion: 1 };
}

export async function installSynapse(name, wheelWindowsPath, env) {
  const wheel = mntPath(wheelWindowsPath);
  await inDistro(name, [
    'export DEBIAN_FRONTEND=noninteractive',
    'apt-get update -q',
    'apt-get install -y -q --no-install-recommends python3-venv',
    `python3 -m venv ${VENV}`,
    `${VENV}/bin/pip install --no-input --disable-pip-version-check --only-binary=:all: ${shq(wheel)}`,
  ].join('\n'), env);
  const version = (await inDistro(name, `${VENV}/bin/python -c 'import synapse; print(synapse.__version__)'`, env)).trim();
  if (version !== SYNAPSE.version) throw new Error(`synapse version ${version}`);
  const freeze = await inDistro(name, `${VENV}/bin/pip freeze --all`, env);
  return { version, packages: freeze.split(/\r?\n/).filter(Boolean).slice(0, 400) };
}

// Config com segredos entra por stdin direto para arquivo 0600 dentro da distro; não passa por argv.
export async function configureSynapse(name, configJson, env) {
  await inDistro(name, `umask 077; mkdir -p ${DATA}/media_store; cat > ${DATA}/homeserver.yaml`, env, { input: configJson });
  await inDistro(name, `${VENV}/bin/python -m synapse.app.homeserver -c ${DATA}/homeserver.yaml --generate-keys`, env);
}

export function startSynapse(name, env) {
  return spawn('wsl.exe', ['-d', name, '-u', 'root', '--', `${VENV}/bin/python`, '-m', 'synapse.app.homeserver', '-c', `${DATA}/homeserver.yaml`],
    { env: { ...env, WSL_UTF8: '1' }, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
}

// The program is a private file. Only JSON travels on stdin; no identifier is in argv.
export async function querySqlite(name, script, args, env, { database = `${DATA}/homeserver.db` } = {}) {
  const file = `${DATA}/sqlite-check.py`;
  await inDistro(name, `umask 077; cat > ${file}; chmod 600 ${file}`, env, { input: script });
  if (![`${DATA}/homeserver.db`, `${DATA}/negative.db`].includes(database)) throw new Error('sqlite database outside rehearsal');
  const parameters = [database, ...args];
  const out = await wsl(['-d', name, '-u', 'root', '--exec', `${VENV}/bin/python`, file], env,
    { input: JSON.stringify(parameters), timeout: 120000 });
  const evidence = JSON.parse(out.trim());
  const expected = args.slice(0, 3).map(v => createHash('sha256').update(v).digest('hex'));
  if (JSON.stringify(evidence.parameterDigests) !== JSON.stringify(expected)) throw new Error('sqlite parameter transport changed identifiers');
  return evidence;
}

// Test-only: a private damaged copy of a coherent snapshot (event row without its JSON row).
export async function makeInconsistentCopy(name, eventId, env) {
  const program = `${DATA}/make-inconsistent.py`;
  await inDistro(name, `umask 077; cat > ${program}`, env, { input: [
    'import importlib.util, json, shutil, sqlite3, sys',
    `spec = importlib.util.spec_from_file_location('q', '${DATA}/sqlite-check.py'); q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)`,
    `with q.snapshot('${DATA}/homeserver.db') as copied:`,
    `    c = sqlite3.connect(copied); c.execute('pragma wal_checkpoint(truncate)'); c.close()`,
    `    shutil.copyfile(copied, '${DATA}/negative.db')`,
    `con = sqlite3.connect('${DATA}/negative.db'); con.execute('pragma journal_mode=delete')`,
    'con.execute("delete from event_json where event_id=?", (json.load(sys.stdin),)); con.commit(); con.close()', ''].join('\n') });
  await wsl(['-d', name, '-u', 'root', '--exec', `${VENV}/bin/python`, program], env, { input: JSON.stringify(eventId), timeout: 60000 });
}

export async function transportProbe(name, values, env, legacy = false) {
  const file = `${DATA}/transport-probe.py`;
  await inDistro(name, `umask 077; cat > ${file}`, env,
    { input: 'import json,sys\nprint(json.dumps(sys.argv[1:] if len(sys.argv)>1 else json.load(sys.stdin)))\n' });
  const out = await wsl(legacy
    ? ['-d', name, '-u', 'root', '--', `${VENV}/bin/python`, file, ...values]
    : ['-d', name, '-u', 'root', '--exec', `${VENV}/bin/python`, file], env,
    legacy ? {} : { input: JSON.stringify(values) });
  return JSON.parse(out.trim());
}

export async function removeDistro(name, env) {
  await wsl(['--terminate', name], env).catch(() => {});
  await wsl(['--unregister', name], env);
}
