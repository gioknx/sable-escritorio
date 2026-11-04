import { execFile, spawn } from 'node:child_process';
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

export async function querySqlite(name, script, args, env) {
  const out = await wsl(['-d', name, '-u', 'root', '--', `${VENV}/bin/python`, '-', `${DATA}/homeserver.db`, ...args], env, { input: script, timeout: 120000 });
  return JSON.parse(out.trim().split(/\r?\n/).pop());
}

export async function removeDistro(name, env) {
  await wsl(['--terminate', name], env).catch(() => {});
  await wsl(['--unregister', name], env);
}
