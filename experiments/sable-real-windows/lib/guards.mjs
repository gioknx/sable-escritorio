import { win32 } from 'node:path';

export const ARGS = Object.freeze(['--source-root', '--recipe-root', '--electron-zip', '--wsl-rootfs', '--synapse-wheel', '--out']);

// Todos obrigatórios, absolutos, sem repetição. Faltou um => erro concreto (o driver vira ERROR).
export function parseArgs(argv, isAbsolute = win32.isAbsolute) {
  const result = {}, problems = [];
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i], value = argv[i + 1];
    if (!ARGS.includes(key)) { problems.push(`unknown argument ${String(key).slice(0, 64)}`); continue; }
    if (Object.hasOwn(result, key)) problems.push(`repeated ${key}`);
    if (typeof value !== 'string' || !value || value.startsWith('--')) { problems.push(`missing value for ${key}`); continue; }
    if (!isAbsolute(value)) problems.push(`${key} must be absolute`);
    result[key] = value;
  }
  for (const key of ARGS) if (!Object.hasOwn(result, key)) problems.push(`missing ${key}`);
  return { ok: problems.length === 0, problems, values: result };
}

// Somente o necessário para o Windows funcionar; nada de token CI, NODE_OPTIONS, ELECTRON_*, SABLE_IDENTIFIER.
const BASE = ['SystemRoot', 'SystemDrive', 'windir', 'ComSpec', 'PATHEXT', 'PATH', 'Path', 'NUMBER_OF_PROCESSORS',
  'PROCESSOR_ARCHITECTURE', 'OS', 'USERNAME', 'USERDOMAIN', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)',
  'ProgramW6432', 'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432', 'PSModulePath'];
const FORBIDDEN = /^(NODE_OPTIONS|NODE_TLS_REJECT_UNAUTHORIZED|ELECTRON_.*|SABLE_IDENTIFIER|SABLE_DIST|SABLE_DEV_URL|GITHUB_.*|ACTIONS_.*|CSC_.*|WIN_CSC_.*|.*TOKEN.*|.*SECRET.*|.*PASSWORD.*)$/i;

export function allowlistEnv(source, overrides) {
  const env = {};
  for (const key of Object.keys(source)) if (BASE.some(b => b.toLowerCase() === key.toLowerCase())) env[key] = source[key];
  for (const [key, value] of Object.entries(overrides)) {
    if (typeof value !== 'string' || !value) throw new Error(`env: empty override ${key}`);
    env[key] = value;
  }
  const bad = Object.keys(env).filter(key => FORBIDDEN.test(key));
  if (bad.length) throw new Error(`env: forbidden keys ${bad.join(',')}`);
  return env;
}

// Perfil privado completo para o processo lançado pelo driver. appData/CDP do wrapper vêm de ensaio-launch.json,
// não daqui; LOCALAPPDATA (cache do electron-updater) e a CA do feed (Node fetch do runtime) vêm daqui.
export function appEnv(source, { profile, appData, localAppData, temp, caFile }) {
  return allowlistEnv(source, {
    USERPROFILE: profile, HOME: profile, APPDATA: appData, LOCALAPPDATA: localAppData, TEMP: temp, TMP: temp,
    NODE_EXTRA_CA_CERTS: caFile,
  });
}

// NTFS curto, sem espaços (NSIS /D não aceita aspas) e todo caminho instalado < 260.
export function pathPreflight(privateRoot, installDir, relativePaths) {
  const problems = [];
  if (privateRoot.length > 48) problems.push(`private root too long (${privateRoot.length})`);
  if (/\s/.test(installDir)) problems.push('install dir has whitespace');
  const longest = relativePaths.reduce((max, rel) => Math.max(max, win32.join(installDir, rel).length), 0);
  if (longest >= 260) problems.push(`installed path length ${longest} >= 260`);
  return { ok: problems.length === 0, problems, longest };
}
