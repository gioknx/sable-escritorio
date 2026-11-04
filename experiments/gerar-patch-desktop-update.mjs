#!/usr/bin/env node
// Generates the recipe patch from its maintained runtime/bridge sources.
// Does not edit the input source tree or activate/configure any release channel.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECIPE = HERE;
const DEFAULT_OUT = path.join(HERE, 'patches/0015-mindtech-desktop-update.patch');
const EXISTING = [
  'electron/src/main.ts', 'electron/src/updater.ts',
  'src/lib/features/settings/AboutSettings.svelte',
  'src/lib/settings/preferences.svelte.ts',
  'electron/electron-builder.yml', 'electron/package.json',
  'pnpm-workspace.yaml', 'pnpm-lock.yaml', 'package.json',
];
export function exact(text, before, after, count = 1) {
  if (text.split(before).length - 1 !== count) throw new Error(`Unexpected source shape: ${before}`);
  return text.split(before).join(after);
}
export function mainSource(text) {
  for (const event of ['second-instance', 'open-url']) {
    const hook = `app.on('${event}',`;
    exact(text, hook, hook); // Refuse a changed lifecycle, not just matching window lines.
  }
  text = exact(text,
    "import { registerUpdater, setUpdateChannel, supportsAutoUpdate } from './updater';",
    "import {\n  preparePendingUpdateBeforeStart,\n  registerUpdater,\n  setUpdateChannel,\n  supportsAutoUpdate,\n} from './updater';");
  text = exact(text, 'let mainWindow: BrowserWindow | null = null;',
    'let mainWindow: BrowserWindow | null = null;\nlet pendingUpdateStartup = true;');
  text = exact(text, 'if (!mainWindow && app.isReady()) mainWindow = createWindow();',
    'if (!pendingUpdateStartup && !mainWindow && app.isReady()) mainWindow = createWindow();', 2);
  text = exact(text, "  app.on('activate', () => {",
    "  app.on('activate', () => {\n    if (pendingUpdateStartup) return;");
  return exact(text, '  void app.whenReady().then(() => {\n    registerDeepLinks();',
    '  void app.whenReady().then(async () => {\n    if (await preparePendingUpdateBeforeStart()) return;\n    pendingUpdateStartup = false;\n    registerDeepLinks();');
}
export function aboutSource(text) {
  return exact(text, "              { value: 'nightly', label: i18n.t('settings.updateChannelNightly') },\n", '');
}
export function preferencesSource(text) {
  if (text.includes("from '#lib/platform/electron.js'")) throw new Error('Reconcile existing Electron preference import');
  text = "import { isElectron } from '#lib/platform/electron.js';\n" + text;
  return exact(text, 'export const preferences = $state<Preferences>(load());',
    "export const preferences = $state<Preferences>(load());\n\n// This distribution has only its authenticated stable desktop channel.\nif (isElectron() && preferences.updateChannel !== 'stable') {\n  setPreference('updateChannel', 'stable');\n}");
}
export function packageSource(text) {
  const pkg = JSON.parse(text);
  if (pkg.devDependencies?.['electron-updater'] !== '6.8.11' || pkg.devDependencies?.electron !== '45.0.0') {
    throw new Error('Unexpected Electron/updater baseline');
  }
  for (const [name, version] of Object.entries({ 'builder-util-runtime': '9.7.0', semver: '7.7.4', '@types/semver': '7.8.0' })) {
    if (pkg.devDependencies[name] && pkg.devDependencies[name] !== version) throw new Error(`Existing dependency differs: ${name}`);
    pkg.devDependencies[name] = version;
  }
  return JSON.stringify(pkg, null, 2) + '\n';
}
export function workspaceSource(text) {
  if (/^overrides:/m.test(text)) throw new Error('Reconcile existing workspace overrides explicitly');
  return text.trimEnd() + "\n\noverrides:\n  'electron-updater@6.8.11>semver': 7.7.4\n";
}
export function builderSource(text) {
  if (text.includes('mindtech-updates.json')) throw new Error('Existing channel resource requires reconciliation');
  return exact(text, '\nnpmRebuild: false',
    "\n  # Optional public channel configuration; no file means updates remain disabled.\n  - from: .\n    to: .\n    filter:\n      - mindtech-updates.json\n\nnpmRebuild: false");
}
const sha = value => createHash('sha256').update(value).digest('hex');
function readPhysical(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Expected source file: ${file}`);
  return fs.readFileSync(file, 'utf8');
}
function put(root, name, bytes) {
  const target = path.join(root, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
}
function git(root, args) {
  return execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.safecrlf=true', ...args],
    { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
}
export function generate({ source, pnpmCli, out = DEFAULT_OUT, check = false, recipe = RECIPE }) {
  source = path.resolve(source);
  const metadata = JSON.parse(readPhysical(path.join(source, 'package.json')));
  const manager = /^pnpm@([^+]+)(?:\+.*)?$/.exec(metadata.packageManager ?? '');
  if (!manager || manager[1] !== '12.15.0') throw new Error('Expected source pnpm 12.15.0');
  if (!path.isAbsolute(pnpmCli)) throw new Error('Explicit absolute pinned pnpm CLI required');
  const cliVersion = execFileSync(process.execPath, [pnpmCli, '--version'], { encoding: 'utf8' }).trim();
  if (cliVersion !== manager[1]) throw new Error('Pinned pnpm CLI version mismatch');
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'sable-update-patch-'));
  const inputs = {};
  try {
    for (const name of EXISTING) {
      const bytes = readPhysical(path.join(source, name)); inputs[name] = sha(bytes); put(stage, name, bytes);
    }
    // pnpm validates the unchanged upstream dependency patches while solving the lock.
    fs.cpSync(path.join(source, 'patches'), path.join(stage, 'patches'), { recursive: true, dereference: false });
    git(stage, ['init', '-q']);
    git(stage, ['add', '--', ...EXISTING, 'patches']);
    const current = name => fs.readFileSync(path.join(stage, name), 'utf8');
    put(stage, 'electron/src/main.ts', mainSource(current('electron/src/main.ts')));
    put(stage, 'src/lib/features/settings/AboutSettings.svelte', aboutSource(current('src/lib/features/settings/AboutSettings.svelte')));
    put(stage, 'src/lib/settings/preferences.svelte.ts', preferencesSource(current('src/lib/settings/preferences.svelte.ts')));
    put(stage, 'electron/package.json', packageSource(current('electron/package.json')));
    put(stage, 'electron/electron-builder.yml', builderSource(current('electron/electron-builder.yml')));
    put(stage, 'pnpm-workspace.yaml', workspaceSource(current('pnpm-workspace.yaml')));
    const generated = [];
    const copy = (from, to) => {
      const bytes = readPhysical(path.join(recipe, from));
      inputs[`recipe/${from}`] = sha(bytes); put(stage, to, bytes); generated.push(to);
    };
    copy('desktop-bridge/updater.ts', 'electron/src/updater.ts');
    copy('desktop-bridge/runtime-modules.d.ts', 'electron/src/update-runtime-modules.d.ts');
    for (const name of ['policy', 'store', 'update-auth', 'bootstrap']) {
      copy(`desktop-update/runtime/${name}.cjs`, `electron/desktop-update/runtime/${name}.cjs`);
    }
    const emptyConfig = path.join(stage, '.empty-npmrc'); put(stage, '.empty-npmrc', '');
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/(TOKEN|SECRET|PASSWORD|AUTH|NODE_OPTIONS)/i.test(key)));
    Object.assign(env, { NPM_CONFIG_USERCONFIG: emptyConfig, NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org',
      NPM_CONFIG_STRICT_SSL: 'true', NPM_CONFIG_IGNORE_SCRIPTS: 'true' });
    execFileSync(process.execPath, [pnpmCli, 'install', '--lockfile-only', '--ignore-scripts',
      '--registry=https://registry.npmjs.org'], { cwd: stage, env, stdio: 'inherit' });
    git(stage, ['add', '-N', '-f', '--', ...generated]);
    const diff = git(stage, ['diff', '--no-ext-diff', '--binary', '--', ...EXISTING, ...generated]);
    if (!diff.includes('preparePendingUpdateBeforeStart') || !diff.includes('electron/desktop-update/runtime/bootstrap.cjs')) {
      throw new Error('Incomplete generated patch');
    }
    // All pre-existing recipe inputs must stay byte-identical throughout generation.
    for (const name of EXISTING) if (sha(readPhysical(path.join(source, name))) !== inputs[name]) throw new Error(`Input changed: ${name}`);
    for (const [name, hash] of Object.entries(inputs)) {
      if (name.startsWith('recipe/') && sha(readPhysical(path.join(recipe, name.slice(7)))) !== hash) {
        throw new Error(`Maintained source changed during generation: ${name}`);
      }
    }
    const patch = '# Generated by sable/gerar-patch-desktop-update.mjs; edit maintained sources, then regenerate.\n' + diff;
    if (check) {
      if (readPhysical(path.resolve(out)) !== patch) throw new Error('Generated recipe patch is stale');
    } else {
      fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
      fs.writeFileSync(path.resolve(out), patch);
    }
    return { out: path.resolve(out), sha256: sha(patch), inputs, sourceEdited: false, activated: false };
  } finally { fs.rmSync(stage, { recursive: true, force: true }); }
}
function cli(args) {
  const options = {};
  while (args.length) {
    const flag = args.shift();
    if (flag === '--check') options.check = true;
    else if (['--source', '--pnpm-cli', '--out'].includes(flag) && args.length) {
      options[flag === '--pnpm-cli' ? 'pnpmCli' : flag.slice(2)] = args.shift();
    } else throw new Error('Usage: --source <read-only Sable source> --pnpm-cli <pinned pnpm.cjs> [--out patch] [--check]');
  }
  if (!options.source || !options.pnpmCli) throw new Error('Explicit --source and --pnpm-cli are required');
  console.log(JSON.stringify(generate(options), null, 2));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
