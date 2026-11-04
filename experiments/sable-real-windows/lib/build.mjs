import { execFile } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { asarPackageVersion } from './asar.mjs';
import { hashFile, inventory } from './inventory.mjs';
import { CONSOLIDATED_LAYOUT, ELECTRON, IDENTIFIER, NATIVE, OFFICE_HOMESERVER, PRODUCT_EXE, SOURCE_PINS, TOOL_VERSIONS, UPDATES_RESOURCE } from './pins.mjs';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
export const ENTRY_DIR = join(here, '..', 'entry');
export const ENTRY_NAME = 'ensaio-entry.cjs';
export const ENTRY_FILES = Object.freeze([ENTRY_NAME, 'ensaio-launch.cjs']);

// Fuses exigidos por electron/after-pack.mjs (índices de @electron/fuses FuseV1Options).
export const EXPECTED_FUSES = Object.freeze({ 0: '0', 1: '1', 2: '0', 3: '0', 4: '1', 5: '1', 7: '0' });
const SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX');
export function readFuses(bytes) {
  const at = bytes.indexOf(SENTINEL);
  if (at < 0 || bytes.lastIndexOf(SENTINEL) !== at) throw new Error('fuses: sentinel absent or repeated');
  const version = bytes[at + SENTINEL.length], length = bytes[at + SENTINEL.length + 1];
  if (version !== 1) throw new Error(`fuses: wire version ${version}`);
  return [...bytes.subarray(at + SENTINEL.length + 2, at + SENTINEL.length + 2 + length)].map(b => String.fromCharCode(b));
}
export function checkFuses(wire) {
  return Object.entries(EXPECTED_FUSES).filter(([i, v]) => wire[Number(i)] !== v).map(([i]) => `fuse ${i}`);
}

// Fonte materializada pela mãe: pins de build/guards, versões exatas das ferramentas, guard office original.
export async function verifySource(sourceRoot) {
  const problems = [];
  for (const [rel, sha] of Object.entries(SOURCE_PINS)) {
    const file = join(sourceRoot, rel);
    if (!existsSync(file)) problems.push(`missing ${rel}`);
    else if (hashFile(file) !== sha) problems.push(`pin drift ${rel}`);
  }
  for (const [rel, version] of Object.entries(TOOL_VERSIONS)) {
    const file = join(sourceRoot, rel, 'package.json');
    const got = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')).version : null;
    if (got !== version) problems.push(`${rel} version ${got} != ${version}`);
  }
  for (const rel of ['electron/dist', 'electron/release', UPDATES_RESOURCE]) if (existsSync(join(sourceRoot, rel))) problems.push(`${rel} must not pre-exist`);
  for (const rel of CONSOLIDATED_LAYOUT) if (!existsSync(join(sourceRoot, rel))) problems.push(`0015 layout missing ${rel}`);
  const main = join(sourceRoot, 'electron/src/main.ts');
  if (existsSync(main) && !readFileSync(main, 'utf8').includes('await preparePendingUpdateBeforeStart()')) problems.push('0015 main.ts pending-update guard absent');
  if (!problems.length) {
    const { assertOfficeConfigFile } = await import(pathToFileURL(join(sourceRoot, 'electron/office-config.mjs')).href);
    try { assertOfficeConfigFile(join(sourceRoot, 'static/config.json')); } catch (e) { problems.push(String(e.message).slice(0, 256)); }
  }
  return { ok: problems.length === 0, problems };
}

// recipe.json (receita da mãe): {schema:1, patch:{name,sha256}, nativeModules:{name:{path,sha256}},
// frontendInputs:[{path,sha256}], sourceFiles:[{path,sha256}]}. Caminhos relativos à source-root, exceto nativos (absolutos).
export function verifyRecipe(recipeRoot, sourceRoot) {
  const problems = [];
  const file = join(recipeRoot, 'recipe.json');
  if (!existsSync(file)) return { ok: false, problems: ['recipe.json absent'] };
  const recipe = JSON.parse(readFileSync(file, 'utf8'));
  const keys = Object.keys(recipe).sort().join();
  if (recipe.schema !== 1 || keys !== 'frontendInputs,nativeModules,patch,schema,sourceFiles') problems.push('recipe schema');
  for (const [name, sha] of Object.entries(NATIVE)) {
    const entry = recipe.nativeModules?.[name];
    if (!entry || entry.sha256 !== sha) problems.push(`native ${name} not the published pin`);
    else if (!existsSync(entry.path) || hashFile(entry.path) !== sha) problems.push(`native ${name} bytes differ`);
  }
  for (const list of ['frontendInputs', 'sourceFiles']) {
    if (!Array.isArray(recipe[list]) || recipe[list].length === 0) { problems.push(`${list} empty`); continue; }
    for (const { path, sha256 } of recipe[list]) {
      const full = join(sourceRoot, path);
      if (path.split(/[\\/]/).includes('..') || !existsSync(full) || hashFile(full) !== sha256) problems.push(`${list}: ${String(path).slice(0, 128)}`);
    }
  }
  const listed = new Set((Array.isArray(recipe.sourceFiles) ? recipe.sourceFiles : []).map(f => f.path));
  for (const rel of CONSOLIDATED_LAYOUT) if (!listed.has(rel)) problems.push(`sourceFiles lacks 0015 ${rel}`);
  if (typeof recipe.patch?.name !== 'string' || !/^[a-f0-9]{64}$/.test(recipe.patch?.sha256 ?? '')) problems.push('patch identity');
  return { ok: problems.length === 0, problems, recipe, recipeSha256: hashFile(file) };
}

// Frontend genuíno (script "build" = vite build) sem o prebuild Rust/WASM: os bytes WASM vêm comprovados da receita.
export async function buildFrontend(sourceRoot, env) {
  await run(process.execPath, [join(sourceRoot, 'node_modules/vite/bin/vite.js'), 'build'], { cwd: sourceRoot, env, maxBuffer: 64 << 20, timeout: 1800000 });
  const { assertOfficeConfigFile } = await import(pathToFileURL(join(sourceRoot, 'electron/office-config.mjs')).href);
  assertOfficeConfigFile(join(sourceRoot, 'dist/config.json'));
  const config = JSON.parse(readFileSync(join(sourceRoot, 'dist/config.json'), 'utf8'));
  if (config.homeserverList[0] !== OFFICE_HOMESERVER) throw new Error('office homeserver changed');
  return { distConfigSha256: hashFile(join(sourceRoot, 'dist/config.json')) };
}

// Mesmas opções do trecho esbuild de electron/build.mjs (pin acima), sem cargo: DLL publicada copiada e conferida.
export async function buildElectronMain(sourceRoot, recipe) {
  const electronDir = join(sourceRoot, 'electron'), out = join(electronDir, 'dist');
  mkdirSync(out);
  for (const [name, sha] of Object.entries(NATIVE)) {
    const target = join(out, `${name}.node`);
    copyFileSync(recipe.nativeModules[name].path, target);
    if (hashFile(target) !== sha) throw new Error(`native ${name} copy mismatch`);
  }
  const { build } = await import(pathToFileURL(join(electronDir, 'node_modules/esbuild/lib/main.js')).href);
  const { browserCsp } = await import(pathToFileURL(join(sourceRoot, 'scripts/build/csp.mjs')).href);
  const { csp } = JSON.parse(readFileSync(join(sourceRoot, 'src-tauri/tauri.conf.json'), 'utf8')).app.security;
  await build({
    entryPoints: {
      main: join(electronDir, 'src/main.ts'),
      preload: join(electronDir, 'src/preload.ts'),
      'core-host': join(electronDir, 'src/core-host.ts'),
      'audiofox-host': join(electronDir, 'src/audiofox-host.ts'),
    },
    outdir: out,
    outExtension: { '.js': '.cjs' },
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node24',
    external: ['electron', './sable_node.node'],
    define: {
      __SABLE_CSP__: JSON.stringify(browserCsp(csp)),
      __SABLE_IDENTIFIER__: JSON.stringify(IDENTIFIER),
      __SABLE_SENTRY__: JSON.stringify({ dsn: undefined, environment: undefined, release: undefined }),
    },
    sourcemap: true,
  });
  for (const name of ENTRY_FILES) copyFileSync(join(ENTRY_DIR, name), join(out, name));
  const names = ['main.cjs', 'preload.cjs', 'core-host.cjs', 'audiofox-host.cjs', ...ENTRY_FILES];
  return Object.fromEntries(names.map(n => [n, hashFile(join(out, n))]));
}

// electron-builder 26.18 com a config stable original por extends; só NSIS x64, --publish never, Electron do zip pinado.
export function builderConfig(sourceRoot, { version, output, electronZip }) {
  return {
    extends: `file:${join(sourceRoot, 'electron', 'electron-builder.stable.yml')}`,
    directories: { output },
    electronDist: electronZip,
    electronVersion: ELECTRON.version,
    extraMetadata: { version, main: `dist/${ENTRY_NAME}` },
  };
}

// O recurso entra pelo extraResources do 0015 (from electron/); a fixture só cria o arquivo desta execução.
export function placeUpdatesResource(sourceRoot, text) {
  const file = join(sourceRoot, UPDATES_RESOURCE);
  writeFileSync(file, text, { flag: 'wx' });
  return file;
}

export async function packageVersion(sourceRoot, options, env) {
  const configFile = join(options.privateDir, `builder-${options.version}.json`);
  writeFileSync(configFile, JSON.stringify(builderConfig(sourceRoot, options), null, 1), { flag: 'wx' });
  const electronDir = join(sourceRoot, 'electron');
  await run(process.execPath, [join(electronDir, 'node_modules/electron-builder/cli.js'), '--win', 'nsis', '--x64',
    '--publish', 'never', '--projectDir', electronDir, '--config', configFile], { cwd: electronDir, env, maxBuffer: 64 << 20, timeout: 1800000 });
  return inspectPackage(options);
}

export function inspectPackage({ version, output, updatesJson }) {
  const unpacked = join(output, 'win-unpacked'), installer = join(output, `sable-${version}-x64.exe`), problems = [];
  const resources = join(unpacked, 'resources');
  const pkg = asarPackageVersion(join(resources, 'app.asar'));
  if (pkg.version !== version || pkg.main !== `dist/${ENTRY_NAME}`) problems.push('asar package version/main');
  for (const [name, sha] of Object.entries(NATIVE)) {
    if (hashFile(join(resources, 'app.asar.unpacked/dist', `${name}.node`)) !== sha) problems.push(`packaged ${name} differs`);
  }
  if (hashFile(join(resources, 'mindtech-updates.json')) !== hashFile(updatesJson)) problems.push('updates resource differs');
  if (!existsSync(join(resources, 'app-update.yml'))) problems.push('builder app-update.yml absent');
  problems.push(...checkFuses(readFuses(readFileSync(join(unpacked, PRODUCT_EXE)))));
  const items = inventory(unpacked);
  return { ok: problems.length === 0, problems, version, installer, unpacked, items,
    installerSha256: hashFile(installer), installerSha512: hashFile(installer, 'sha512', 'base64'),
    installerSize: statSync(installer).size, exeSha256: hashFile(join(unpacked, PRODUCT_EXE)) };
}
