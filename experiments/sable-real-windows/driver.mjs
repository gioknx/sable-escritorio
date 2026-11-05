#!/usr/bin/env node
// Driver do ensaio real Sable 2.2.2 -> 2.2.3 em Windows descartável. Fora de win32/x64: BLOCKED exit 78.
// Qualquer elo ausente ou não correlacionado => ERROR; diagnostics nunca autorizam PASS.
import { spawn, execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { asarPackageVersion } from './lib/asar.mjs';
import { buildElectronMain, buildFrontend, packageVersion, placeUpdatesResource, verifyRecipe, verifySource } from './lib/build.mjs';
import { Cdp, CorePage, browserPid, waitEndpoint } from './lib/cdp.mjs';
import { PublicEvidence } from './lib/evidence.mjs';
import { envelope, signingKey, startFeed, updatesResource } from './lib/feed.mjs';
import { allowlistEnv, appEnv, parseArgs, pathPreflight } from './lib/guards.mjs';
import { compareInventory, hashFile, inventory } from './lib/inventory.mjs';
import { validateProcessChain } from './lib/nsis.mjs';
import { ELECTRON, IDENTIFIER, PRODUCT_EXE, SYNAPSE, VERSIONS, WSL_ROOTFS } from './lib/pins.mjs';
import { SQLITE_CHECK_PY, databaseDiagnostic, generateSecrets, homeserverConfig, registerSyntheticAccount, secretValues, validateDatabaseEvidence } from './lib/synapse.mjs';
import { applyDiffs, findConfirmed, findDecrypted } from './lib/timeline.mjs';
import { decide } from './lib/verdict.mjs';
import { PS, parseWatcherLog, pwsh, pwshJson, startWatcher } from './lib/windows.mjs';
import { DATA, configureSynapse, importDistro, installSynapse, querySqlite, removeDistro, startSynapse } from './lib/wsl.mjs';

const run = promisify(execFile);
const { LAUNCH, MARKER } = createRequire(import.meta.url)('./entry/ensaio-launch.cjs');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const NSIS_EXTRAS = ['Uninstall Sable.exe', 'uninstallerIcon.ico'];
const short = e => String(e?.message ?? e).slice(0, 1024);

async function until(label, deadlineMs, probe) {
  const end = Date.now() + deadlineMs;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timeout: ${label}`);
    await sleep(250);
  }
}

// Processo próprio: guarda pid real, saída limitada e código de término.
// Todo processo criado pelo driver entra em `spawned` (pid, imagem, instante anterior ao spawn) e nunca sai:
// a cadeia NSIS rejeita reabertura com PID do driver ou app lançado pelo driver depois do instalador.
const spawned = [];
function own(exe, args, env, live) {
  const at = new Date().toISOString();
  const child = spawn(exe, args, { env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  spawned.push({ pid: child.pid ?? null, image: exe, at });
  const record = { pid: child.pid ?? null, exitCode: undefined, signal: null, stderrTail: '' };
  child.stdout.resume();
  child.stderr.on('data', b => { record.stderrTail = (record.stderrTail + b.toString('utf8')).slice(-4096); });
  record.done = new Promise(resolve => child.once('close', (code, signal) => { record.exitCode = code; record.signal = signal; resolve(record); }));
  child.once('error', e => { record.spawnError = short(e); });
  live.add(record);
  return record;
}

async function freePort() {
  const { createServer } = await import('node:net');
  return new Promise((resolve, reject) => {
    const s = createServer(); s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

async function syncLive(core) {
  return until('sync live', 180000, async () => (await core.call('session.sync_status', {}))?.state === 'live');
}

async function waitTimeline(core, subscription, start, predicate, label) {
  let items = start;
  return until(label, 180000, async () => {
    for (const event of await core.drain()) {
      if (event?.type === 'timeline_diff' && event.subscription === subscription) items = applyDiffs(items, event.diffs);
    }
    return predicate(items);
  });
}

const electronCall = (core, name, args = []) => core.fn(`function (n, a) {
  return Promise.resolve(window.sableElectron[n](...a)).then(v => ({ ok: v === undefined ? null : v }), e => ({ err: String(e && e.message || e).slice(0, 512) }));
}`, [name, args]);

export async function main(argv = process.argv.slice(2), platform = process.platform, arch = process.arch) {
  const parsed = parseArgs(argv);
  if (platform !== 'win32' || arch !== 'x64') {
    console.log(JSON.stringify({ status: 'BLOCKED', nativeAuthorization: false,
      reason: 'Requires disposable Windows x64 runner with WSL1; Node UNIT is not Native', argumentProblems: parsed.problems }));
    return 78;
  }
  if (!parsed.ok) {
    console.log(JSON.stringify({ status: 'ERROR', nativeAuthorization: false, reason: 'arguments', argumentProblems: parsed.problems }));
    return 1;
  }
  const a = parsed.values, out = a['--out'], sourceRoot = a['--source-root'];
  if (existsSync(out)) { console.log(JSON.stringify({ status: 'ERROR', nativeAuthorization: false, reason: 'public out must not exist' })); return 1; }
  mkdirSync(out);
  const evidence = new PublicEvidence(out), checks = {}, live = new Set(), diag = { steps: [] };
  const report = { status: 'ERROR', nativeAuthorization: false, classification: 'PUBLIC',
    scope: 'Disposable Windows: genuine Sable NSIS 2.2.2 -> 2.2.3 via startup preparation, synthetic loopback account; not production, not SSO/first-entry proof' };
  const temp = process.env.RUNNER_TEMP || tmpdir();
  const root = realpathSync.native(mkdtempSync(join(temp, 'se-')));
  const launchNonce = randomBytes(16).toString('hex');
  const P = name => join(root, name);
  for (const d of ['t', 't\\home', 't\\temp', 't\\local', 'p', 'p\\home', 'p\\roaming', 'p\\local', 'p\\temp', 'b', 'k', 'h', 'w']) mkdirSync(P(d));
  const installDir = P('i'), roaming = P('p\\roaming'), cacheRoot = P('p\\local');
  writeFileSync(join(roaming, MARKER), launchNonce, { flag: 'wx' });
  const toolEnv = allowlistEnv(process.env, { USERPROFILE: P('t\\home'), HOME: P('t\\home'), TEMP: P('t\\temp'), TMP: P('t\\temp'),
    LOCALAPPDATA: P('t\\local') }); // cache do electron-builder fica no LOCALAPPDATA privado das ferramentas.
  const nonce = randomBytes(8).toString('hex'), distro = `sable-ensaio-${nonce}`;
  let feed, synapse, watcher, hostsAdded = false, distroImported = false, secrets, caThumb, updatesJson;
  const step = name => diag.steps.push({ name, at: new Date().toISOString() });
  try {
    step('preflight');
    if ((await pwsh(PS.volume, { ...toolEnv, ENSAIO_PATH: root })) !== 'NTFS') throw new Error('private root is not NTFS');
    const foreign = await pwshJson(PS.foreignSable, toolEnv);
    if (foreign.processes.length || foreign.uninstall.length) throw new Error('foreign Sable process or installation present');

    step('inputs');
    const inputs = { electronZip: hashFile(a['--electron-zip']), rootfs: hashFile(a['--wsl-rootfs']), wheel: hashFile(a['--synapse-wheel']) };
    if (inputs.electronZip !== ELECTRON.archiveSha256) throw new Error('electron archive pin');
    if (inputs.rootfs !== WSL_ROOTFS.sha256) throw new Error('wsl rootfs pin');
    if (inputs.wheel !== SYNAPSE.wheelSha256 || win32.basename(a['--synapse-wheel']) !== SYNAPSE.wheel) throw new Error('synapse wheel pin');
    const source = await verifySource(sourceRoot);
    if (!source.ok) throw new Error(`source: ${source.problems.join('; ')}`);
    const recipe = verifyRecipe(a['--recipe-root'], sourceRoot);
    if (!recipe.ok) throw new Error(`recipe: ${recipe.problems.join('; ')}`);
    evidence.write('inputs.json', { ...inputs, recipeSha256: recipe.recipeSha256, patch: recipe.recipe.patch,
      sourceFiles: recipe.recipe.sourceFiles.length, frontendInputs: recipe.recipe.frontendInputs.length });
    checks.inputsVerified = true;

    step('tls+signing');
    const caKey = P('k\\ca.key'), ca = P('k\\ca.pem'), key = P('k\\tls.key'), csr = P('k\\tls.csr'), cert = P('k\\tls.pem'), ext = P('k\\san.ext');
    await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', `/CN=Sable ensaio CA ${nonce}`,
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', ca], { env: toolEnv });
    await run('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', key, '-out', csr], { env: toolEnv });
    writeFileSync(ext, 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n');
    await run('openssl', ['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-days', '1', '-extfile', ext, '-out', cert], { env: toolEnv });
    rmSync(caKey);
    caThumb = await pwsh(PS.caAdd, { ...toolEnv, ENSAIO_CA: ca });
    const signer = signingKey(), feedState = { manifest: null, installers: {}, tamper: false };
    feed = await startFeed({ keyFile: key, certFile: cert }, feedState);
    updatesJson = placeUpdatesResource(sourceRoot, updatesResource(feed.origin, signer.publicKey));

    step('build');
    const frontend = await buildFrontend(sourceRoot, toolEnv);
    const bundle = await buildElectronMain(sourceRoot, recipe.recipe);
    const pkgs = {};
    for (const version of [VERSIONS.seed, VERSIONS.target]) {
      pkgs[version] = await packageVersion(sourceRoot, { version, output: P(`b\\${version}`), updatesJson,
        electronZip: a['--electron-zip'], privateDir: P('b') }, toolEnv);
      if (!pkgs[version].ok) throw new Error(`package ${version}: ${pkgs[version].problems.join('; ')}`);
    }
    const seed = pkgs[VERSIONS.seed], target = pkgs[VERSIONS.target];
    if (seed.installerSha256 === target.installerSha256) throw new Error('installers not distinct');
    const pre = pathPreflight(root, installDir, target.items.map(i => i.path));
    if (!pre.ok) throw new Error(`path preflight: ${pre.problems.join('; ')}`);
    evidence.write('build.json', { identifier: IDENTIFIER, frontend, bundle, pathLongest: pre.longest,
      packages: Object.fromEntries(Object.values(pkgs).map(p => [p.version, { installerSha256: p.installerSha256, installerSize: p.installerSize,
        exeSha256: p.exeSha256, files: p.items.length }])) });
    feedState.installers = { [`sable-${VERSIONS.seed}-x64.exe`]: seed.installer, [`sable-${VERSIONS.target}-x64.exe`]: target.installer };
    feedState.manifest = envelope(signer.privateKey, { origin: feed.origin, version: VERSIONS.seed, seq: 1, sha512: seed.installerSha512, size: seed.installerSize });
    checks.packagesBuilt = true;

    step('synapse');
    secrets = generateSecrets();
    evidence.registerSecrets(secretValues(secrets));
    writeFileSync(P('k\\secrets.json'), JSON.stringify(secrets), { flag: 'wx', mode: 0o600 });
    await importDistro({ name: distro, installDir: P('w'), rootfs: a['--wsl-rootfs'] }, toolEnv); distroImported = true;
    const synapseInstall = await installSynapse(distro, a['--synapse-wheel'], toolEnv);
    await configureSynapse(distro, JSON.stringify(homeserverConfig(secrets, DATA)), toolEnv);
    await pwsh(PS.hostsAdd, { ...toolEnv, ENSAIO_NONCE: nonce }); hostsAdded = true;
    const resolved = await pwshJson(PS.resolve, toolEnv);
    if (!Array.isArray(resolved) || resolved.length !== 1 || resolved[0] !== '127.0.0.1') throw new Error('escritorio.localhost does not resolve only to loopback');
    const synapseChild = startSynapse(distro, toolEnv);
    synapse = { pid: synapseChild.pid, child: synapseChild };
    await until('synapse health', 180000, () => fetch(`${SYNAPSE.homeserver}/health`).then(r => r.ok, () => false));
    const federation = await fetch(`${SYNAPSE.homeserver}/_matrix/federation/v1/version`).then(r => r.status, () => 'unreachable');
    const keyServer = await fetch(`${SYNAPSE.homeserver}/_matrix/key/v2/server`).then(r => r.status, () => 'unreachable');
    if (federation !== 404 || keyServer !== 404) throw new Error('federation resources exposed');
    const account = await registerSyntheticAccount(SYNAPSE.homeserver, secrets);
    evidence.write('synapse.json', { version: synapseInstall.version, packages: synapseInstall.packages, wslVersion: 1,
      serverName: SYNAPSE.serverName, listener: '127.0.0.1:8008 http', federationStatus: federation, keyServerStatus: keyServer, userId: account.userId });
    checks.synapseLoopback = true;

    step('seed-install');
    const seedInstaller = own(seed.installer, ['/S', `/D=${installDir}`], toolEnv, live);
    await seedInstaller.done; live.delete(seedInstaller);
    if (seedInstaller.exitCode !== 0) throw new Error(`seed installer exit ${seedInstaller.exitCode}`);
    const seedInventory = compareInventory(seed.items, inventory(installDir), NSIS_EXTRAS);
    const seedEntry = await pwshJson(PS.uninstallEntry, toolEnv);
    if (!seedInventory.equal || [seedEntry].flat().length !== 1 || [seedEntry].flat()[0].displayVersion !== VERSIONS.seed) throw new Error('seed install inventory/registry');
    checks.seedInstalled = true;

    step('seed-launch');
    const watchLog = P('h\\watch.jsonl'), watchStop = P('h\\stop');
    watcher = startWatcher({ ...toolEnv, ENSAIO_LOG: watchLog, ENSAIO_STOP: watchStop, ENSAIO_ROOT: root + '\\', ENSAIO_CACHE: cacheRoot + '\\' });
    const portA = await freePort(), portC = await freePort(), exe = join(installDir, PRODUCT_EXE);
    if (portA === portC) throw new Error('CDP ports collide');
    // Lido pelo wrapper do pacote a partir de <root>\i\..; independe do ambiente herdado na reabertura NSIS.
    // Somente caminhos privados desta raiz e a CA PÚBLICA (sem chave); a chave da CA já foi apagada.
    writeFileSync(P(LAUNCH), JSON.stringify({ schema: 1, nonce: launchNonce, root, appData: roaming, localAppData: cacheRoot,
      home: P('p\\home'), temp: P('p\\temp'), caPem: ca, caSha256: hashFile(ca), cdpPort: portA, cdpPortUpdated: portC }), { flag: 'wx' });
    const witnessOf = pid => {
      const file = join(roaming, 'ensaio-witness', `${pid}.json`);
      return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
    };
    const witnessProblems = (w, pid, updated, port) => [
      !w && 'witness absent', w && w.pid !== pid && 'witness pid', w && w.nonce !== launchNonce && 'witness nonce',
      w && w.updated !== updated && 'witness --updated', w && w.cdpPort !== port && 'witness port',
      w && w.execPath?.toLowerCase() !== exe.toLowerCase() && 'witness image', w && w.caSha256 !== hashFile(ca) && 'witness ca',
      w && ['main.cjs', 'ensaio-entry.cjs', 'ensaio-launch.cjs'].some(n => w.code?.[n] !== bundle[n]) && 'witness code hash',
    ].filter(Boolean);
    const appProcessEnv = appEnv(process.env, { profile: P('p\\home'), appData: roaming, localAppData: cacheRoot, temp: P('p\\temp'), caFile: ca });
    const seedApp = own(exe, [], appProcessEnv, live);
    const endA = await waitEndpoint(portA, 120000, t => t.url.startsWith('sable-app://app'));
    if ((await browserPid(endA.browser)) !== seedApp.pid) throw new Error('CDP endpoint is not the seed process');
    const seedWitness = witnessProblems(witnessOf(seedApp.pid), seedApp.pid, false, portA);
    if (seedWitness.length) throw new Error(`seed bootstrap witness: ${seedWitness.join(', ')}`);
    const cdpA = await Cdp.open(endA.page), coreA = await CorePage.attach(cdpA);
    // auth.login (Core RPC) devolve o user_id Matrix; o account_id local só aparece em session.restore.
    const loggedInUser = await coreA.call('auth.login', { homeserver: SYNAPSE.homeserver, identifier: { kind: 'user', user: secrets.username },
      password: secrets.password, reauth_account_id: null });
    await coreA.reload();
    const before = await until('seed restore', 120000, () => coreA.call('session.restore', {}).catch(() => null));
    const accountId = before?.account_id;
    if (loggedInUser !== account.userId || typeof accountId !== 'string' || !accountId || before.user_id !== account.userId || before.needs_reauth !== false
      || typeof before.device_id !== 'string' || !before.device_id || before.homeserver.replace(/\/$/, '') !== SYNAPSE.homeserver)
      throw new Error(`seed restore after reload: ${JSON.stringify({ loginUserMatches: loggedInUser === account.userId, accountIdPresent: typeof accountId === 'string' && !!accountId, userMatches: before?.user_id === account.userId, needsReauth: before?.needs_reauth, deviceIdPresent: typeof before?.device_id === 'string' && !!before.device_id, homeserverMatches: String(before?.homeserver ?? '').replace(/\/$/, '') === SYNAPSE.homeserver })}`);
    await syncLive(coreA);
    checks.seedCoreLogin = true;

    step('encrypted-event');
    const canary = `ensaio-canary-${randomBytes(12).toString('hex')}`;
    const roomId = await coreA.call('rooms.create', { name: `ensaio-${nonce}`, topic: null, kind: 'text', public: false, encrypted: true,
      invite: [], parent_space: null, alias: null, room_version: null, join_rule: null, federate: false, predecessor: null });
    // O Core marca `encrypted` como null até carregar o estado; enviar antes disso produziria texto claro.
    await until('room encryption state', 60000, async () => (await coreA.call('rooms.list_item', { room_id: roomId }).catch(() => null))?.encrypted === true ? true : null);
    const sub = await coreA.call('timeline.subscribe', { room_id: roomId, focus: { kind: 'live' }, hidden_events: false });
    await coreA.call('messages.send', { room_id: roomId, body: canary });
    const confirmed = await waitTimeline(coreA, sub.subscription, sub.items, items => findConfirmed(items, canary), 'remote canary');
    const dbSeed = await querySqlite(distro, SQLITE_CHECK_PY, [roomId, confirmed.event_id, account.userId, canary], toolEnv);
    diag.databaseSeed = databaseDiagnostic(dbSeed, { userId: account.userId, deviceId: before.device_id });
    const dbSeedCheck = validateDatabaseEvidence(dbSeed, { userId: account.userId, deviceId: before.device_id });
    if (!dbSeedCheck.ok) throw new Error(`server database: ${dbSeedCheck.problems.join('; ')}`);
    evidence.write('seed.json', { pid: seedApp.pid, version: asarPackageVersion(join(installDir, 'resources/app.asar')).version,
      accountId, userId: before.user_id, deviceId: before.device_id, roomId, eventId: confirmed.event_id, database: dbSeed });
    checks.encryptedEventConfirmed = true;

    step('negative');
    feedState.manifest = envelope(signer.privateKey, { origin: feed.origin, version: VERSIONS.target, seq: 2, sha512: target.installerSha512, size: target.installerSize });
    feedState.tamper = true;
    const hint = join(roaming, `${IDENTIFIER}.electron`, 'mindtech-update-stable-pending.json');
    const rejected = await electronCall(coreA, 'checkForUpdate');
    const afterNegative = await coreA.call('session.restore', {});
    const negOk = 'err' in rejected && !existsSync(hint) && asarPackageVersion(join(installDir, 'resources/app.asar')).version === VERSIONS.seed
      && afterNegative?.account_id === accountId && afterNegative.device_id === before.device_id
      && feed.counts.length >= 1 && feed.counts.every(c => c.tampered);
    evidence.write('negative.json', { rejected: 'err' in rejected, hintAbsent: !existsSync(hint), counts: feed.counts.slice() });
    if (!negOk) throw new Error('tampered installer was not rejected cleanly');
    checks.negativeTamperRejected = true;

    step('download');
    feedState.tamper = false;
    const negativeDownloads = feed.counts.length;
    const ready = await electronCall(coreA, 'checkForUpdate');
    const clean = feed.counts.slice(negativeDownloads);
    const hintValue = existsSync(hint) ? JSON.parse(readFileSync(hint, 'utf8')) : null;
    if (ready.ok?.version !== VERSIONS.target || JSON.stringify(hintValue) !== JSON.stringify({ schema: 1, pendingVersion: VERSIONS.target, attemptedAtStartup: false })
      || clean.length < 1 || clean.some(c => c.tampered) || clean.at(-1).bytes !== target.installerSize) throw new Error('authenticated download/hint');
    checks.updateDownloadedHint = true;

    step('close-to-tray');
    // Keep the genuine Windows default (custom title bar): omitting it makes the app recreate its window and drop the CDP page.
    const tray = await electronCall(coreA, 'applyWindowSettings', [{ closeToTray: true, minimizeToTray: false, showSystemTrayIcon: true, useCustomTitleBar: true }]);
    if (tray.ok?.trayAvailable !== true) throw new Error('tray unavailable');
    // Bounded, non-authorizing observation of the failing hide step: no URLs with paths, ids, messages or logs.
    const observeClose = async (error) => {
      const seen = { appExited: seedApp.exitCode !== undefined, error: String(error?.message ?? error).slice(0, 96) };
      try {
        const cdp = await Cdp.open(endA.browser);
        try { seen.targets = (await cdp.send('Target.getTargets', {}, 5000)).targetInfos.map(t => ({ type: t.type, attached: t.attached, app: t.url.startsWith('sable-app://app') })); }
        finally { cdp.close(); }
      } catch (e) { seen.browserEndpoint = String(e?.message ?? e).slice(0, 64); }
      try { seen.ownedProcessCount = [await pwshJson(PS.ownedProcesses, { ...toolEnv, ENSAIO_ROOT: installDir + '\\' }) ?? []].flat().length; } catch { seen.ownedProcessCount = null; }
      diag.closeToTray = seen;
    };
    let visibility;
    try {
      await electronCall(coreA, 'closeWindow');
      await sleep(3000);
      visibility = await coreA.fn('function () { return document.visibilityState; }', []);
    } catch (error) { await observeClose(error); throw error; }
    const runningAfterX = parseWatcherLog(readFileSync(watchLog, 'utf8')).rows.filter(r => r.executable.toLowerCase().startsWith(cacheRoot.toLowerCase() + '\\'));
    if (seedApp.exitCode !== undefined || visibility !== 'hidden' || runningAfterX.length
      || asarPackageVersion(join(installDir, 'resources/app.asar')).version !== VERSIONS.seed) throw new Error('X did not hide without installing');
    cdpA.close();
    checks.closedToTrayNoInstall = true;

    step('abrupt-stop');
    const ownedRows = await pwshJson(PS.ownedProcesses, { ...toolEnv, ENSAIO_ROOT: installDir + '\\' });
    const owned = [ownedRows ?? []].flat();
    if (!owned.some(r => r.pid === seedApp.pid)) throw new Error('seed main not among observed own processes');
    await pwshJson(PS.stopOwned, { ...toolEnv, ENSAIO_PIDS: owned.map(r => r.pid).join(','), ENSAIO_ROOT: installDir + '\\' });
    await seedApp.done; live.delete(seedApp);
    await until('own processes gone', 60000, async () => [await pwshJson(PS.ownedProcesses, { ...toolEnv, ENSAIO_ROOT: installDir + '\\' }) ?? []].flat().length === 0);
    checks.abruptStopOwnPids = true;

    step('relaunch-seed');
    const relaunch = own(exe, [], appProcessEnv, live);
    const chainOptions = { seedPid: relaunch.pid, cacheRoot, installDir, driverSpawns: spawned, expectedExeSha256: target.exeSha256,
      expectedInstallerSha512: target.installerSha512, explorerPath: win32.join(process.env.SystemRoot || 'C:\\Windows', 'explorer.exe') };
    const chainNow = () => { const { rows, exits } = parseWatcherLog(readFileSync(watchLog, 'utf8')); return { exits, result: validateProcessChain(rows, exits, chainOptions) }; };
    const { result: chain, exits: chainExits } = await until('installer chain', 300000, async () => {
      const now = chainNow(); return now.result.ok ? now : null;
    }).catch(error => { diag.chain = chainNow().result; throw error; });
    await relaunch.done; live.delete(relaunch);
    const installerExit = chainExits.get(chain.installer.pid);
    evidence.write('chain.json', { launchMode: chain.launchMode, seedPid: relaunch.pid, seedExit: relaunch.exitCode,
      installer: { pid: chain.installer.pid, parent: chain.installer.parent, created: chain.installer.created, commandLine: chain.installer.commandLine,
        sha512: chain.installer.sha512, sid: chain.installer.sid, sessionId: chain.installer.sessionId }, installerExit,
      reopened: { pid: chain.reopened.pid, parent: chain.reopened.parent, created: chain.reopened.created, commandLine: chain.reopened.commandLine,
        sha256: chain.reopened.sha256, sid: chain.reopened.sid, sessionId: chain.reopened.sessionId },
      parentFacts: chain.launchMode === 'nsis-shell-broker' ? chain.reopened.parentFacts : null,
      driverSpawns: spawned.map(s => ({ pid: s.pid, image: win32.basename(s.image), at: s.at })) });
    report.launchMode = chain.launchMode; // 'direct' ou 'nsis-shell-broker'; broker é correlação via shell, não pai direto.
    checks.installerChain = true;
    if (installerExit?.exitCode !== 0) throw new Error(`installer exit ${installerExit?.exitCode}`);
    checks.installerExitZero = true;

    step('installed');
    const installedInventory = compareInventory(target.items, inventory(installDir), NSIS_EXTRAS);
    const pe = await pwshJson(PS.peVersion, { ...toolEnv, ENSAIO_PATH: exe });
    const entry = [await pwshJson(PS.uninstallEntry, toolEnv)].flat();
    const asarVersion = asarPackageVersion(join(installDir, 'resources/app.asar')).version;
    evidence.write('installed.json', { inventory: installedInventory, pe, registry: entry, asarVersion });
    if (!installedInventory.equal || asarVersion !== VERSIONS.target || !String(pe.product).startsWith(VERSIONS.target)
      || !String(pe.file).startsWith(VERSIONS.target) || entry.length !== 1 || entry[0].displayVersion !== VERSIONS.target) throw new Error('installed 2.2.3 identity');
    checks.installedInventory = true;

    step('reopened-cdp');
    const endB = await waitEndpoint(portC, 120000, t => t.url.startsWith('sable-app://app'));
    if ((await browserPid(endB.browser)) !== chain.reopened.pid) throw new Error('CDP endpoint is not the installer-launched process');
    const reopenedWitness = witnessProblems(witnessOf(chain.reopened.pid), chain.reopened.pid, true, portC);
    if (reopenedWitness.length) throw new Error(`reopened bootstrap witness: ${reopenedWitness.join(', ')}`);
    checks.cdpBoundToReopened = true;
    const downloadsBeforeSelf = feed.counts.length;
    const cdpB = await Cdp.open(endB.page), coreB = await CorePage.attach(cdpB);

    step('restore');
    const after = await until('restore', 120000, () => coreB.call('session.restore', {}).catch(() => null));
    await syncLive(coreB);
    const dbAfter = await querySqlite(distro, SQLITE_CHECK_PY, [roomId, confirmed.event_id, account.userId, canary], toolEnv);
    diag.databaseAfter = databaseDiagnostic(dbAfter, { userId: account.userId, deviceId: before.device_id });
    const dbAfterCheck = validateDatabaseEvidence(dbAfter, { userId: account.userId, deviceId: before.device_id });
    const sameAccount = after.account_id === accountId && after.user_id === before.user_id && after.device_id === before.device_id
      && after.needs_reauth === false && dbAfterCheck.ok;
    const subB = await coreB.call('timeline.subscribe', { room_id: roomId, focus: { kind: 'event', event_id: confirmed.event_id }, hidden_events: false });
    const decrypted = await waitTimeline(coreB, subB.subscription, subB.items, items => {
      const r = findDecrypted(items, confirmed.event_id, canary); return r.ok ? r : null;
    }, 'decrypted canary').catch(e => ({ ok: false, reason: short(e) }));
    const noUpdate = await electronCall(coreB, 'checkForUpdate');
    const png = await coreB.screenshot();
    evidence.write('account.png', png);
    evidence.write('restore.json', { accountId: after.account_id, userId: after.user_id, deviceId: after.device_id, needsReauth: after.needs_reauth,
      database: dbAfter, decrypted: decrypted.ok === true, eventId: confirmed.event_id, selfCheck: noUpdate, downloads: feed.counts.length });
    if (!sameAccount) throw new Error(`account/device not preserved: ${dbAfterCheck.problems.join('; ')}`);
    checks.sameAccountDevice = true;
    if (decrypted.ok !== true) throw new Error(`same event not decrypted: ${decrypted.reason}`);
    checks.decryptedSameEvent = true;
    if (!('ok' in noUpdate) || noUpdate.ok !== null || feed.counts.length !== downloadsBeforeSelf) throw new Error('self no-update');
    checks.selfNoUpdate = true;
    cdpB.close();
  } catch (error) {
    report.reason = short(error);
  } finally {
    const cleanup = [];
    const attempt = async (label, fn) => { try { await fn(); } catch (e) { cleanup.push(`${label}: ${short(e)}`); } };
    await attempt('own-app-processes', async () => {
      const rows = [await pwshJson(PS.ownedProcesses, { ...toolEnv, ENSAIO_ROOT: root + '\\' }) ?? []].flat();
      if (rows.length) await pwshJson(PS.stopOwned, { ...toolEnv, ENSAIO_PIDS: rows.map(r => r.pid).join(','), ENSAIO_ROOT: root + '\\' });
    });
    await attempt('watcher', async () => { if (watcher) { writeFileSync(P('h\\stop'), ''); await new Promise(r => watcher.exitCode !== null ? r() : watcher.once('close', r)); } });
    await attempt('synapse', async () => { if (synapse?.child) { synapse.child.kill(); } });
    await attempt('distro', async () => { if (distroImported) await removeDistro(distro, toolEnv); });
    await attempt('updates-resource', async () => { if (updatesJson) rmSync(updatesJson); });
    await attempt('ca', async () => { if (caThumb) await pwsh(PS.caRemove, { ...toolEnv, ENSAIO_THUMB: caThumb }); });
    await attempt('hosts', async () => { if (hostsAdded) await pwsh(PS.hostsRemove, { ...toolEnv, ENSAIO_NONCE: nonce }); });
    await attempt('feed', async () => { if (feed) { feed.server.closeAllConnections(); await new Promise(r => feed.server.close(r)); } });
    await attempt('own-children', async () => { for (const r of live) if (r.exitCode === undefined && r.pid) process.kill(r.pid); });
    await attempt('diagnostics', async () => evidence.write('diagnostics.json', { classification: 'PUBLIC_NON_AUTHORIZING_DIAGNOSTIC',
      nativeAuthorization: false, reason: report.reason ?? null, steps: diag.steps, chain: diag.chain ?? null,
      databaseSeed: diag.databaseSeed ?? null, databaseAfter: diag.databaseAfter ?? null, closeToTray: diag.closeToTray ?? null,
      children: [...live].map(r => ({ pid: r.pid, exitCode: r.exitCode ?? null })) }));
    await attempt('private-root', async () => rmSync(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 200 }));
    if (cleanup.length) report.cleanupErrors = cleanup;
    const refused = evidence.audit();
    checks.evidenceAudited = refused.length === 0 && cleanup.length === 0;
    if (refused.length) report.refusedArtifacts = refused;
  }
  const verdict = decide(platform, checks);
  Object.assign(report, { status: verdict.status, nativeAuthorization: verdict.nativeAuthorization, checks, missing: verdict.missing });
  try { evidence.write('result.json', report); } catch (e) { console.error(short(e)); return 1; }
  console.log(JSON.stringify({ status: report.status, nativeAuthorization: report.nativeAuthorization, evidence: join(out, 'result.json') }));
  return verdict.exitCode;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().then(code => { process.exitCode = code; }, error => {
    console.error(JSON.stringify({ status: 'ERROR', nativeAuthorization: false, reason: short(error) })); process.exitCode = 1;
  });
}
