#!/usr/bin/env node
// Stage-one diagnostic only: real Synapse + libolm on the existing disposable WSL1.
// No Sable source, build, install or updater authorization. No private output uploaded.
// Failures carry a fixed code only: values compared here may be identifiers or the private canary.
export class QueryFailure extends Error { constructor(code) { super(code); this.code = code; } }
const must = (ok, code) => { if (!ok) throw new QueryFailure(code); };
export const publicReason = error => error instanceof QueryFailure ? error.code : `unexpected:${String(error?.code ?? error?.name ?? 'error').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 48)}`;
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { PINNED, PYPI_JSON, fetchPublic, saveVerified, selectWheel } from './fetch-inputs.mjs';
import { SYNAPSE } from '../lib/pins.mjs';
import { SQLITE_CHECK_PY, databaseDiagnostic, generateSecrets, homeserverConfig, registerSyntheticAccount, validateDatabaseEvidence } from '../lib/synapse.mjs';
import { DATA, configureSynapse, importDistro, installSynapse, makeInconsistentCopy, querySqlite, removeDistro, startSynapse, transportProbe } from '../lib/wsl.mjs';
import { PS, pwsh, pwshJson } from '../lib/windows.mjs';

const run = promisify(execFile);
const require = createRequire(import.meta.url);
async function download(item, root) {
  const response = await fetchPublic(item.url, item.hosts);
  const file = join(root, item.file);
  await saveVerified(Readable.fromWeb(response.body), file, item);
  return file;
}
const pause = ms => new Promise(r => setTimeout(r, ms));
async function ready(child) {
  const end = Date.now() + 60000;
  while (Date.now() < end) {
    if (child.exitCode !== null) throw new Error('Synapse exited before readiness');
    try { if ((await fetch(`${SYNAPSE.homeserver}/_matrix/client/versions`, { signal: AbortSignal.timeout(2000) })).ok) return; } catch {}
    await pause(250);
  }
  throw new Error('Synapse readiness timeout');
}

async function cleanupTests(root) {
  // The real process-disappeared case, including the race between CIM and Stop-Process.
  const env = { ...process.env, ENSAIO_ROOT: root + '\\', ENSAIO_PIDS: '2147483646' };
  must(JSON.stringify(await pwshJson(PS.stopOwned, env)) === '[]', 'cleanup-absent-pid');
  const tests = [
    { name: 'already-exited-race', stop: "$PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('gone'),'gone',[Management.Automation.ErrorCategory]::ObjectNotFound,$null))", remaining: '$null', fails: false },
    { name: 'access-denied', stop: "$PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('denied'),'denied',[Management.Automation.ErrorCategory]::PermissionDenied,$null))", remaining: '$null', fails: true },
    { name: 'still-alive', stop: '$null', remaining: "[pscustomobject]@{ExecutablePath=$env:ENSAIO_ROOT+'owned.exe'}", fails: true },
  ];
  for (const t of tests) {
    const prefix = `function Get-CimInstance { param($ClassName,$Filter) $script:queries++; if($script:queries -eq 1){ [pscustomobject]@{ExecutablePath=$env:ENSAIO_ROOT+'owned.exe'} } else { ${t.remaining} } }\nfunction Stop-Process { [CmdletBinding()]param($Id,[switch]$Force) ${t.stop} }\n$script:queries=0;\n`;
    let failed = false;
    try { await pwsh(prefix + PS.stopOwned, env, 20000); } catch { failed = true; }
    must(failed === t.fails, `cleanup-${t.name}`);
  }
  return { absentPid: true, exitedRace: true, accessDeniedRejected: true, stillAliveRejected: true };
}

export async function queryOnly() {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('query-only requires disposable Windows x64');
  const root = mkdtempSync(join(tmpdir(), 'sq-'));
  const distro = `sable-query-${randomBytes(6).toString('hex')}`;
  const env = { ...process.env };
  let imported = false, hosts = false, server;
  const cleanupErrors = [];
  const report = { scope: 'QUERY_ONLY', nativeAuthorization: false, checks: {}, timings: {} };
  const nonce = randomBytes(8).toString('hex');
  let started = Date.now();
  try {
    const rootfs = await download(PINNED.find(p => p.name === 'wslRootfs'), root);
    const metadata = await (await fetchPublic(PYPI_JSON, ['pypi.org'])).json();
    const wheel = await download(selectWheel(metadata), root);
    // Official libolm 3.2.15, npm integrity checked independently before pinning this digest.
    const olmArchive = await download({ file: 'olm.tgz', url: 'https://registry.npmjs.org/@matrix-org/olm/-/olm-3.2.15.tgz', hosts: ['registry.npmjs.org'], maxBytes: 2 << 20,
      sha256: '5d506e5fb7f54aa27312e4abdd9f131fe4f5c55bb0a4b960d6ec1e8eed42a056' }, root);
    const olmDir = join(root, 'olm'); mkdirSync(olmDir);
    await run('tar.exe', ['-xzf', olmArchive, '-C', olmDir]);
    const Olm = require(join(olmDir, 'package', 'olm.js')); await Olm.init();
    report.timings.downloadMs = Date.now() - started; started = Date.now();
    await importDistro({ name: distro, installDir: join(root, 'wsl'), rootfs }, env); imported = true;
    await installSynapse(distro, wheel, env);
    const secrets = generateSecrets();
    await configureSynapse(distro, JSON.stringify(homeserverConfig(secrets, DATA)), env);
    await pwsh(PS.hostsAdd, { ...env, ENSAIO_NONCE: nonce }); hosts = true;
    server = startSynapse(distro, env);
    server.stderr.on('data', () => {}); // private server logs never enter the public report
    await ready(server);
    report.timings.serverMs = Date.now() - started; started = Date.now();
    const account = await registerSyntheticAccount(SYNAPSE.homeserver, secrets);
    let token;
    async function api(path, body, method = 'POST') {
      const response = await fetch(`${SYNAPSE.homeserver}/_matrix/client/v3/${path}`, { method,
        headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
      if (!response.ok) throw new Error(`synthetic Matrix request HTTP ${response.status}`);
      return response.json();
    }
    const login = await api('login', { type: 'm.login.password', identifier: { type: 'm.id.user', user: account.userId }, password: secrets.password, device_id: 'QUERY_DEVICE' });
    token = login.access_token;
    const { room_id: roomId } = await api('createRoom', { preset: 'private_chat', creation_content: { 'm.federate': false }, initial_state: [{ type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } }] });
    const canary = `private-query-canary-${randomBytes(16).toString('hex')}`;
    const outbound = new Olm.OutboundGroupSession(), inbound = new Olm.InboundGroupSession(), identity = new Olm.Account();
    let ciphertext, sessionId, senderKey;
    try {
      outbound.create(); identity.create(); inbound.create(outbound.session_key());
      ciphertext = outbound.encrypt(JSON.stringify({ room_id: roomId, type: 'm.room.message', content: { msgtype: 'm.text', body: canary } }));
      must(JSON.parse(inbound.decrypt(ciphertext).plaintext).content.body === canary, 'olm-roundtrip');
      sessionId = outbound.session_id(); senderKey = JSON.parse(identity.identity_keys()).curve25519;
    } finally { outbound.free(); inbound.free(); identity.free(); }
    const send = (type, content) => api(`rooms/${encodeURIComponent(roomId)}/send/${type}/${randomBytes(6).toString('hex')}`, content, 'PUT');
    const { event_id: eventId } = await send('m.room.encrypted', { algorithm: 'm.megolm.v1.aes-sha2', ciphertext, session_id: sessionId, sender_key: senderKey, device_id: 'QUERY_DEVICE' });
    must(eventId.startsWith('$'), 'event-id-shape');
    const expected = { userId: account.userId, deviceId: 'QUERY_DEVICE' };
    const values = [roomId, eventId, account.userId, "space quote ' dollar $ backslash \\ Unicode ç"];
    const oldReceived = await transportProbe(distro, values.slice(0, 3), env, true);
    must(JSON.stringify(oldReceived) !== JSON.stringify(values.slice(0, 3)), 'legacy-transport-not-reproduced');
    must(JSON.stringify(await transportProbe(distro, values, env)) === JSON.stringify(values), 'json-transport-changed-values');
    report.checks.transportLegacyReproduced = true; report.checks.transportJsonPreserved = true;
    const query = (id = eventId, options) => querySqlite(distro, SQLITE_CHECK_PY, [roomId, id, account.userId, canary], env, options);
    const present = await query();
    report.present = databaseDiagnostic(present, expected); // record before validating
    must(validateDatabaseEvidence(present, expected).ok === true, 'present-event-rejected');
    report.checks.encryptedEventPresent = true;
    for (const [label, id] of [['absent', '$absent-query-event'], ['changed', eventId.slice(1)]]) {
      const result = await query(id);
      report[label] = databaseDiagnostic(result, expected);
      must(result.eventFound === false, `${label}-event-found`);
      must(validateDatabaseEvidence(result, expected).ok === false, `${label}-accepted`);
      report.checks[label + 'Rejected'] = true;
    }
    const { event_id: plainId } = await send('m.room.message', { msgtype: 'm.text', body: 'negative plaintext, not the private canary' });
    const plain = await query(plainId); report.plain = databaseDiagnostic(plain, expected);
    must(plain.eventFound === true && plain.hasBody === true, 'plaintext-control-missing');
    must(validateDatabaseEvidence(plain, expected).ok === false, 'plaintext-accepted'); report.checks.plaintextRejected = true;
    // Damage only a separate private snapshot, never the live server database.
    await makeInconsistentCopy(distro, eventId, env);
    let inconsistentRejected = false;
    try { await query(eventId, { database: `${DATA}/negative.db` }); } catch { inconsistentRejected = true; }
    must(inconsistentRejected === true, 'inconsistent-copy-accepted');
    report.checks.inconsistentRejected = true;
    report.checks.cleanup = await cleanupTests(root);
    report.timings.queryMs = Date.now() - started;
  } catch (error) {
    report.status = 'ERROR';
    // The public reason is a fixed code. Never attach compared values, raw commands or server logs.
    report.reason = publicReason(error);
    throw Object.assign(new Error('query-only diagnostic failed'), { report });
  } finally {
    if (hosts) try { await pwsh(PS.hostsRemove, { ...env, ENSAIO_NONCE: nonce }); } catch { cleanupErrors.push('hosts'); }
    if (imported) try { await removeDistro(distro, env); } catch { cleanupErrors.push('distro'); }
    try { rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); } catch { cleanupErrors.push('private-root'); }
    report.cleanupErrors = cleanupErrors;
    if (cleanupErrors.length) report.status = 'ERROR';
  }
  if (report.cleanupErrors.length) throw Object.assign(new Error('query-only cleanup failed'), { report });
  report.status = 'QUERY_CHECKED';
  return report;
}

if (import.meta.url === new URL(process.argv[1], 'file:').href || process.argv[1]?.endsWith('query-only.mjs')) {
  queryOnly().then(report => console.log(JSON.stringify(report)), error => { console.log(JSON.stringify(error.report ?? { status: 'ERROR', nativeAuthorization: false, scope: 'QUERY_ONLY' })); process.exitCode = 1; });
}
