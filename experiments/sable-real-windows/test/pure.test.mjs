import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { decide, REQUIRED } from '../lib/verdict.mjs';
import { allowlistEnv, appEnv, parseArgs, pathPreflight } from '../lib/guards.mjs';
import { splitWindowsCommandLine, validateInstallerCommand, validateProcessChain } from '../lib/nsis.mjs';
import { applyDiffs, findConfirmed, findDecrypted } from '../lib/timeline.mjs';
import { mntPath } from '../lib/wsl.mjs';
import { parseWatcherLog } from '../lib/windows.mjs';

test('verdict: non-Windows is BLOCKED 78 and never authorizes', () => {
  const all = Object.fromEntries(REQUIRED.map(k => [k, true]));
  assert.deepEqual(decide('linux', all).exitCode, 78);
  assert.equal(decide('linux', all).nativeAuthorization, false);
});
test('verdict: any missing or unknown check is ERROR; only all-true is PASS', () => {
  const all = Object.fromEntries(REQUIRED.map(k => [k, true]));
  assert.equal(decide('win32', all).status, 'PASS');
  for (const k of REQUIRED) assert.equal(decide('win32', { ...all, [k]: undefined }).status, 'ERROR');
  assert.equal(decide('win32', { ...all, installerChain: 'yes' }).status, 'ERROR');
  assert.equal(decide('win32', { ...all, extra: true }).status, 'ERROR');
});

test('args: every input is required and absolute', () => {
  const ok = parseArgs(['--source-root', 'C:\\s', '--recipe-root', 'C:\\r', '--electron-zip', 'C:\\e.zip', '--wsl-rootfs', 'C:\\w.tgz',
    '--synapse-wheel', 'C:\\x.whl', '--out', 'C:\\o']);
  assert.equal(ok.ok, true);
  const bad = parseArgs(['--source-root', 'rel', '--out']);
  assert.equal(bad.ok, false);
  assert.ok(bad.problems.includes('--source-root must be absolute'));
  assert.ok(bad.problems.includes('missing value for --out'));
  assert.ok(bad.problems.includes('missing --recipe-root'));
});

test('env: allowlist drops CI tokens, NODE_OPTIONS, ELECTRON_* and identity overrides', () => {
  const env = appEnv({ PATH: 'C:\\w', SystemRoot: 'C:\\Windows', GITHUB_TOKEN: 'x', NODE_OPTIONS: '--inspect', ELECTRON_RUN_AS_NODE: '1',
    ELECTRON_FORCE_IS_PACKAGED: '1', SABLE_IDENTIFIER: 'moe.sable.next', ACTIONS_RUNTIME_TOKEN: 'y' },
  { profile: 'C:\\p', appData: 'C:\\p\\r', localAppData: 'C:\\p\\l', temp: 'C:\\p\\t', caFile: 'C:\\k\\ca.pem' });
  assert.deepEqual(Object.keys(env).sort(), ['APPDATA', 'HOME', 'LOCALAPPDATA', 'NODE_EXTRA_CA_CERTS', 'PATH',
    'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE'].sort());
  assert.throws(() => allowlistEnv({}, { NODE_OPTIONS: '--x' }), /forbidden/);
  assert.throws(() => allowlistEnv({}, { ELECTRON_RUN_AS_NODE: '1' }), /forbidden/);
});

test('path preflight: short root, no whitespace, installed paths < 260', () => {
  assert.equal(pathPreflight('D:\\a\\_temp\\se-AbC123', 'D:\\a\\_temp\\se-AbC123\\i', ['resources\\app.asar']).ok, true);
  assert.equal(pathPreflight('D:\\a\\_temp\\se-AbC123', 'D:\\a b\\i', []).ok, false);
  assert.equal(pathPreflight('D:\\a', 'D:\\a\\i', ['x'.repeat(260)]).ok, false);
});

test('CommandLineToArgvW rules (Microsoft documented table)', () => {
  assert.deepEqual(splitWindowsCommandLine('"abc" d e'), ['abc', 'd', 'e']);
  assert.deepEqual(splitWindowsCommandLine('a\\\\b d"e f"g h'), ['a\\\\b', 'de fg', 'h']);
  assert.deepEqual(splitWindowsCommandLine('a\\\\\\"b c d'), ['a\\"b', 'c', 'd']);
  assert.deepEqual(splitWindowsCommandLine('a\\\\\\\\"b c" d e'), ['a\\\\b c', 'd', 'e']);
  assert.deepEqual(splitWindowsCommandLine('a"b"" c d'), ['ab" c d']);
});

const inst = 'D:\\a\\_temp\\se-x\\p\\local\\sable-updater\\pending\\sable-2.2.3-x64.exe', dir = 'D:\\a\\_temp\\se-x\\i';
test('installer command: /S --updated --force-run and unquoted /D last', () => {
  assert.equal(validateInstallerCommand(`"${inst}" /S --updated --force-run /D=${dir}`, inst, dir).ok, true);
  assert.equal(validateInstallerCommand(`${inst} /S --updated --force-run /D=${dir}`, inst, dir).ok, true);
  assert.equal(validateInstallerCommand(`"${inst}" /S --updated --force-run "/D=${dir}"`, inst, dir).ok, false);
  assert.equal(validateInstallerCommand(`"${inst}" --updated /S --force-run /D=${dir}`, inst, dir).ok, false);
  assert.equal(validateInstallerCommand(`"${inst}" /S --updated /D=${dir}`, inst, dir).ok, false);
  assert.equal(validateInstallerCommand(`"${inst}" /S --updated --force-run /D=${dir} --x`, inst, dir).ok, false);
});

// Metadados UNIT da cadeia (não Native). SID/sessão/hashes sintéticos; caminhos no formato do runner.
const app = `${dir}\\Sable.exe`, cacheRoot = 'D:\\a\\_temp\\se-x\\p\\local', explorer = 'C:\\Windows\\explorer.exe';
const SID = 'S-1-5-21-1-2-3-1001', EXE = 'e'.repeat(64), PAYLOAD = 'p'.repeat(86) + '==';
const at = s => `2026-11-05T10:00:${String(s).padStart(2, '0')}.000Z`;
const who = { sid: SID, sessionId: 1 };
const seedRow = { pid: 100, parent: 1, executable: app, commandLine: `"${app}"`, created: at(10), ...who };
const installerRow = { pid: 200, parent: 100, executable: inst, commandLine: `"${inst}" /S --updated --force-run /D=${dir}`,
  created: at(12), sha512: PAYLOAD, ...who };
const reopenedRow = { pid: 300, parent: 200, executable: app, commandLine: `"${app}" --updated`, created: at(20), sha256: EXE, ...who };
const broker = { pid: 4000, executable: explorer, created: '2026-11-05T09:00:00.000Z', signatureStatus: 'Valid',
  signer: 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US', ...who };
const exitsOk = () => new Map([[200, { exitCode: 0, exitedAt: at(21) }]]);
const options = (extra = {}) => ({ seedPid: 100, cacheRoot, installDir: dir, expectedExeSha256: EXE, expectedInstallerSha512: PAYLOAD,
  explorerPath: explorer, driverSpawns: [{ pid: 90, image: app, at: at(1) }, { pid: 100, image: app, at: at(9) }], ...extra });
const firstSeed = { pid: 90, parent: 1, executable: app, commandLine: `"${app}"`, created: at(1), ...who };
const chain = (rows, exits = exitsOk(), extra) => validateProcessChain(rows, exits, options(extra));
const brokerRows = (facts = {}, row = {}) => [firstSeed, seedRow, installerRow,
  { ...reopenedRow, parent: 4000, parentFacts: { ...broker, ...facts }, ...row }];

test('process chain direct: installer is the real parent; renderer children ignored', () => {
  const r = chain([firstSeed, seedRow, installerRow, reopenedRow,
    { pid: 301, parent: 300, executable: app, commandLine: `"${app}" --type=renderer --x`, created: at(21), ...who }]);
  assert.deepEqual(r.problems, []);
  assert.equal(r.launchMode, 'direct'); assert.equal(r.reopened.pid, 300);
});

test('process chain broker: canonical Microsoft-signed explorer, same SID/session (metadata UNIT only)', () => {
  const r = chain(brokerRows());
  assert.deepEqual(r.problems, []);
  assert.equal(r.launchMode, 'nsis-shell-broker');
});

test('process chain rejects wrong parent, signer, SID, session, args, timing, driver PIDs and scope', () => {
  const bad = (rows, re, exits, extra) => { const r = chain(rows, exits, extra); assert.equal(r.ok, false); assert.equal(r.launchMode, null); assert.match(r.problems.join('|'), re); };
  bad(brokerRows({ executable: 'C:\\Users\\x\\explorer.exe' }), /canonical explorer/);
  bad(brokerRows({ executable: 'C:\\Windows\\System32\\cmd.exe' }), /canonical explorer/);
  bad(brokerRows({ signatureStatus: 'NotSigned' }), /signature/);
  bad(brokerRows({ signer: 'CN=Microsoft Windows Fake, O=Evil' }), /signature/);
  bad(brokerRows({ sid: 'S-1-5-18' }), /parent SID\/session/);
  bad(brokerRows({ sessionId: 0 }), /parent SID\/session/);
  bad(brokerRows({ created: at(30) }), /parent not created before/);
  bad(brokerRows({ pid: 999 }), /parent facts not observed/);
  bad(brokerRows({ pid: 4000 }, { parent: 4000, parentFacts: undefined }), /parent facts not observed/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, sid: 'S-1-5-21-9-9-9-500' }], /user SID differs/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, sessionId: 2 }], /session differs/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, commandLine: `"${app}" --updated --remote-debugging-port=1` }], /StartApp/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, commandLine: `"${app}" --updatedX` }], /exactly one app main with --updated/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, created: at(11) }], /outside installer lifetime/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, created: '2026-11-05T10:00:32.000Z' }], /outside installer lifetime/);
  bad([firstSeed, seedRow, installerRow, reopenedRow], /installer exit not observed/, new Map());
  bad([firstSeed, seedRow, installerRow, reopenedRow], /installer exit 2/, new Map([[200, { exitCode: 2, exitedAt: at(21) }]]));
  bad([firstSeed, seedRow, installerRow, reopenedRow], /reopened pid not new/, undefined,
    { driverSpawns: [...options().driverSpawns, { pid: 300, image: 'C:\\other.exe', at: at(5) }] });
  bad([firstSeed, seedRow, installerRow, reopenedRow], /driver launched the app after the installer/, undefined,
    { driverSpawns: [...options().driverSpawns, { pid: 555, image: app, at: at(15) }] });
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, sha256: 'f'.repeat(64) }], /not the 2\.2\.3 executable/);
  bad([firstSeed, seedRow, { ...installerRow, sha512: 'x' }, reopenedRow], /authenticated payload/);
  bad([firstSeed, seedRow, installerRow, { ...reopenedRow, executable: 'D:\\a\\_temp\\se-x\\copy\\Sable.exe' }], /exactly one app main/);
  bad([firstSeed, seedRow, { ...installerRow, executable: 'C:\\Users\\x\\AppData\\Local\\i.exe' }, reopenedRow], /installer child of seed/);
  bad([firstSeed, seedRow, installerRow, reopenedRow, { pid: 400, parent: 1, executable: app, commandLine: `"${app}"`, created: at(22), ...who }], /outside chain/);
  bad([firstSeed, { ...seedRow, commandLine: `"${app}" --updated` }, installerRow, reopenedRow], /seed not observed with genuine/);
});

test('watcher log: partial last line ignored, exits mapped with OS exit time', () => {
  const { rows, exits } = parseWatcherLog('{"kind":"process","pid":1}\r\n{"kind":"exit","pid":1,"exitCode":0,"exitedAt":"x"}\n{"kind":"proc');
  assert.equal(rows.length, 1); assert.deepEqual(exits.get(1), { exitCode: 0, exitedAt: 'x' });
});

test('timeline: VectorDiff application and remote-confirmed canary (local echo rejected)', () => {
  const echo = { id: 'a', event_id: null, transaction_id: 't', send_state: { status: 'sending', progress: null }, is_own: true, content: { kind: 'message', body: 'c' } };
  const remote = { ...echo, event_id: '$e', transaction_id: null, send_state: null };
  let items = applyDiffs([], [{ op: 'append', values: [{ id: 'x' }] }, { op: 'push_back', value: echo }]);
  assert.equal(findConfirmed(items, 'c'), null);
  items = applyDiffs(items, [{ op: 'set', index: 1, value: remote }]);
  assert.equal(findConfirmed(items, 'c').event_id, '$e');
  assert.deepEqual(applyDiffs([1, 2, 3], [{ op: 'remove', index: 0 }, { op: 'insert', index: 2, value: 9 }, { op: 'truncate', length: 2 }]), [2, 3]);
  assert.throws(() => applyDiffs([], [{ op: 'set', index: 0, value: 1 }]), /out of range/);
  assert.equal(findDecrypted([{ event_id: '$e', content: { kind: 'unable_to_decrypt' } }], '$e', 'c').reason, 'unable_to_decrypt');
  assert.equal(findDecrypted([remote], '$e', 'c').ok, true);
});

test('wsl: drvfs path', () => {
  assert.equal(mntPath('D:\\a\\_temp\\se-x\\w.whl'), '/mnt/d/a/_temp/se-x/w.whl');
  assert.throws(() => mntPath('\\\\server\\share\\x'), /drive-absolute/);
});

test('close-to-tray settings keep the genuine Windows title bar so the app does not recreate its window', () => {
  const source = readFileSync(new URL('../driver.mjs', import.meta.url), 'utf8');
  const call = source.split('\n').find(l => l.includes("'applyWindowSettings'"));
  assert.ok(call, 'driver applies window settings');
  assert.match(call, /useCustomTitleBar: true/);
});
