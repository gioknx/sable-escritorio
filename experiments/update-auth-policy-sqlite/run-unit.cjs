'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
function completeTAP(output) {
  if (!/^TAP version 13\r?$/m.test(output)) return false;
  const count = label => [...output.matchAll(new RegExp(`^# ${label} (\\d+)\\r?$`, 'gm'))];
  const tests = count('tests'), pass = count('pass');
  // Minimum covers this matrix, and cannot accidentally accept the old W suite's 14.
  return tests.length === 1 && pass.length === 1 && Number(tests[0][1]) >= 17 &&
    tests[0][1] === pass[0][1] && ['fail', 'cancelled', 'skipped', 'todo'].every(label => {
      const values = count(label); return values.length === 1 && values[0][1] === '0';
    }) && new RegExp(`^1\\.\\.${tests[0][1]}\\r?$`, 'm').test(output) && !/^not ok\b/m.test(output);
}
function main() {
  const report = { gate: 'UNIT', status: 'FAIL', scope: 'Node Policy+SQLite ONLY; NOT Native',
    node: process.version, platform: process.platform, arch: process.arch,
    hashes: Object.fromEntries(['policy.cjs', 'store.cjs', 'test.cjs', 'run-unit.cjs'].map(file =>
      [file, createHash('sha256').update(fs.readFileSync(path.join(__dirname, file))).digest('hex')])) };
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-sqlite-tls-'));
  try {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('TLS bypass environment rejected');
    const key = path.join(root, 'key.pem'), cert = path.join(root, 'cert.pem');
    const generated = spawnSync(process.env.UPDATE_AUTH_OPENSSL || 'openssl', ['req', '-x509', '-newkey',
      'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=UNIT ONLY localhost', '-addext',
      'subjectAltName=IP:127.0.0.1', '-keyout', key, '-out', cert], {
      shell: false, encoding: 'utf8', timeout: 30000, windowsHide: true,
    });
    if (generated.error) throw generated.error;
    if (generated.status !== 0) throw new Error('OpenSSL certificate generation failed');
    const child = spawnSync(process.execPath, ['--test', '--test-reporter=tap', path.join(__dirname, 'test.cjs')], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: cert, UNIT_TLS_KEY: key },
      shell: false, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    });
    report.child = { status: child.status, signal: child.signal, stdout: child.stdout, stderr: child.stderr };
    if (child.error) report.error = { code: child.error.code, message: child.error.message };
    if (!child.error && child.status === 0 && child.signal === null && completeTAP(child.stdout || '')) report.status = 'PASS';
  } catch (error) { report.error = { code: error.code, message: error.message }; }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.status === 'PASS' ? 0 : 1;
}
module.exports = { completeTAP };
if (require.main === module) main();
