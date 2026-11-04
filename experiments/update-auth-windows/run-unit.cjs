'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function errorRecord(error) {
  return Object.fromEntries(['name', 'message', 'code', 'errno', 'syscall', 'path', 'stack']
    .filter(key => error[key] !== undefined).map(key => [key, error[key]]));
}
function writeEvidence(name, report) {
  const json = JSON.stringify(report, null, 2) + '\n';
  if (process.env.UPDATE_AUTH_EVIDENCE_DIR) {
    fs.writeFileSync(path.join(process.env.UPDATE_AUTH_EVIDENCE_DIR, name + '.json'), json);
  }
  process.stdout.write(json);
}
async function withTLS(run) {
  const root = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'update-auth-tls-'));
  try {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('TLS bypass environment rejected');
    const key = path.join(root, 'key.pem'), cert = path.join(root, 'cert.pem');
    const result = spawnSync(process.env.UPDATE_AUTH_OPENSSL || 'openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=UNIT ONLY localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
      '-keyout', key, '-out', cert,
    ], { shell: false, encoding: 'utf8', timeout: 30000, windowsHide: true });
    // Never persist OpenSSL output or private PEM data in evidence.
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`OpenSSL certificate generation failed: status ${result.status}`);
    return await run({ key, cert, env: { ...process.env, NODE_EXTRA_CA_CERTS: cert, UNIT_TLS_KEY: key } });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
async function main() {
  const report = { gate: 'UNIT', status: 'FAIL', platform: process.platform, arch: process.arch,
    node: process.version, scope: 'UNIT ONLY; inert installer and substituted launchInstaller' };
  try {
    await withTLS(async ({ env }) => {
      const child = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'test.cjs'], {
        cwd: __dirname, env, shell: false, encoding: 'utf8', timeout: 120000,
        maxBuffer: 8 * 1024 * 1024, windowsHide: true,
      });
      report.child = { status: child.status, signal: child.signal, stdout: child.stdout, stderr: child.stderr };
      if (child.error) report.error = errorRecord(child.error);
      const complete = /^# tests 14$/m.test(child.stdout || '') && /^# pass 14$/m.test(child.stdout || '') &&
        /^# fail 0$/m.test(child.stdout || '') && /^# skipped 0$/m.test(child.stdout || '');
      report.status = child.status === 0 && !child.error && complete ? 'PASS' :
        process.platform === 'win32' && /\b(EPERM|EACCES|EINVAL|ENOTSUP|EBADF|EISDIR)\b/.test(
          (child.stdout || '') + (child.stderr || '')) ? 'BLOQUEADO' : 'FAIL';
    });
    report.tlsCleanup = 'completed';
  } catch (error) { report.status = 'FAIL'; report.error = errorRecord(error); }
  writeEvidence('unit', report);
  process.exitCode = report.status === 'PASS' ? 0 : 1;
}
module.exports = { withTLS, errorRecord, writeEvidence };
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
