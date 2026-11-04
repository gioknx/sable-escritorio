'use strict';
// Lógica pura do wrapper do ENSAIO (sem electron): testável em Node; o ensaio-entry.cjs só aplica o resultado.
// Fonte da configuração: <raiz>\ensaio-launch.json, irmão de <raiz>\i (diretório do Sable.exe instalado).
// Motivo: a reabertura pelo NSIS (StdUtils.ExecShellAsUser) herda o ambiente do explorer, não o do driver.
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');
const { createHash, X509Certificate } = require('node:crypto');

const LAUNCH = 'ensaio-launch.json';
const MARKER = '.sable-ensaio-root';
const KEYS = 'appData,caPem,caSha256,cdpPort,cdpPortUpdated,home,localAppData,nonce,root,schema,temp';
const DIRS = ['appData', 'localAppData', 'home', 'temp'];

function demand(ok, reason) { if (!ok) throw new Error(`ENSAIO_LAUNCH: ${reason}`); }
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const port = v => Number.isInteger(v) && v >= 1024 && v < 65536;
const inside = (root, p) => {
  const rel = path.relative(root, p);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
};

// Caminho físico: absoluto, canônico (sem link/junção no trajeto) e dentro da raiz.
function physical(root, p, kind) {
  demand(typeof p === 'string' && path.isAbsolute(p) && path.resolve(p) === p, `absolute canonical ${kind}`);
  demand(fs.realpathSync.native(p) === p, `physical path ${kind}`);
  demand(root === null || inside(root, p), `${kind} inside root`);
  const st = fs.lstatSync(p);
  if (kind === 'dir') demand(st.isDirectory(), 'directory');
  else demand(st.isFile() && st.nlink === 1, `${kind} regular single-link file`);
  return st;
}

function readFile(root, p, kind, limit) {
  physical(root, p, kind);
  const bytes = fs.readFileSync(p);
  demand(bytes.length > 0 && bytes.length <= limit, `${kind} size`);
  return bytes;
}

// execPath: o Sable.exe em execução; argv: process.argv. Retorna o que aplicar antes do main.cjs real.
function loadLaunch(execPath, argv) {
  const root = path.dirname(path.dirname(execPath));
  const file = path.join(root, LAUNCH);
  physical(null, root, 'dir');
  const raw = readFile(root, file, 'launch', 8192);
  const value = JSON.parse(raw.toString('utf8'));
  demand(value && Object.keys(value).sort().join() === KEYS && value.schema === 1, 'launch schema');
  demand(value.root === root, 'launch root');
  demand(typeof value.nonce === 'string' && /^[a-f0-9]{32}$/.test(value.nonce), 'nonce');
  for (const key of DIRS) physical(root, value[key], 'dir');
  demand(readFile(root, path.join(value.appData, MARKER), 'marker', 64).toString('utf8') === value.nonce, 'marker');
  demand(port(value.cdpPort) && port(value.cdpPortUpdated) && value.cdpPort !== value.cdpPortUpdated, 'cdp ports');
  const pem = readFile(root, value.caPem, 'ca', 16384);
  demand(typeof value.caSha256 === 'string' && sha256(pem) === value.caSha256, 'ca pin');
  const text = pem.toString('ascii');
  demand(/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/.test(text), 'ca PEM certificate only');
  const cert = new X509Certificate(pem);
  const now = Date.now();
  demand(cert.ca === true && Date.parse(cert.validFrom) <= now && now < Date.parse(cert.validTo), 'ca certificate valid CA');
  // '--updated' só vem do NSIS StartApp; o driver nunca o passa ao seed. Seleciona porta e testemunha.
  const updated = argv.slice(1).includes('--updated');
  return {
    root, nonce: value.nonce, appData: value.appData, updated, launchSha256: sha256(raw),
    cdpPort: updated ? value.cdpPortUpdated : value.cdpPort,
    env: { USERPROFILE: value.home, HOME: value.home, APPDATA: value.appData, LOCALAPPDATA: value.localAppData,
      TEMP: value.temp, TMP: value.temp },
    ca: { pem: text, sha256: value.caSha256, fingerprint256: cert.fingerprint256 },
  };
}

// Acrescenta a CA pública efêmera ao conjunto padrão do Node (verificação de cadeia e hostname seguem ligadas).
// Sem a API real, falha: nunca desliga verificação nem finge via NODE_EXTRA_CA_CERTS tardio.
function installCa(ca) {
  demand(typeof tls.setDefaultCACertificates === 'function' && typeof tls.getCACertificates === 'function',
    'tls.setDefaultCACertificates unavailable in this runtime');
  const current = tls.getCACertificates('default');
  const fp = pem => new X509Certificate(pem).fingerprint256;
  const present = current.some(pem => fp(pem) === ca.fingerprint256);
  if (!present) tls.setDefaultCACertificates([...current, ca.pem]);
  const after = tls.getCACertificates('default');
  demand(after.filter(pem => fp(pem) === ca.fingerprint256).length === 1, 'ca installed exactly once');
  return { alreadyPresent: present, count: after.length };
}

// Testemunha por PID do processo real: liga OS PID, argv genuíno, porta e hashes do código carregado.
function writeWitness(launch, { pid, ppid, execPath, codeDir }) {
  const dir = path.join(launch.appData, 'ensaio-witness');
  fs.mkdirSync(dir, { recursive: true });
  physical(launch.root, dir, 'dir');
  const code = name => sha256(fs.readFileSync(path.join(codeDir, name)));
  const witness = { schema: 1, nonce: launch.nonce, pid, ppid, execPath, updated: launch.updated, cdpPort: launch.cdpPort,
    launchSha256: launch.launchSha256, caSha256: launch.ca.sha256,
    code: { 'ensaio-entry.cjs': code('ensaio-entry.cjs'), 'ensaio-launch.cjs': code('ensaio-launch.cjs'), 'main.cjs': code('main.cjs') } };
  fs.writeFileSync(path.join(dir, `${pid}.json`), JSON.stringify(witness), { flag: 'wx' });
  return witness;
}

module.exports = { LAUNCH, MARKER, KEYS, loadLaunch, installCa, writeWitness };
