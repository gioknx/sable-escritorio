'use strict';
// Filho Node real: fronteira TLS do wrapper. Conecta por fetch (undici) e https antes/depois de installCa.
// Argumentos: <launch.json da CA A> <urlA> <urlB (CA B)> <urlA via nome errado>. Sem Electron, sem spoof.
const https = require('node:https');
const { readFileSync } = require('node:fs');
const { X509Certificate } = require('node:crypto');
const { installCa } = require('../entry/ensaio-launch.cjs');

const [caFile, urlA, urlB, urlWrongName] = process.argv.slice(2);
const outcome = p => p.then(() => 'ok', e => String(e.cause?.code ?? e.code ?? e.message));
const viaHttps = url => new Promise((resolve, reject) => https.get(url, r => { r.resume(); r.on('end', resolve); }).on('error', reject));

(async () => {
  const pem = readFileSync(caFile, 'ascii');
  const ca = { pem, sha256: 'unused', fingerprint256: new X509Certificate(pem).fingerprint256 };
  const before = await outcome(fetch(urlA));
  const first = installCa(ca);
  const second = installCa(ca); // idempotente: não duplica
  const result = {
    before, first, second,
    fetchA: await outcome(fetch(urlA)), httpsA: await outcome(viaHttps(urlA)),
    fetchB: await outcome(fetch(urlB)), fetchWrongName: await outcome(fetch(urlWrongName)),
  };
  process.stdout.write(JSON.stringify(result) + '\n');
})().catch(e => { process.stderr.write(String(e.stack)); process.exit(1); });
