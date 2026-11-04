import { generateKeyPairSync, sign } from 'node:crypto';
import { createReadStream, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:https';
import { Transform } from 'node:stream';

// Feed HTTPS real (CA própria da execução, separada do Synapse HTTP) com manifest Ed25519 do runtime desktop-update.
export function signingKey() {
  const pair = generateKeyPairSync('ed25519');
  return { privateKey: pair.privateKey, publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }) };
}

export function envelope(privateKey, { origin, version, seq, sha512, size }) {
  const payload = JSON.stringify({ appId: 'MINDTECH', arch: 'x64', channel: 'stable', platform: 'win32', seq,
    sha512, size, url: `${origin}/sable-${version}-x64.exe`, version });
  return { payload, signature: sign(null, Buffer.from(payload), privateKey).toString('base64') };
}

export function updatesResource(origin, publicKey) {
  return JSON.stringify({ schema: 1, channel: 'stable', feedURL: `${origin}/manifest`, publicKey });
}

// state: {manifest, installers:{name:path}, tamper:boolean}. Adulteração no stream de saída, metadata assinada intacta.
export async function startFeed({ keyFile, certFile }, state) {
  const counts = [];
  const server = createServer({ key: readFileSync(keyFile), cert: readFileSync(certFile) }, (req, res) => {
    if (req.method === 'GET' && req.url === '/manifest' && state.manifest) { res.end(JSON.stringify(state.manifest)); return; }
    const file = req.method === 'GET' && state.installers[req.url.slice(1)];
    if (!file) { res.writeHead(404); res.end(); return; }
    const record = { name: req.url.slice(1), tampered: state.tamper, bytes: 0 };
    counts.push(record);
    let flip = state.tamper;
    const mutate = new Transform({ transform(chunk, _e, done) {
      if (flip) { chunk = Buffer.from(chunk); chunk[0] ^= 1; flip = false; }
      record.bytes += chunk.length; done(null, chunk);
    } });
    const input = createReadStream(file);
    input.on('error', () => res.destroy()); res.on('close', () => input.destroy());
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': statSync(file).size });
    input.pipe(mutate).pipe(res);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { server, origin: `https://127.0.0.1:${server.address().port}`, counts };
}
