// Processo filho do io.test: precisa de NODE_EXTRA_CA_CERTS no ambiente de início (Node lê só no boot).
// Prova que o feed do ensaio (HTTPS real com CA própria, envelope Ed25519) é aceito pelo runtime REAL de
// ../desktop-update (openState + Policy.latest), e que o modo tamper altera bytes sem tocar a metadata.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { envelope, signingKey, startFeed, updatesResource } from '../lib/feed.mjs';

const [dir, runtimePath] = process.argv.slice(2);
if (process.env.SABLE_FEED_CHILD !== '1') throw new Error('run only from io.test.mjs');
const ca = join(dir, 'ca.pem');
// O pai já define NODE_EXTRA_CA_CERTS=<dir>/ca.pem; Node ignora arquivo ausente no boot, então o filho
// é relançado uma vez depois de criar a CA para que o boot leia o arquivo real.
if (!existsSync(ca)) {
  const k = p => join(dir, p);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=ensaio test CA', '-keyout', k('ca.key'), '-out', ca], { stdio: 'ignore' });
  execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', k('tls.key'), '-out', k('tls.csr')], { stdio: 'ignore' });
  writeFileSync(k('san.ext'), 'subjectAltName=IP:127.0.0.1\n');
  execFileSync('openssl', ['x509', '-req', '-in', k('tls.csr'), '-CA', ca, '-CAkey', k('ca.key'), '-CAcreateserial', '-days', '1', '-extfile', k('san.ext'), '-out', k('tls.pem')], { stdio: 'ignore' });
  const out = execFileSync(process.execPath, process.argv.slice(1), { env: process.env, encoding: 'utf8' });
  process.stdout.write(out);
  process.exit(0);
}

const require = createRequire(import.meta.url);
const { openState } = require(runtimePath);
const { Policy } = require(join(runtimePath, '..', 'policy.cjs'));
const installer = join(dir, 'sable-2.2.3-x64.exe');
writeFileSync(installer, Buffer.alloc(4096, 7));
const sha512 = createHash('sha512').update(Buffer.alloc(4096, 7)).digest('base64');
const signer = signingKey();
const state = { manifest: null, installers: { 'sable-2.2.3-x64.exe': installer }, tamper: false };
const feed = await startFeed({ keyFile: join(dir, 'tls.key'), certFile: join(dir, 'tls.pem') }, state);
try {
  const resource = JSON.parse(updatesResource(feed.origin, signer.publicKey));
  state.manifest = envelope(signer.privateKey, { origin: feed.origin, version: '2.2.2', seq: 1, sha512, size: 4096 });
  const opened = await openState({ stateRoot: join(dir, 'state'), publicKey: resource.publicKey, feedURL: resource.feedURL, channel: 'stable' }, { version: '2.2.2' });
  state.manifest = envelope(signer.privateKey, { origin: feed.origin, version: '2.2.3', seq: 2, sha512, size: 4096 });
  const policy = new Policy(opened, { version: '2.2.2' });
  const info = await policy.latest();
  policy.close();
  state.tamper = true;
  const tampered = Buffer.from(await (await fetch(info.files[0].url)).arrayBuffer());
  const tamperedBytes = tampered.length === 4096 && createHash('sha512').update(tampered).digest('base64') !== sha512 && feed.counts[0].tampered;
  console.log(JSON.stringify({ initialised: true, latest: info.version, resourceKeys: Object.keys(resource).sort().join(), tamperedBytes }));
} finally { feed.server.closeAllConnections(); feed.server.close(); }
