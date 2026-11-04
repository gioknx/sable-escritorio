'use strict';
const fs = require('node:fs');
const { createHash, createPublicKey, verify } = require('node:crypto');
// Exact existing experiment installation, never a global/system SemVer fallback.
const semver = require('../update-auth-windows/node_modules/semver');
const { Store } = require('./store.cjs');
const BOOTSTRAP = '2.2.1';
const INITIALISING = Symbol('initialising');
const fields = 'appId,arch,channel,platform,seq,sha512,size,url,version';
function demand(ok, reason) { if (!ok) throw new Error(`AUTH: ${reason}`); }
function base64(value, length) {
  demand(typeof value === 'string', 'base64 type');
  const bytes = Buffer.from(value, 'base64');
  demand(bytes.length === length && bytes.toString('base64') === value, 'base64 encoding');
  return bytes;
}
function httpsURL(value) {
  const u = new URL(value);
  demand(u.protocol === 'https:' && !u.username && !u.password && !u.hash, 'HTTPS URL');
  demand(u.href === value, 'canonical URL');
  return u;
}
async function receive(url) {
  demand(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0', 'TLS bypass rejected');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120000);
  try {
    const response = await fetch(url, { redirect: 'error', signal: controller.signal });
    demand(response.status === 200 && response.body, 'HTTP response');
    let count = 0;
    const parts = [];
    for await (const bytes of response.body) {
      count += bytes.length;
      demand(count <= 16384, 'response size limit');
      parts.push(Buffer.from(bytes));
    }
    return JSON.parse(Buffer.concat(parts).toString('utf8'));
  } finally { clearTimeout(timer); }
}
class Policy {
  #key; #feed; #channel; #store; #high; #infos = new WeakMap();
  constructor(options, app, initialising) {
    demand(require('../update-auth-windows/node_modules/semver/package.json').version === '7.7.3', 'pinned semver required');
    this.#key = createPublicKey(options.publicKey);
    demand(this.#key.asymmetricKeyType === 'ed25519', 'Ed25519 key required');
    this.#feed = httpsURL(options.feedURL);
    demand(typeof options.channel === 'string' && options.channel.length > 0, 'channel required');
    this.#channel = options.channel;
    demand(semver.valid(app.version) && semver.gte(app.version, BOOTSTRAP), 'bootstrap version');
    this.currentVersion = app.version;
    if (initialising !== INITIALISING) {
      this.#store = new Store(options, envelope => this.decode(envelope));
      this.#high = this.#store.snapshot;
    }
  }
  static async initialise(options, app) {
    const policy = new Policy(options, app, INITIALISING);
    const envelope = await receive(policy.#feed.href);
    const m = policy.decode(envelope);
    demand(semver.gt(m.version, policy.currentVersion), 'downgrade/current version');
    policy.#store = new Store(options, value => policy.decode(value), envelope);
    policy.#high = policy.#store.snapshot;
    return policy;
  }
  close() {
    const store = this.#store; this.#store = undefined;
    if (store) store.close();
  }
  decode(envelope) {
    demand(envelope && Object.keys(envelope).sort().join() === 'payload,signature', 'envelope schema');
    demand(typeof envelope.payload === 'string' && Buffer.byteLength(envelope.payload) < 8192, 'payload size');
    demand(verify(null, Buffer.from(envelope.payload), this.#key, base64(envelope.signature, 64)), 'signature');
    const m = JSON.parse(envelope.payload);
    demand(m && Object.keys(m).sort().join() === fields, 'manifest schema');
    demand(m.appId === 'MINDTECH' && m.channel === this.#channel, 'identity/channel');
    demand(m.platform === 'win32' && m.arch === 'x64', 'platform/arch');
    demand(semver.valid(m.version) === m.version && semver.gt(m.version, BOOTSTRAP), 'version');
    demand(Number.isSafeInteger(m.seq) && m.seq > 0, 'sequence');
    demand(Number.isSafeInteger(m.size) && m.size > 0 && m.size <= 1024 ** 3, 'installer size');
    base64(m.sha512, 64);
    const url = httpsURL(m.url);
    demand(url.origin === this.#feed.origin && url.pathname.endsWith('.exe'), 'installer origin/type');
    return Object.freeze(m);
  }
  #opened() {
    demand(this.#store, 'policy closed');
    this.#store.snapshot; // Also fails after a poisoned transaction.
  }
  guard(info) {
    this.#opened();
    const envelope = this.#infos.get(info);
    demand(envelope && this.#high && envelope.payload === this.#high.payload &&
      envelope.signature === this.#high.signature, 'metadata not current/authenticated');
    const m = this.decode(envelope);
    demand(semver.gt(m.version, this.currentVersion), 'downgrade/current version');
    return m;
  }
  async latest() {
    this.#opened();
    const envelope = Object.freeze(await receive(this.#feed.href));
    const m = this.decode(envelope);
    demand(semver.gt(m.version, this.currentVersion), 'downgrade/current version');
    this.#opened(); // A close during the HTTPS request cannot emit metadata.
    this.#high = this.#store.advance(envelope, highEnvelope => {
      const high = this.decode(highEnvelope);
      demand(m.seq >= high.seq, 'rollback sequence');
      if (m.seq === high.seq) demand(envelope.payload === highEnvelope.payload &&
        envelope.signature === highEnvelope.signature, 'sequence reused');
      else demand(semver.gt(m.version, high.version), 'rollback version');
    });
    // No metadata or cached highwater is published until COMMIT returned successfully.
    const file = Object.freeze({ url: m.url, sha512: m.sha512, size: m.size });
    const info = Object.freeze({ version: m.version, files: Object.freeze([file]) });
    this.#infos.set(info, envelope);
    return info;
  }
  rehash(file, info) {
    const m = this.guard(info);
    const fd = fs.openSync(file, 'r');
    try {
      const before = fs.fstatSync(fd);
      demand(before.isFile() && before.size === m.size && !fs.lstatSync(file).isSymbolicLink(), 'file type/size');
      const hash = createHash('sha512'), buffer = Buffer.alloc(65536);
      let n, count = 0;
      while ((n = fs.readSync(fd, buffer, 0, buffer.length, null))) {
        count += n; demand(count <= m.size, 'file growth'); hash.update(buffer.subarray(0, n));
      }
      const after = fs.statSync(file);
      demand(count === m.size && hash.digest('base64') === m.sha512, 'installer SHA512');
      demand(before.ino === after.ino && before.dev === after.dev && before.size === after.size &&
        before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'file changed during hash');
    } finally { fs.closeSync(fd); }
  }
}
module.exports = { Policy };
