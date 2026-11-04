'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createHash, createPublicKey, verify } = require('node:crypto');
const semver = require('semver');
const { NsisUpdater, Provider } = require('electron-updater');
const { CancellationError } = require('builder-util-runtime');
const BOOTSTRAP = '2.2.1';
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
async function receive(url, limit, consume, token) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120000);
  const abort = () => controller.abort();
  if (token) { token.on('cancel', abort); if (token.cancelled) abort(); }
  try {
    const response = await fetch(url, { redirect: 'error', signal: controller.signal });
    demand(response.status === 200 && response.body, 'HTTP response');
    let count = 0;
    for await (const bytes of response.body) {
      count += bytes.length;
      demand(count <= limit, 'response size limit');
      if (token && token.cancelled) throw new CancellationError();
      await consume(bytes);
    }
    return count;
  } finally { clearTimeout(timer); if (token) token.removeListener('cancel', abort); }
}
class Policy {
  #key; #feed; #channel; #state; #high = null; #infos = new WeakMap(); #lock;
  constructor(options, app) {
    this.#key = createPublicKey(options.publicKey);
    demand(this.#key.asymmetricKeyType === 'ed25519', 'Ed25519 key required');
    this.#feed = httpsURL(options.feedURL);
    demand(typeof options.channel === 'string' && options.channel.length > 0, 'channel required');
    this.#channel = options.channel;
    demand(semver.valid(app.version) && semver.gte(app.version, BOOTSTRAP), 'bootstrap version');
    this.currentVersion = app.version;
    this.#state = path.join(app.userDataPath, 'mindtech-update-seq.json');
    this.#lock = fs.openSync(this.#state + '.lock', 'wx', 0o600);
    try {
      if (fs.existsSync(this.#state)) {
        demand(fs.statSync(this.#state).size <= 16384, 'state size');
        const envelope = JSON.parse(fs.readFileSync(this.#state, 'utf8'));
        this.decode(envelope);
        this.#high = envelope;
      }
    } catch (e) { this.close(); throw e; }
  }
  close() {
    if (this.#lock === undefined) return;
    fs.closeSync(this.#lock); this.#lock = undefined;
    fs.unlinkSync(this.#state + '.lock');
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
  guard(info) {
    demand(this.#lock !== undefined, 'policy closed');
    const envelope = this.#infos.get(info);
    demand(envelope && this.#high && envelope.payload === this.#high.payload &&
      envelope.signature === this.#high.signature, 'metadata not current/authenticated');
    const m = this.decode(envelope);
    demand(semver.gt(m.version, this.currentVersion), 'downgrade/current version');
    return m;
  }
  async latest() {
    const parts = [];
    await receive(this.#feed.href, 16384, bytes => parts.push(Buffer.from(bytes)));
    const envelope = JSON.parse(Buffer.concat(parts).toString('utf8'));
    const m = this.decode(envelope);
    demand(semver.gt(m.version, this.currentVersion), 'downgrade/current version');
    if (this.#high) {
      const high = this.decode(this.#high);
      demand(m.seq >= high.seq, 'rollback sequence');
      if (m.seq === high.seq) demand(envelope.payload === this.#high.payload &&
        envelope.signature === this.#high.signature, 'sequence reused');
      else demand(semver.gt(m.version, high.version), 'rollback version');
    }
    if (!this.#high || envelope.payload !== this.#high.payload) {
      const temp = this.#state + '.new';
      const fd = fs.openSync(temp, 'wx', 0o600);
      try { fs.writeFileSync(fd, JSON.stringify(envelope)); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      fs.renameSync(temp, this.#state);
      const dir = fs.openSync(path.dirname(this.#state), 'r');
      try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
      this.#high = Object.freeze(envelope);
    }
    const file = Object.freeze({ url: m.url, sha512: m.sha512, size: m.size });
    const info = Object.freeze({ version: m.version, files: Object.freeze([file]) });
    this.#infos.set(info, Object.freeze(envelope));
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
class SignedProvider extends Provider {
  #policy;
  constructor(options, updater, runtime) { super(runtime); this.#policy = options.authPolicy; }
  getLatestVersion() { return this.#policy.latest(); }
  resolveFiles(info) {
    const m = this.#policy.guard(info);
    return [{ url: new URL(m.url), info: info.files[0] }];
  }
}
class AuthenticatedNsisUpdater extends NsisUpdater {
  #policy;
  #pendingInfo;
  #downloadedInfo;
  #launchAttempt = 0;
  constructor(options, app) {
    super(null, app);
    this.autoDownload = false; this.autoInstallOnAppQuit = false;
    this.autoRunAppAfterInstall = false;
    this.allowDowngrade = false; this.allowPrerelease = false;
    this.disableWebInstaller = true; this.disableDifferentialDownload = true;
    this.#policy = new Policy(options, this.app);
    this.setFeedURL({ provider: 'custom', updateProvider: SignedProvider, authPolicy: this.#policy });
  }
  close() { this.#policy.close(); }
  // Public/protected extension only: independent full download, NOT Authenticode verification.
  async executeDownload(options) {
    const info = options.downloadUpdateOptions.updateInfoAndProvider.info;
    const m = this.#policy.guard(info); // Must precede super: it can accept cache without running task.
    demand(!options.fileInfo.packageInfo && options.fileInfo.url.href === m.url &&
      options.fileInfo.info === info.files[0], 'file metadata');
    this.#pendingInfo = info;
    return super.executeDownload({ ...options, task: async (destination) => {
      const fd = fs.openSync(destination, 'wx', 0o600);
      try {
        const size = await receive(m.url, m.size, bytes => {
          let offset = 0;
          while (offset < bytes.length) {
            const n = fs.writeSync(fd, bytes, offset, bytes.length - offset);
            demand(n > 0, 'short write'); offset += n;
          }
        }, options.downloadUpdateOptions.cancellationToken);
        demand(size === m.size, 'download size'); fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
      this.#policy.rehash(destination, info);
    } });
  }
  dispatchUpdateDownloaded(event) {
    this.#policy.rehash(event.downloadedFile, this.#pendingInfo);
    this.#downloadedInfo = this.#pendingInfo;
    super.dispatchUpdateDownloaded(event);
  }
  // Own adapter: Node public spawn contract; overridden only by UNIT fixtures.
  launchInstaller(file, args) {
    return spawn(file, args, {
      shell: false,
      detached: true,
      stdio: 'ignore',
    });
  }
  doInstall(options) {
    try {
      demand(!options.isAdminRightsRequired && !options.isForceRunAfter &&
        !this.installDirectory, 'unsupported install options');
      demand(this.#downloadedInfo && this.#downloadedInfo === this.#pendingInfo,
        'authenticated full installer not ready');
      const args = options.isSilent ? ['/S'] : [];
      const file = this.installerPath;
      const attempt = ++this.#launchAttempt;
      this.#policy.rehash(file, this.#downloadedInfo);
      const child = this.launchInstaller(file, args);
      child.once('error', error => {
        if (this.#launchAttempt === attempt) this.quitAndInstallCalled = false;
        this.dispatchError(error);
      });
      if (typeof child.pid !== 'number' || !Number.isInteger(child.pid) || child.pid <= 0) {
        this.quitAndInstallCalled = false;
        return false;
      }
      child.unref();
      // True means process creation accepted, never installation completed.
      return true;
    } catch (error) {
      this.quitAndInstallCalled = false;
      throw error;
    }
  }
}
module.exports = { AuthenticatedNsisUpdater };
