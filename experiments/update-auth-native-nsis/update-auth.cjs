'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { NsisUpdater, Provider } = require('../update-auth-windows/node_modules/electron-updater');
const { CancellationError } = require('../update-auth-windows/node_modules/builder-util-runtime');
const { Policy } = require('../update-auth-policy-sqlite/policy.cjs');
function demand(ok, reason) { if (!ok) throw new Error(`AUTH: ${reason}`); }
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
