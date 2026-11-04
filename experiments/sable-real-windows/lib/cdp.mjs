// CDP mínimo sobre o WebSocket nativo do Node (>=22). Só 127.0.0.1; nada de segredo em log.
const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function waitEndpoint(port, deadlineMs, accept = () => true) {
  const until = Date.now() + deadlineMs;
  let last = 'not reached';
  while (Date.now() < until) {
    try {
      const [version, list] = await Promise.all(['version', 'list'].map(p =>
        fetch(`http://127.0.0.1:${port}/json/${p}`, { redirect: 'error' }).then(r => r.json())));
      const page = list.find(t => t.type === 'page' && accept(t));
      if (page) return { browser: version.webSocketDebuggerUrl, page: page.webSocketDebuggerUrl, url: page.url };
      last = 'no app page';
    } catch (error) { last = String(error.message).slice(0, 128); }
    await sleep(250);
  }
  throw new Error(`cdp: endpoint ${port} ${last}`);
}

export class Cdp {
  #ws; #next = 1; #pending = new Map(); #listeners = new Set();
  static async open(url) {
    if (!/^ws:\/\/127\.0\.0\.1:\d+\//.test(url)) throw new Error('cdp: loopback endpoint required');
    const cdp = new Cdp();
    cdp.#ws = new WebSocket(url);
    await new Promise((resolve, reject) => { cdp.#ws.onopen = resolve; cdp.#ws.onerror = () => reject(new Error('cdp: connect failed')); });
    cdp.#ws.onmessage = ({ data }) => {
      const message = JSON.parse(data);
      if (message.id && cdp.#pending.has(message.id)) {
        const { resolve, reject } = cdp.#pending.get(message.id); cdp.#pending.delete(message.id);
        if (message.error) reject(new Error(`cdp: ${String(message.error.message).slice(0, 256)}`)); else resolve(message.result);
      } else if (message.method) for (const l of cdp.#listeners) l(message);
    };
    cdp.#ws.onclose = () => { for (const { reject } of cdp.#pending.values()) reject(new Error('cdp: closed')); cdp.#pending.clear(); };
    return cdp;
  }
  send(method, params = {}, timeoutMs = 60000) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#pending.delete(id); reject(new Error(`cdp: ${method} timeout`)); }, timeoutMs);
      this.#pending.set(id, { resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); } });
      this.#ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(listener) { this.#listeners.add(listener); return () => this.#listeners.delete(listener); }
  close() { this.#ws?.close(); }
}

// Executado no mundo principal da página real: abre um MessagePort próprio para o Core pelo caminho do preload.
export const PAGE_HELPER = String.raw`function () {
  if (globalThis.__sableEnsaio) return 'present';
  const { port1, port2 } = new MessageChannel();
  const pending = new Map(), events = [];
  let next = 1;
  port1.onmessage = ({ data }) => {
    if (data && Array.isArray(data.events)) { events.push(...data.events); if (events.length > 20000) events.splice(0, events.length - 20000); return; }
    if (data && typeof data.id === 'number' && pending.has(data.id)) {
      const settle = pending.get(data.id); pending.delete(data.id);
      settle('ok' in data ? { ok: data.ok } : 'err' in data ? { err: data.err } : { other: Object.keys(data) });
    }
  };
  port1.start();
  window.postMessage('sable-core-connect', location.origin, [port2]);
  globalThis.__sableEnsaio = {
    call(method, params, timeoutMs) {
      const id = next++;
      return new Promise(resolve => {
        const timer = setTimeout(() => { pending.delete(id); resolve({ err: { code: 'ensaio_timeout', message: method } }); }, timeoutMs);
        pending.set(id, value => { clearTimeout(timer); resolve(value); });
        port1.postMessage({ id, call: { method, params } });
      });
    },
    drain() { return events.splice(0); },
  };
  return 'installed';
}`;

export class CorePage {
  #cdp; #global;
  constructor(cdp) { this.#cdp = cdp; }
  static async attach(cdp) {
    const page = new CorePage(cdp);
    await cdp.send('Runtime.enable');
    await page.#refresh();
    return page;
  }
  async #refresh() {
    const { result } = await this.#cdp.send('Runtime.evaluate', { expression: 'globalThis' });
    this.#global = result.objectId;
    await this.fn(PAGE_HELPER, []);
  }
  // Argumentos vão por callFunctionOn, nunca concatenados no texto avaliado.
  async fn(declaration, args, timeoutMs = 120000) {
    const out = await this.#cdp.send('Runtime.callFunctionOn', { functionDeclaration: declaration, objectId: this.#global,
      arguments: args.map(value => ({ value })), awaitPromise: true, returnByValue: true }, timeoutMs + 5000);
    if (out.exceptionDetails) throw new Error(`page: ${String(out.exceptionDetails.text).slice(0, 256)}`);
    return out.result.value;
  }
  async call(method, params, timeoutMs = 120000) {
    const reply = await this.fn('function (m, p, t) { return this.__sableEnsaio.call(m, p, t); }', [method, params, timeoutMs], timeoutMs);
    if (!reply || !('ok' in reply)) throw new Error(`core ${method}: ${JSON.stringify(reply?.err ?? reply).slice(0, 256)}`);
    return reply.ok;
  }
  drain() { return this.fn('function () { return this.__sableEnsaio.drain(); }', []); }
  // Recarrega a UI genuína e reabre o port próprio (sem hook na aplicação).
  async reload() {
    await this.#cdp.send('Page.enable');
    const loaded = new Promise(resolve => { const off = this.#cdp.on(m => { if (m.method === 'Page.loadEventFired') { off(); resolve(); } }); });
    await this.#cdp.send('Page.reload', { ignoreCache: false });
    await loaded;
    await this.#refresh();
  }
  async screenshot() {
    const { data } = await this.#cdp.send('Page.captureScreenshot', { format: 'png' });
    return Buffer.from(data, 'base64');
  }
}

export async function browserPid(browserUrl) {
  const cdp = await Cdp.open(browserUrl);
  try {
    const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
    const browsers = processInfo.filter(p => p.type === 'browser');
    if (browsers.length !== 1) throw new Error('cdp: browser process not unique');
    return browsers[0].id;
  } finally { cdp.close(); }
}
