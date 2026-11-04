import { lstatSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Únicos nomes publicáveis: resultado, digests, metadata e PNG da conta sintética.
export const PUBLIC_FILES = Object.freeze(['result.json', 'inputs.json', 'build.json', 'synapse.json', 'seed.json',
  'negative.json', 'update.json', 'chain.json', 'installed.json', 'restore.json', 'diagnostics.json', 'account.png']);
const MAX_BYTES = 8 * 1024 * 1024;

// Padrões genéricos além dos valores exatos desta execução.
const PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bsyt_[A-Za-z0-9_]{10,}/, /\bgh[pousr]_[A-Za-z0-9]{20,}/, /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /"(access_token|refresh_token|password|registration_shared_secret|macaroon_secret_key|form_secret)"\s*:\s*"[^"]/i,
  /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/,
];

export function secretScan(bytes, secrets) {
  const hits = [];
  for (const value of secrets) {
    if (typeof value !== 'string' || value.length < 8) throw new Error('secret scan: invalid registered secret');
    for (const encoding of ['utf8', 'utf16le']) {
      if (bytes.includes(Buffer.from(value, encoding))) { hits.push(`registered secret (${encoding})`); break; }
    }
  }
  const text = bytes.toString('latin1');
  for (const pattern of PATTERNS) if (pattern.test(text)) hits.push(`pattern ${pattern.source.slice(0, 40)}`);
  return hits;
}

export class PublicEvidence {
  #out; #secrets = [];
  constructor(out) { this.#out = out; }
  registerSecrets(values) { for (const v of values) this.#secrets.push(v); }
  write(name, value) {
    if (!PUBLIC_FILES.includes(name)) throw new Error(`evidence: ${name} not in allowlist`);
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value, null, 1));
    if (bytes.length > MAX_BYTES) throw new Error(`evidence: ${name} too large`);
    const hits = secretScan(bytes, this.#secrets);
    if (hits.length) throw new Error(`evidence: ${name} refused by secret scan: ${hits.join('; ')}`);
    writeFileSync(join(this.#out, name), bytes, { flag: 'wx' });
  }
  // Varredura final antes de upload: remove o que não estiver na allowlist ou falhar no scan.
  audit() {
    const refused = [];
    for (const name of readdirSync(this.#out)) {
      const full = join(this.#out, name), st = lstatSync(full);
      const bad = !PUBLIC_FILES.includes(name) || !st.isFile() || st.size > MAX_BYTES
        || secretScan(readFileSync(full), this.#secrets).length > 0;
      if (bad) { refused.push(name); rmSync(full, { recursive: true, force: true }); }
    }
    return refused;
  }
}
