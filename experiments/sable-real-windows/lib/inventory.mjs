import { createHash } from 'node:crypto';
import { closeSync, lstatSync, openSync, readSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export function hashFile(path, algorithm = 'sha256', encoding = 'hex') {
  const hash = createHash(algorithm), fd = openSync(path, 'r'), buffer = Buffer.allocUnsafe(1 << 20);
  try {
    for (let n; (n = readSync(fd, buffer, 0, buffer.length, null)) > 0;) hash.update(buffer.subarray(0, n));
  } finally { closeSync(fd); }
  return hash.digest(encoding);
}

// Inventário integral: arquivo regular físico, sem link/reparse; caminho relativo com '/'.
export function inventory(root) {
  const items = [];
  const walk = (dir, prefix) => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name), rel = prefix ? `${prefix}/${name}` : name, st = lstatSync(full);
      if (st.isSymbolicLink()) throw new Error(`inventory: link refused: ${rel}`);
      if (st.isDirectory()) walk(full, rel);
      else if (st.isFile()) items.push({ path: rel, size: st.size, sha256: hashFile(full) });
      else throw new Error(`inventory: non-regular entry: ${rel}`);
    }
  };
  walk(root, '');
  return items;
}

export function inventoryDigest(items) {
  return createHash('sha256').update(JSON.stringify(items)).digest('hex');
}

// Compara instalado contra o payload empacotado. Extras só pelos nomes exatos permitidos (desinstalador NSIS).
export function compareInventory(expected, actual, allowedExtras = []) {
  const want = new Map(expected.map(i => [i.path.toLowerCase(), i]));
  const got = new Map(actual.map(i => [i.path.toLowerCase(), i]));
  const missing = [], changed = [], extra = [];
  for (const [key, item] of want) {
    const other = got.get(key);
    if (!other) missing.push(item.path);
    else if (other.size !== item.size || other.sha256 !== item.sha256) changed.push(item.path);
  }
  const allowed = new Set(allowedExtras.map(n => n.toLowerCase()));
  for (const [key, item] of got) if (!want.has(key) && !allowed.has(key)) extra.push(item.path);
  return { equal: !missing.length && !changed.length && !extra.length, expectedCount: expected.length,
    actualCount: actual.length, missing: missing.slice(0, 32), changed: changed.slice(0, 32), extra: extra.slice(0, 32) };
}
