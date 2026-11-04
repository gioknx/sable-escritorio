import { closeSync, openSync, readSync } from 'node:fs';

// Leitura só do formato asar (Pickle: uint32 4, uint32 headerPickleSize, uint32 payload, uint32 jsonLen, JSON).
function readAt(fd, length, position) {
  const buffer = Buffer.alloc(length);
  if (readSync(fd, buffer, 0, length, position) !== length) throw new Error('asar: short read');
  return buffer;
}

export function readAsarFile(asarPath, inner) {
  const fd = openSync(asarPath, 'r');
  try {
    const prefix = readAt(fd, 16, 0);
    if (prefix.readUInt32LE(0) !== 4) throw new Error('asar: bad size pickle');
    const headerSize = prefix.readUInt32LE(4), jsonLength = prefix.readUInt32LE(12);
    if (jsonLength > headerSize || headerSize > 64 * 1024 * 1024) throw new Error('asar: header bounds');
    const header = JSON.parse(readAt(fd, jsonLength, 16).toString('utf8'));
    let node = header;
    for (const part of inner.split('/')) {
      node = node.files?.[part];
      if (!node) throw new Error(`asar: missing ${inner}`);
    }
    if (node.unpacked || node.link || typeof node.size !== 'number' || node.size > 1024 * 1024) throw new Error(`asar: unsupported entry ${inner}`);
    return readAt(fd, node.size, 8 + headerSize + Number(node.offset));
  } finally { closeSync(fd); }
}

export function asarPackageVersion(asarPath) {
  const pkg = JSON.parse(readAsarFile(asarPath, 'package.json').toString('utf8'));
  return { version: pkg.version, main: pkg.main, name: pkg.name };
}
