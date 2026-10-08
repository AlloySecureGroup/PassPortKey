// Minimal CBOR encoder: exactly what WebAuthn attestation objects and COSE keys need.
// Supports integers, text, byte strings, arrays and Maps (insertion order is preserved,
// so callers control canonical ordering).

import { concat, enc } from './util.js';

function head(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  return Uint8Array.of(
    (major << 5) | 26,
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255
  );
}

export function cborEncode(v) {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('cbor: only integers are supported');
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (typeof v === 'string') {
    const b = enc.encode(v);
    return concat(head(3, b.length), b);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(cborEncode));
  if (v instanceof Map) {
    const parts = [];
    for (const [k, val] of v) parts.push(cborEncode(k), cborEncode(val));
    return concat(head(5, v.size), ...parts);
  }
  throw new Error('cbor: unsupported type');
}
