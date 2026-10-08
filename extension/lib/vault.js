// Key derivation, vault encryption and merge logic. Pure WebCrypto.
//
// One PBKDF2 run yields 64 bytes:
//   bytes  0..31  AES-256-GCM key that encrypts the vault (never leaves the device)
//   bytes 32..63  sync auth secret (the server only ever stores its SHA-256)
// The salt is derived from the account name, so a brand new device can compute
// the vault id and auth token before it has downloaded anything.

import { b64uEncode, b64uDecode, concat, dec, enc, hex, randomBytes, sha256 } from './util.js';

export const ITER = 600000;
const AAD = enc.encode('passportkey-vault-v1');

export function normalizeAccount(name) {
  return name.trim().toLowerCase();
}

export async function deriveMaterial(accountName, password, iterations = ITER) {
  const salt = await sha256(enc.encode('passportkey-v1:' + normalizeAccount(accountName)));
  const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, [
    'deriveBits'
  ]);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 512);
  return new Uint8Array(bits);
}

export function authToken(material) {
  return hex(material.slice(32, 64));
}

export async function vaultId(material) {
  return hex(await sha256(concat(enc.encode('passportkey-id:'), material.slice(32, 64))));
}

async function aesKey(material, usage) {
  return crypto.subtle.importKey('raw', material.slice(0, 32), 'AES-GCM', false, [usage]);
}

export function emptyVault() {
  return { v: 1, credentials: [] };
}

export async function encryptVault(material, vault, iterations = ITER) {
  const iv = randomBytes(12);
  const key = await aesKey(material, 'encrypt');
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: AAD },
    key,
    enc.encode(JSON.stringify(vault))
  );
  return { v: 1, iter: iterations, iv: b64uEncode(iv), ct: b64uEncode(new Uint8Array(ct)) };
}

export async function decryptVault(material, blob) {
  if (!blob || blob.v !== 1) throw new Error('Unsupported vault format');
  const key = await aesKey(material, 'decrypt');
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64uDecode(blob.iv), additionalData: AAD },
    key,
    b64uDecode(blob.ct)
  );
  return JSON.parse(dec.decode(pt));
}

const TOMBSTONE_MS = 90 * 24 * 3600 * 1000;

/**
 * Merge two vaults. Per credential id, the newer updatedAt wins. Deletions are kept as
 * tombstones for 90 days so a deleted passkey does not come back from a stale device.
 */
export function mergeVaults(a, b, now = Date.now()) {
  const map = new Map();
  for (const c of a.credentials.concat(b.credentials)) {
    const prev = map.get(c.id);
    if (
      !prev ||
      c.updatedAt > prev.updatedAt ||
      (c.updatedAt === prev.updatedAt && c.deleted && !prev.deleted)
    ) {
      map.set(c.id, c);
    }
  }
  const credentials = [...map.values()]
    .filter((c) => !(c.deleted && now - c.updatedAt > TOMBSTONE_MS))
    .sort((x, y) => (x.id < y.id ? -1 : 1));
  return { v: 1, credentials };
}

export function sameContent(a, b) {
  const key = (v) => v.credentials.map((c) => c.id + ':' + c.updatedAt + ':' + (c.deleted ? 1 : 0)).join('|');
  return key(a) === key(b);
}
