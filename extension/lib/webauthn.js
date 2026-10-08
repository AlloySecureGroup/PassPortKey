// The virtual authenticator: builds WebAuthn registration and assertion responses.
// Pure WebCrypto, no chrome.* APIs, so it runs identically in the service worker and in Node tests.

import { b64uEncode, b64uDecode, concat, enc, hex, sha256, randomBytes, u16be, u32be } from './util.js';
import { cborEncode } from './cbor.js';

export const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

// A browser would use the full Public Suffix List. This is a small guard list of the
// suffixes people most often get wrong. Anything not listed here is still protected by
// the "rpId must be the origin host or a parent domain" rule.
const BLOCKED_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp',
  'or.jp', 'com.br', 'com.cn', 'com.mx', 'co.in', 'co.za', 'com.sg', 'com.hk', 'com.tw',
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app',
  'herokuapp.com', 'appspot.com', 'web.app', 'firebaseapp.com', 'blogspot.com',
  'cloudfront.net', 's3.amazonaws.com', 'azurewebsites.net', 'onrender.com', 'fly.dev'
]);

function isIpLike(host) {
  return /^[0-9.]+$/.test(host) || host.includes(':') || host.startsWith('[');
}

/**
 * Returns the effective rpId, or null if the request must be rejected.
 * This check is what makes passkeys phishing resistant. Do not weaken it.
 */
export function resolveRpId(requested, origin) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  const secure =
    url.protocol === 'https:' ||
    (url.protocol === 'http:' && (host === 'localhost' || host.endsWith('.localhost')));
  if (!secure || isIpLike(host)) return null;

  const rpId = (requested || host).toLowerCase();
  if (rpId === host) return rpId;
  if (!/^[a-z0-9.-]+$/.test(rpId) || !rpId.includes('.') || isIpLike(rpId)) return null;
  if (BLOCKED_SUFFIXES.has(rpId)) return null;
  if (host.endsWith('.' + rpId)) return rpId;
  return null;
}

function derInt(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  let v = b.slice(i);
  if (v[0] & 0x80) v = concat(Uint8Array.of(0), v);
  return concat(Uint8Array.of(0x02, v.length), v);
}

/** WebCrypto returns r||s (P1363). WebAuthn wants ASN.1 DER. */
export function rawSigToDer(raw) {
  const body = concat(derInt(raw.slice(0, 32)), derInt(raw.slice(32, 64)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

function clientData(type, challenge, origin) {
  return enc.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

function flags(uv, withAttestedData) {
  // Synced passkey: backup eligible (BE) and backed up (BS) are both set.
  let f = FLAG.UP | FLAG.BE | FLAG.BS;
  if (uv) f |= FLAG.UV;
  if (withAttestedData) f |= FLAG.AT;
  return f;
}

/**
 * Create a new credential.
 * Returns { record, response }: `record` is stored in the encrypted vault (contains the
 * private key), `response` is sent to the page (public data only).
 */
export async function createCredential({ rpId, rpName, user, challenge, origin, uv, now = Date.now() }) {
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));

  const credId = randomBytes(32);
  // COSE_Key, canonical key order: 1, 3, -1, -2, -3
  const cose = cborEncode(
    new Map([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, b64uDecode(pubJwk.x)],
      [-3, b64uDecode(pubJwk.y)]
    ])
  );

  const rpIdHash = await sha256(enc.encode(rpId));
  const authData = concat(
    rpIdHash,
    Uint8Array.of(flags(uv, true)),
    u32be(0), // sign counter: always 0 for synced passkeys
    new Uint8Array(16), // AAGUID: zeros (no attestation)
    u16be(credId.length),
    credId,
    cose
  );

  const attestationObject = cborEncode(
    new Map([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData]
    ])
  );

  const id = b64uEncode(credId);
  const record = {
    id,
    rpId,
    rpName: rpName || rpId,
    userHandle: user.id,
    userName: user.name || '',
    userDisplayName: user.displayName || '',
    privateKeyJwk: privJwk,
    createdAt: now,
    updatedAt: now
  };

  const response = {
    id,
    clientDataJSON: b64uEncode(clientData('webauthn.create', challenge, origin)),
    attestationObject: b64uEncode(attestationObject),
    authenticatorData: b64uEncode(authData),
    publicKey: b64uEncode(spki),
    publicKeyAlgorithm: -7,
    transports: ['internal', 'hybrid']
  };
  return { record, response };
}

/** Sign an assertion with a stored credential. */
export async function getAssertion({ credential, rpId, challenge, origin, uv }) {
  const key = await crypto.subtle.importKey(
    'jwk',
    credential.privateKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const rpIdHash = await sha256(enc.encode(rpId));
  const authData = concat(rpIdHash, Uint8Array.of(flags(uv, false)), u32be(0));
  const cd = clientData('webauthn.get', challenge, origin);
  const cdHash = await sha256(cd);
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, concat(authData, cdHash))
  );
  return {
    id: credential.id,
    clientDataJSON: b64uEncode(cd),
    authenticatorData: b64uEncode(authData),
    signature: b64uEncode(rawSigToDer(raw)),
    userHandle: credential.userHandle
  };
}

export async function rpIdHashHex(rpId) {
  return hex(await sha256(enc.encode(rpId)));
}
