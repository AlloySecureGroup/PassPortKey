import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';

import { cborEncode } from '../extension/lib/cbor.js';
import { b64uEncode, b64uDecode, randomBytes } from '../extension/lib/util.js';
import { resolveRpId, createCredential, getAssertion, rawSigToDer } from '../extension/lib/webauthn.js';
import {
  deriveMaterial, encryptVault, decryptVault, mergeVaults, emptyVault, vaultId, authToken
} from '../extension/lib/vault.js';
import { createStore } from '../extension/lib/store.js';
import { handle as workerHandle } from '../worker/src/index.js';
import { fakeD1 } from './fake-d1.mjs';

// ---------- helpers ----------

function memArea() {
  const m = new Map();
  return {
    async get(keys) {
      const out = {};
      for (const k of [].concat(keys)) if (m.has(k)) out[k] = structuredClone(m.get(k));
      return out;
    },
    async set(o) { for (const [k, v] of Object.entries(o)) m.set(k, structuredClone(v)); },
    async remove(keys) { for (const k of [].concat(keys)) m.delete(k); }
  };
}

function makeServer(env = {}) {
  const e = Object.assign({ DB: fakeD1() }, env);
  const fetchImpl = (url, init) => workerHandle(new Request(url, init), e);
  return { env: e, fetchImpl };
}

function makeDevice(server) {
  return createStore({ local: memArea(), session: memArea(), fetchImpl: server.fetchImpl });
}

const URL_ = 'https://sync.example.com';
const ORIGIN = 'https://login.example.com';
const user = { id: b64uEncode(randomBytes(16)), name: 'ada@example.com', displayName: 'Ada' };

// ---------- cbor / rpId ----------

test('cbor encodes known vectors', () => {
  const hex = (u) => Buffer.from(u).toString('hex');
  assert.equal(hex(cborEncode(0)), '00');
  assert.equal(hex(cborEncode(24)), '1818');
  assert.equal(hex(cborEncode(-7)), '26');
  assert.equal(hex(cborEncode('fmt')), '63666d74');
  assert.equal(hex(cborEncode(new Uint8Array([1, 2]))), '420102');
  assert.equal(hex(cborEncode(new Map([['a', 1]]))), 'a1616101');
  assert.equal(hex(cborEncode([1, 2])), '820102');
});

test('resolveRpId enforces the phishing-resistance rules', () => {
  assert.equal(resolveRpId(undefined, 'https://example.com'), 'example.com');
  assert.equal(resolveRpId('example.com', 'https://login.example.com'), 'example.com');
  assert.equal(resolveRpId('EXAMPLE.com', 'https://login.example.com'), 'example.com');
  assert.equal(resolveRpId('evil.com', 'https://login.example.com'), null);
  assert.equal(resolveRpId('example.com', 'https://notexample.com'), null);
  assert.equal(resolveRpId('com', 'https://example.com'), null);
  assert.equal(resolveRpId('co.uk', 'https://foo.co.uk'), null);
  assert.equal(resolveRpId('github.io', 'https://me.github.io'), null);
  assert.equal(resolveRpId(undefined, 'http://example.com'), null);
  assert.equal(resolveRpId(undefined, 'http://localhost:3000'), 'localhost');
  assert.equal(resolveRpId(undefined, 'https://127.0.0.1'), null);
  assert.equal(resolveRpId('example.com', 'https://example.com.evil.com'), null);
});

test('rawSigToDer produces DER that node:crypto accepts', async () => {
  const { generateKeyPairSync, createSign, createVerify } = await import('node:crypto');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  for (let i = 0; i < 50; i++) {
    const data = randomBytes(40);
    const ieee = createSign('SHA256').update(data).sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });
    const der = rawSigToDer(new Uint8Array(ieee));
    assert.ok(createVerify('SHA256').update(data).verify(publicKey, Buffer.from(der)));
  }
});

// ---------- WebAuthn, verified by an independent RP library ----------

test('registration and sign-in verify against @simplewebauthn/server', async () => {
  const challenge = b64uEncode(randomBytes(32));
  const { record, response } = await createCredential({
    rpId: 'example.com', rpName: 'Example', user, challenge, origin: ORIGIN, uv: true
  });

  const reg = await verifyRegistrationResponse({
    response: {
      id: response.id,
      rawId: response.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: response.clientDataJSON,
        attestationObject: response.attestationObject,
        transports: response.transports
      }
    },
    expectedChallenge: challenge,
    expectedOrigin: ORIGIN,
    expectedRPID: 'example.com',
    requireUserVerification: true
  });
  assert.equal(reg.verified, true);
  assert.equal(reg.registrationInfo.credentialDeviceType, 'multiDevice');
  assert.equal(reg.registrationInfo.credentialBackedUp, true);

  const authChallenge = b64uEncode(randomBytes(32));
  const a = await getAssertion({
    credential: record, rpId: 'example.com', challenge: authChallenge, origin: ORIGIN, uv: true
  });
  const auth = await verifyAuthenticationResponse({
    response: {
      id: a.id,
      rawId: a.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: a.clientDataJSON,
        authenticatorData: a.authenticatorData,
        signature: a.signature,
        userHandle: a.userHandle
      }
    },
    expectedChallenge: authChallenge,
    expectedOrigin: ORIGIN,
    expectedRPID: 'example.com',
    credential: {
      id: reg.registrationInfo.credential.id,
      publicKey: reg.registrationInfo.credential.publicKey,
      counter: reg.registrationInfo.credential.counter
    },
    requireUserVerification: true
  });
  assert.equal(auth.verified, true);
  assert.equal(a.userHandle, user.id);
});

test('assertion for the wrong rpId or origin is rejected by the RP', async () => {
  const challenge = b64uEncode(randomBytes(32));
  const { record, response } = await createCredential({
    rpId: 'example.com', user, challenge, origin: ORIGIN, uv: false
  });
  const reg = await verifyRegistrationResponse({
    response: {
      id: response.id, rawId: response.id, type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: response.clientDataJSON, attestationObject: response.attestationObject }
    },
    expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: 'example.com',
    requireUserVerification: false
  });
  const c2 = b64uEncode(randomBytes(32));
  const a = await getAssertion({ credential: record, rpId: 'example.com', challenge: c2, origin: ORIGIN, uv: false });
  const attempt = (origin, rpID) =>
    verifyAuthenticationResponse({
      response: {
        id: a.id, rawId: a.id, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: a.clientDataJSON, authenticatorData: a.authenticatorData, signature: a.signature }
      },
      expectedChallenge: c2, expectedOrigin: origin, expectedRPID: rpID,
      credential: reg.registrationInfo.credential,
      requireUserVerification: false
    });
  await assert.rejects(attempt('https://evil.com', 'example.com'));
  await assert.rejects(attempt(ORIGIN, 'evil.com'));
  assert.equal((await attempt(ORIGIN, 'example.com')).verified, true);
});

// ---------- vault ----------

test('vault encrypts, decrypts, and rejects a wrong password', async () => {
  const m = await deriveMaterial('Ada@Example.com ', 'correct horse battery');
  const same = await deriveMaterial('ada@example.com', 'correct horse battery');
  assert.deepEqual(m, same, 'account name is normalized');
  const vault = { v: 1, credentials: [{ id: 'a', rpId: 'x.com', updatedAt: 1 }] };
  const blob = await encryptVault(m, vault);
  assert.deepEqual(await decryptVault(m, blob), vault);
  const wrong = await deriveMaterial('ada@example.com', 'wrong horse battery');
  await assert.rejects(decryptVault(wrong, blob));
  const tampered = Object.assign({}, blob, { ct: blob.ct.slice(0, -4) + 'AAAA' });
  await assert.rejects(decryptVault(m, tampered));
  assert.notEqual(await vaultId(m), authToken(m), 'vault id must not reveal the auth token');
});

test('mergeVaults: newest wins, deletes stick, old tombstones expire', () => {
  const now = 100 * 24 * 3600 * 1000;
  const a = { v: 1, credentials: [{ id: '1', rpId: 'a', updatedAt: 10 }, { id: '2', rpId: 'b', updatedAt: 10 }] };
  const b = {
    v: 1,
    credentials: [
      { id: '1', rpId: 'a', deleted: true, updatedAt: now - 1000 },
      { id: '3', rpId: 'c', updatedAt: 20 },
      { id: '9', rpId: 'z', deleted: true, updatedAt: 5 }
    ]
  };
  const m = mergeVaults(a, b, now);
  assert.equal(m.credentials.find((c) => c.id === '1').deleted, true);
  assert.ok(m.credentials.find((c) => c.id === '2'));
  assert.ok(m.credentials.find((c) => c.id === '3'));
  assert.equal(m.credentials.find((c) => c.id === '9'), undefined, 'expired tombstone dropped');
});

// ---------- store + worker: end to end sync ----------

test('two devices sync a passkey through the Worker and the server only sees ciphertext', async () => {
  const server = makeServer();
  const phone = makeDevice(server);
  const laptop = makeDevice(server);

  await phone.setup({ mode: 'create', accountName: 'ada@example.com', password: 'a long passphrase!', syncUrl: URL_ });
  assert.equal((await phone.status()).dirty, false);

  const challenge = b64uEncode(randomBytes(32));
  const { record } = await createCredential({ rpId: 'example.com', rpName: 'Example', user, challenge, origin: ORIGIN, uv: true });
  await phone.addCredential(record);
  await phone.sync();

  await laptop.setup({ mode: 'signin', accountName: 'ADA@example.com', password: 'a long passphrase!', syncUrl: URL_ });
  const found = await laptop.findCredentials('example.com', null);
  assert.equal(found.length, 1);
  assert.equal(found[0].id, record.id);

  // The laptop can sign with the synced key and the RP accepts it.
  const c2 = b64uEncode(randomBytes(32));
  const a = await getAssertion({ credential: found[0], rpId: 'example.com', challenge: c2, origin: ORIGIN, uv: true });
  assert.ok(a.signature.length > 60);

  // Server-side data contains no plaintext secrets.
  const stored = JSON.stringify([...server.env.DB.rows.values()]);
  assert.ok(!stored.includes('example.com'));
  assert.ok(!stored.includes(record.privateKeyJwk.d));
  assert.ok(!stored.includes('a long passphrase'));
});

test('concurrent edits from two devices merge without losing either passkey', async () => {
  const server = makeServer();
  const a = makeDevice(server);
  const b = makeDevice(server);
  const pw = 'another long passphrase';
  await a.setup({ mode: 'create', accountName: 'bob@example.com', password: pw, syncUrl: URL_ });
  await b.setup({ mode: 'signin', accountName: 'bob@example.com', password: pw, syncUrl: URL_ });

  const mk = async (rp) => (await createCredential({ rpId: rp, user, challenge: b64uEncode(randomBytes(32)), origin: 'https://' + rp, uv: false })).record;
  await a.addCredential(await mk('one.example'));
  await b.addCredential(await mk('two.example'));
  await a.sync();
  await b.sync();
  await a.sync();

  for (const dev of [a, b]) {
    const rps = (await dev.listCredentials()).map((c) => c.rpId).sort();
    assert.deepEqual(rps, ['one.example', 'two.example']);
  }

  // Deleting on one device propagates and is not resurrected by the other.
  const toDelete = (await a.listCredentials()).find((c) => c.rpId === 'one.example');
  await a.deleteCredential(toDelete.id);
  await a.sync();
  await b.sync();
  assert.deepEqual((await b.listCredentials()).map((c) => c.rpId), ['two.example']);
  await b.sync();
  await a.sync();
  assert.deepEqual((await a.listCredentials()).map((c) => c.rpId), ['two.example']);
});

test('lock, unlock, wrong password, and the local site hint index', async () => {
  const server = makeServer();
  const d = makeDevice(server);
  await d.setup({ mode: 'create', accountName: 'cy@example.com', password: 'yet another passphrase' });
  const { record } = await createCredential({ rpId: 'example.com', user, challenge: b64uEncode(randomBytes(32)), origin: ORIGIN, uv: false });
  await d.addCredential(record);

  assert.equal(await d.hasHint('example.com'), true);
  assert.equal(await d.hasHint('other.com'), false);

  await d.lock();
  assert.equal((await d.status()).unlocked, false);
  await assert.rejects(d.findCredentials('example.com', null), /locked/i);
  assert.equal(await d.hasHint('example.com'), true, 'hint index works while locked');
  await assert.rejects(d.unlock('not the password'), /Wrong master password/);
  await d.unlock('yet another passphrase');
  assert.equal((await d.findCredentials('example.com', null)).length, 1);
  assert.equal(await d.verifyPassword('nope nope nope'), false);
  assert.equal(await d.verifyPassword('yet another passphrase'), true);
});

test('setup validation and sign-in failures', async () => {
  const server = makeServer();
  const d = makeDevice(server);
  await assert.rejects(d.setup({ mode: 'create', accountName: 'x@y.z', password: 'short' }), /at least 10/);
  await assert.rejects(d.setup({ mode: 'create', accountName: 'x@y.z', password: 'long enough pw', syncUrl: 'http://evil.example.com' }), /https/);
  await assert.rejects(d.setup({ mode: 'signin', accountName: 'x@y.z', password: 'long enough pw', syncUrl: URL_ }), /No vault found/);

  const a = makeDevice(server);
  await a.setup({ mode: 'create', accountName: 'x@y.z', password: 'long enough pw', syncUrl: URL_ });
  const b = makeDevice(server);
  await assert.rejects(b.setup({ mode: 'create', accountName: 'x@y.z', password: 'long enough pw', syncUrl: URL_ }), /already exists/);
  await assert.rejects(b.setup({ mode: 'signin', accountName: 'x@y.z', password: 'WRONG long enough pw', syncUrl: URL_ }), /No vault found/);
});

test('backup export and import round trip', async () => {
  const server = makeServer();
  const a = makeDevice(server);
  await a.setup({ mode: 'create', accountName: 'dee@example.com', password: 'backup passphrase 1' });
  const { record } = await createCredential({ rpId: 'example.com', user, challenge: b64uEncode(randomBytes(32)), origin: ORIGIN, uv: false });
  await a.addCredential(record);
  const backup = await a.exportBackup();

  const b = makeDevice(server);
  await b.setup({ mode: 'create', accountName: 'dee@example.com', password: 'backup passphrase 1' });
  assert.equal((await b.importBackup(backup)).count, 1);

  const c = makeDevice(server);
  await c.setup({ mode: 'create', accountName: 'dee@example.com', password: 'a different passphrase' });
  await assert.rejects(c.importBackup(backup), /different account or master password/);
});

// ---------- Worker ----------

test('worker: auth, compare-and-swap, invite code, validation', async () => {
  const server = makeServer({ INVITE_CODE: 'sesame' });
  const id = 'a'.repeat(64);
  const tok = 'b'.repeat(64);
  const other = 'c'.repeat(64);
  const blob = { v: 1, iter: 600000, iv: 'x', ct: 'y' };
  const req = (method, token, body, extra) =>
    server.fetchImpl('https://w/v1/vault/' + id, {
      method,
      headers: Object.assign({ Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, extra),
      body: body ? JSON.stringify(body) : undefined
    });

  assert.equal((await req('GET', tok)).status, 404);
  assert.equal((await req('PUT', tok, { baseVersion: 0, blob })).status, 403, 'invite required');
  assert.equal((await req('PUT', tok, { baseVersion: 0, blob }, { 'X-Invite-Code': 'sesame' })).status, 200);
  assert.equal((await req('PUT', other, { baseVersion: 1, blob })).status, 401);
  assert.equal((await req('GET', other)).status, 401);
  assert.equal((await req('PUT', tok, { baseVersion: 0, blob }, { 'X-Invite-Code': 'sesame' })).status, 409);
  assert.equal((await req('PUT', tok, { baseVersion: 5, blob })).status, 409, 'stale version');
  const ok = await req('PUT', tok, { baseVersion: 1, blob });
  assert.equal((await ok.json()).version, 2);
  assert.equal((await req('PUT', tok, { baseVersion: 1, blob })).status, 409, 'lost the race');
  assert.equal((await req('PUT', tok, { baseVersion: 2, blob: { v: 1 } })).status, 400);
  const got = await (await req('GET', tok)).json();
  assert.equal(got.version, 2);
  assert.deepEqual(got.blob, blob);
  assert.equal((await server.fetchImpl('https://w/v1/vault/nothex', { headers: { Authorization: 'Bearer ' + tok } })).status, 404);
  assert.equal((await server.fetchImpl('https://w/v1/vault/' + id)).status, 401);
  assert.equal((await req('DELETE', other)).status, 401);
  assert.equal((await req('DELETE', tok)).status, 200);
  assert.equal((await req('GET', tok)).status, 404);
  const pre = await server.fetchImpl('https://w/v1/vault/' + id, { method: 'OPTIONS' });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), '*');
});
