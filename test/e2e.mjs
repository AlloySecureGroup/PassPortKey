// End-to-end test: real Chromium + the unpacked extension + a real WebAuthn relying party
// (@simplewebauthn/server) + the sync Worker. Run with: node test/e2e.mjs

import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { handle as workerHandle } from '../worker/src/index.js';
import { fakeD1 } from './fake-d1.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const EXT = path.resolve(here, '../extension');
const SHOTS = process.env.SHOTS_DIR || path.join(os.tmpdir(), 'passportkey-shots');
fs.mkdirSync(SHOTS, { recursive: true });
const CHROME = process.env.CHROME_PATH || '/opt/pw-browsers/chromium';

const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const readBody = async (req) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
};

// ---------- sync Worker over HTTP ----------
const env = { DB: fakeD1() };
const workerServer = http.createServer(async (req, res) => {
  const body = await readBody(req);
  const out = await workerHandle(
    new Request('http://localhost' + req.url, {
      method: req.method,
      headers: req.headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : body
    }),
    env
  );
  res.writeHead(out.status, Object.fromEntries(out.headers));
  res.end(Buffer.from(await out.arrayBuffer()));
});
const workerPort = await listen(workerServer);
const SYNC_URL = 'http://localhost:' + workerPort;

// ---------- relying party ----------
let RP_PORT = 0;
let uvMode = 'preferred';
let lastChallenge = '';
const creds = new Map(); // id -> { publicKey, counter }
const PAGE = `<!doctype html><meta charset=utf-8><title>RP</title>
<button id=reg>Register</button> <button id=login>Sign in</button> <pre id=log></pre>
<script>
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
const log = (m) => document.getElementById('log').textContent = m;
async function post(u, b) { const r = await fetch(u, {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(b||{})}); return r.json(); }
document.getElementById('reg').onclick = async () => {
  try {
    const o = await post('/reg/options');
    const cred = await navigator.credentials.create({ publicKey: Object.assign({}, o, {
      challenge: b64(o.challenge), user: Object.assign({}, o.user, { id: b64(o.user.id) }),
      excludeCredentials: (o.excludeCredentials||[]).map(c => Object.assign({}, c, { id: b64(c.id) }))
    })});
    const v = await post('/reg/verify', cred.toJSON());
    log(v.verified ? 'REGISTERED' : 'REG-FAILED ' + v.error);
  } catch (e) { log('ERROR ' + e.name + ': ' + e.message); }
};
document.getElementById('login').onclick = async () => {
  try {
    const o = await post('/auth/options');
    const cred = await navigator.credentials.get({ publicKey: Object.assign({}, o, { challenge: b64(o.challenge) }) });
    const v = await post('/auth/verify', cred.toJSON());
    log(v.verified ? 'SIGNED-IN uv=' + v.uv : 'AUTH-FAILED ' + v.error);
  } catch (e) { log('ERROR ' + e.name + ': ' + e.message); }
};
</script>`;

const rpServer = http.createServer(async (req, res) => {
  const origin = 'http://localhost:' + RP_PORT;
  const send = (obj) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  try {
    if (req.method === 'GET') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(PAGE); }
    const body = JSON.parse((await readBody(req)).toString() || '{}');
    if (req.url === '/reg/options') {
      const o = await generateRegistrationOptions({
        rpName: 'Test RP', rpID: 'localhost', userName: 'ada@example.com', userDisplayName: 'Ada',
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: uvMode },
        excludeCredentials: [...creds.keys()].map((id) => ({ id }))
      });
      lastChallenge = o.challenge;
      return send(o);
    }
    if (req.url === '/reg/verify') {
      try {
        const v = await verifyRegistrationResponse({
          response: body, expectedChallenge: lastChallenge, expectedOrigin: origin, expectedRPID: 'localhost',
          requireUserVerification: uvMode === 'required'
        });
        if (v.verified) creds.set(v.registrationInfo.credential.id, v.registrationInfo.credential);
        return send({ verified: v.verified });
      } catch (e) { return send({ verified: false, error: e.message }); }
    }
    if (req.url === '/auth/options') {
      const o = await generateAuthenticationOptions({ rpID: 'localhost', userVerification: uvMode });
      lastChallenge = o.challenge;
      return send(o);
    }
    if (req.url === '/auth/verify') {
      try {
        const cred = creds.get(body.id);
        if (!cred) return send({ verified: false, error: 'unknown credential' });
        const v = await verifyAuthenticationResponse({
          response: body, expectedChallenge: lastChallenge, expectedOrigin: origin, expectedRPID: 'localhost',
          credential: cred, requireUserVerification: uvMode === 'required'
        });
        return send({ verified: v.verified, uv: v.authenticationInfo.userVerified });
      } catch (e) { return send({ verified: false, error: e.message }); }
    }
    res.writeHead(404); res.end();
  } catch (e) { res.writeHead(500); res.end(String(e)); }
});
RP_PORT = await listen(rpServer);
const RP_URL = 'http://localhost:' + RP_PORT + '/';

// ---------- browser helpers ----------
async function launch(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pk-profile-' + name + '-'));
  const context = await chromium.launchPersistentContext(dir, {
    executablePath: CHROME,
    headless: false,
    args: ['--headless=new', '--no-sandbox', '--disable-extensions-except=' + EXT, '--load-extension=' + EXT],
    viewport: { width: 900, height: 700 }
  });
  let sw = context.serviceWorkers()[0];
  if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 15000 });
  const id = new URL(sw.url()).host;
  return { context, id, dir };
}

async function findPage(context, needle, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const p = context.pages().find((x) => x.url().includes(needle));
    if (p) { await p.waitForLoadState('domcontentloaded'); return p; }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('No page matching ' + needle + '. Pages: ' + context.pages().map((p) => p.url()).join(', '));
}

async function setupVault(app, mode, shot) {
  const page = await app.context.newPage();
  await page.goto('chrome-extension://' + app.id + '/popup.html');
  if (mode === 'signin') await page.getByRole('tab', { name: 'Sign in' }).click();
  await page.fill('#acct', 'ada@example.com');
  await page.fill('#pw', 'correct horse battery staple');
  if (mode === 'create') await page.fill('#pw2', 'correct horse battery staple');
  await page.fill('#url', SYNC_URL);
  if (shot) await page.screenshot({ path: path.join(SHOTS, shot + '-setup.png') });
  await page.getByRole('button', { name: mode === 'create' ? 'Create vault' : 'Sign in', exact: true }).last().click();
  await page.getByText('Search').or(page.getByPlaceholder(/Search/)).first().waitFor({ timeout: 20000 });
  return page;
}

const results = [];
const step = async (name, fn) => {
  try { await fn(); results.push(['PASS', name]); console.log('PASS', name); }
  catch (e) { results.push(['FAIL', name, e]); console.log('FAIL', name, '\n   ', e.message); }
};

let A, B;
try {
  A = await launch('a');
  let popupA;

  await step('create vault on device A and push to the sync server', async () => {
    popupA = await setupVault(A, 'create', 'a');
    await popupA.screenshot({ path: path.join(SHOTS, 'a-vault-empty.png') });
    assert.equal(env.DB.rows.size, 1, 'vault exists on server');
    const row = [...env.DB.rows.values()][0];
    assert.ok(!row.blob.includes('ada@example.com'), 'server sees no plaintext');
  });

  const rpA = await A.context.newPage();
  await rpA.goto(RP_URL);

  await step('register a passkey on a normal site via the extension', async () => {
    await rpA.click('#reg');
    const approve = await findPage(A.context, 'approve.html');
    await approve.screenshot({ path: path.join(SHOTS, 'approve-create.png') });
    const rp = await approve.locator('.rp').innerText();
    assert.equal(rp, 'localhost');
    await approve.getByRole('button', { name: 'Save passkey' }).click();
    await rpA.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.equal(await rpA.locator('#log').innerText(), 'REGISTERED');
    assert.equal(creds.size, 1);
  });

  await step('sign in with the stored passkey; the RP verifies the signature', async () => {
    await rpA.reload();
    await rpA.click('#login');
    const approve = await findPage(A.context, 'approve.html');
    await approve.screenshot({ path: path.join(SHOTS, 'approve-get.png') });
    await approve.getByRole('button', { name: 'Continue' }).click();
    await rpA.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.match(await rpA.locator('#log').innerText(), /^SIGNED-IN uv=false/);
  });

  await step('re-registering is blocked by excludeCredentials (InvalidStateError)', async () => {
    await rpA.reload();
    await rpA.click('#reg');
    const approve = await findPage(A.context, 'approve.html');
    await approve.getByRole('button', { name: 'Save passkey' }).click();
    await rpA.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.match(await rpA.locator('#log').innerText(), /ERROR InvalidStateError/);
  });

  await step('popup lists the passkey and shows it synced', async () => {
    await popupA.reload();
    await popupA.getByText('localhost', { exact: true }).waitFor({ timeout: 10000 });
    await popupA.getByText(/Synced/).waitFor({ timeout: 15000 });
    await popupA.screenshot({ path: path.join(SHOTS, 'a-vault.png') });
  });

  await step('PORTABLE: device B signs in from the cloud and logs in with the same passkey', async () => {
    B = await launch('b');
    const popupB = await setupVault(B, 'signin', 'b');
    await popupB.getByText('localhost', { exact: true }).waitFor({ timeout: 10000 });
    const rpB = await B.context.newPage();
    await rpB.goto(RP_URL);
    await rpB.click('#login');
    const approve = await findPage(B.context, 'approve.html');
    await approve.getByRole('button', { name: 'Continue' }).click();
    await rpB.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.match(await rpB.locator('#log').innerText(), /^SIGNED-IN/);
  });

  await step('site that requires user verification forces the master password', async () => {
    uvMode = 'required';
    await rpA.reload();
    await rpA.click('#login');
    const approve = await findPage(A.context, 'approve.html');
    await approve.screenshot({ path: path.join(SHOTS, 'approve-uv.png') });
    await approve.getByRole('button', { name: 'Continue' }).click();
    await approve.getByText(/Enter your master password/).first().waitFor({ timeout: 5000 });
    await approve.locator('#pw').fill('wrong password here');
    await approve.getByRole('button', { name: 'Continue' }).click();
    await approve.getByText('Wrong master password.').waitFor({ timeout: 10000 });
    await approve.locator('#pw').fill('correct horse battery staple');
    await approve.getByRole('button', { name: 'Continue' }).click();
    await rpA.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.equal(await rpA.locator('#log').innerText(), 'SIGNED-IN uv=true');
    uvMode = 'preferred';
  });

  await step('locked vault: approval window asks to unlock first', async () => {
    await popupA.reload();
    await popupA.getByRole('button', { name: 'Lock' }).click();
    await popupA.getByRole('button', { name: 'Unlock' }).waitFor();
    await popupA.screenshot({ path: path.join(SHOTS, 'a-locked.png') });
    await rpA.reload();
    await rpA.click('#login');
    const approve = await findPage(A.context, 'approve.html');
    await approve.locator('#pw').fill('correct horse battery staple');
    await approve.getByRole('button', { name: 'Unlock' }).click();
    await approve.getByRole('button', { name: 'Continue' }).click();
    await rpA.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.match(await rpA.locator('#log').innerText(), /^SIGNED-IN/);
  });

  await step('cancelling the approval window gives NotAllowedError', async () => {
    await rpA.reload();
    await rpA.click('#login');
    const approve = await findPage(A.context, 'approve.html');
    await approve.getByRole('button', { name: 'Cancel' }).click();
    await rpA.waitForFunction(() => document.getElementById('log').textContent !== '', null, { timeout: 15000 });
    assert.match(await rpA.locator('#log').innerText(), /ERROR NotAllowedError/);
  });

  await step('a page cannot claim another domain as its rpId (SecurityError)', async () => {
    const r = await rpA.evaluate(async () => {
      try {
        await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32), rpId: 'example.com' } });
        return 'no error';
      } catch (e) { return e.name; }
    });
    assert.equal(r, 'SecurityError');
  });
} finally {
  if (A) await A.context.close().catch(() => {});
  if (B) await B.context.close().catch(() => {});
  workerServer.close();
  rpServer.close();
}

const failed = results.filter((r) => r[0] === 'FAIL');
console.log('\n' + (results.length - failed.length) + '/' + results.length + ' e2e steps passed. Screenshots: ' + SHOTS);
process.exit(failed.length ? 1 : 0);
