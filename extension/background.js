// Service worker: the only place that touches keys. Handles WebAuthn requests from pages,
// the popup UI, and the approval window.

import { createStore } from './lib/store.js';
import { resolveRpId, createCredential, getAssertion } from './lib/webauthn.js';

const store = createStore({ local: chrome.storage.local, session: chrome.storage.session });
const EXT_URL = chrome.runtime.getURL('');
const NATIVE = { handled: false };
const pending = new Map(); // reqId -> { info, resolve, windowId, verified }

const fail = (name, message) => ({ handled: true, error: { name, message } });
const NOT_ALLOWED = 'The operation either timed out or was not allowed.';

// ---------- timers ----------

async function armAutoLock() {
  const { settings } = await store.status();
  await chrome.alarms.clear('autolock');
  if (settings.autoLockMinutes > 0) {
    chrome.alarms.create('autolock', { delayInMinutes: settings.autoLockMinutes });
  }
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'autolock') {
    await store.lock();
  } else if (alarm.name === 'sync') {
    const st = await store.status();
    if (st.unlocked && st.account && st.account.syncUrl) store.sync().catch(() => {});
  }
});

function ensureSyncAlarm() {
  chrome.alarms.get('sync', (a) => {
    if (!a) chrome.alarms.create('sync', { periodInMinutes: 15 });
  });
}
chrome.runtime.onInstalled.addListener(ensureSyncAlarm);
chrome.runtime.onStartup.addListener(ensureSyncAlarm);

function syncSoon() {
  store
    .status()
    .then((st) => {
      if (st.unlocked && st.account && st.account.syncUrl) return store.sync();
    })
    .catch(() => {});
}

// ---------- approval window ----------

async function askUser(info) {
  const reqId = crypto.randomUUID();
  const entry = { info, windowId: null, verified: false, resolve: null };
  const answer = new Promise((resolve) => {
    entry.resolve = resolve;
  });
  pending.set(reqId, entry);
  try {
    const win = await chrome.windows.create({
      url: chrome.runtime.getURL('approve.html') + '?req=' + encodeURIComponent(reqId),
      type: 'popup',
      width: 440,
      height: 620,
      focused: true
    });
    entry.windowId = win.id;
  } catch {
    pending.delete(reqId);
    return { action: 'cancel' };
  }
  const decision = await answer;
  return decision;
}

function finish(reqId, decision) {
  const entry = pending.get(reqId);
  if (!entry) return;
  pending.delete(reqId);
  entry.resolve(decision);
  if (entry.windowId != null) chrome.windows.remove(entry.windowId).catch(() => {});
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [reqId, e] of pending) {
    if (e.windowId === windowId) {
      pending.delete(reqId);
      e.resolve({ action: 'cancel' });
    }
  }
});

// ---------- WebAuthn requests from pages ----------

function originOf(sender) {
  try {
    const u = new URL(sender.url);
    return u.origin === 'null' ? null : u.origin;
  } catch {
    return null;
  }
}

function tabBusy(tabId) {
  for (const e of pending.values()) if (e.info.tabId === tabId) return true;
  return false;
}

async function onCreate(p, sender) {
  const origin = originOf(sender);
  if (!origin || sender.frameId !== 0) return NATIVE;
  const st = await store.status();
  if (!st.configured || !st.settings.interceptCreate) return NATIVE;
  const pk = p.publicKey;

  const rpId = resolveRpId(pk.rp.id, origin);
  if (!rpId) {
    return fail('SecurityError', 'The relying party ID is not a registrable domain suffix of, nor equal to the current domain.');
  }

  // Only take over what we can serve: platform-style ES256 passkeys.
  const params = pk.pubKeyCredParams || [];
  if (params.length && !params.some((c) => c.type === 'public-key' && c.alg === -7)) return NATIVE;
  const sel = pk.authenticatorSelection || {};
  if (sel.authenticatorAttachment === 'cross-platform') return NATIVE;
  if (Array.isArray(pk.hints) && pk.hints[0] === 'security-key') return NATIVE;

  if (tabBusy(sender.tab.id)) return fail('NotAllowedError', NOT_ALLOWED);
  const uvRequired = sel.userVerification === 'required';
  const decision = await askUser({
    kind: 'create',
    tabId: sender.tab.id,
    origin,
    rpId,
    rpName: pk.rp.name || rpId,
    user: pk.user,
    excludeIds: (pk.excludeCredentials || []).map((c) => c.id),
    uvRequired
  });
  if (decision.action === 'native') return NATIVE;
  if (decision.action !== 'approve') return fail('NotAllowedError', NOT_ALLOWED);

  if (pk.excludeCredentials && pk.excludeCredentials.length) {
    const existing = await store.findCredentials(rpId, null);
    const ids = new Set(pk.excludeCredentials.map((c) => c.id));
    if (existing.some((c) => ids.has(c.id))) {
      return fail('InvalidStateError', 'The user attempted to register an authenticator that contains one of the credentials already registered with the relying party.');
    }
  }

  const { record, response } = await createCredential({
    rpId,
    rpName: pk.rp.name,
    user: pk.user,
    challenge: pk.challenge,
    origin,
    uv: decision.verified
  });
  await store.addCredential(record);
  armAutoLock();
  syncSoon();
  return { handled: true, response };
}

async function onGet(p, sender) {
  const origin = originOf(sender);
  if (!origin || sender.frameId !== 0) return NATIVE;
  // Conditional (autofill) UI is not supported yet: let Chrome handle it.
  if (p.mediation === 'conditional') return NATIVE;
  const st = await store.status();
  if (!st.configured) return NATIVE;
  const pk = p.publicKey;

  const rpId = resolveRpId(pk.rpId, origin);
  if (!rpId) {
    return fail('SecurityError', 'The relying party ID is not a registrable domain suffix of, nor equal to the current domain.');
  }
  if (Array.isArray(pk.hints) && pk.hints[0] === 'security-key') return NATIVE;
  const allowIds = (pk.allowCredentials || []).map((c) => c.id);

  // When locked we can only consult the local hash index of known sites.
  if (st.unlocked) {
    if ((await store.findCredentials(rpId, allowIds)).length === 0) return NATIVE;
  } else if (!(await store.hasHint(rpId))) {
    return NATIVE;
  }

  if (tabBusy(sender.tab.id)) return fail('NotAllowedError', NOT_ALLOWED);
  const decision = await askUser({
    kind: 'get',
    tabId: sender.tab.id,
    origin,
    rpId,
    allowIds,
    uvRequired: pk.userVerification === 'required'
  });
  if (decision.action === 'native') return NATIVE;
  if (decision.action !== 'approve') return fail('NotAllowedError', NOT_ALLOWED);

  const cred = (await store.findCredentials(rpId, allowIds)).find((c) => c.id === decision.credentialId);
  if (!cred) return fail('NotAllowedError', NOT_ALLOWED);
  const response = await getAssertion({
    credential: cred,
    rpId,
    challenge: pk.challenge,
    origin,
    uv: decision.verified
  });
  armAutoLock();
  return { handled: true, response };
}

// ---------- approval window API ----------

function publicCred(c) {
  return { id: c.id, userName: c.userName, userDisplayName: c.userDisplayName, createdAt: c.createdAt };
}

async function requestView(reqId) {
  const e = pending.get(reqId);
  if (!e) throw new Error('This request has expired. Close this window and try again.');
  const st = await store.status();
  const info = e.info;
  let credentials = [];
  if (st.unlocked) {
    const found = await store.findCredentials(info.rpId, info.kind === 'get' ? info.allowIds : null);
    credentials = found.map(publicCred);
  }
  return {
    kind: info.kind,
    origin: info.origin,
    rpId: info.rpId,
    rpName: info.rpName || info.rpId,
    user: info.user ? { name: info.user.name, displayName: info.user.displayName } : null,
    uvRequired: info.uvRequired,
    needsPassword: info.uvRequired && !e.verified,
    locked: !st.unlocked,
    credentials,
    account: st.account ? st.account.name : ''
  };
}

async function requestDecide(msg) {
  const e = pending.get(msg.reqId);
  if (!e) throw new Error('This request has expired.');
  if (msg.action === 'cancel' || msg.action === 'native') {
    finish(msg.reqId, { action: msg.action });
    return {};
  }
  if (msg.action !== 'approve') throw new Error('Unknown action');
  const st = await store.status();
  if (!st.unlocked) throw new Error('The vault is locked.');
  let verified = e.verified;
  if (msg.password) {
    if (!(await store.verifyPassword(msg.password))) throw new Error('Wrong master password.');
    verified = true;
    e.verified = true;
  } else if (e.info.uvRequired && !verified) {
    throw new Error('This site requires verification. Enter your master password.');
  }
  if (e.info.kind === 'get' && !msg.credentialId) throw new Error('Choose an account.');
  finish(msg.reqId, { action: 'approve', credentialId: msg.credentialId, verified });
  return {};
}

// ---------- message router ----------

async function handle(msg, sender) {
  const fromExtensionPage = typeof sender.url === 'string' && sender.url.startsWith(EXT_URL);

  if (msg.type === 'wa:create' || msg.type === 'wa:get') {
    if (fromExtensionPage || !sender.tab || sender.id !== chrome.runtime.id) throw new Error('Not allowed');
    return msg.type === 'wa:create' ? onCreate(msg.payload, sender) : onGet(msg.payload, sender);
  }

  if (!fromExtensionPage) throw new Error('Not allowed');

  switch (msg.type) {
    case 'req:ping':
      return {};
    case 'req:get':
      return requestView(msg.reqId);
    case 'req:unlock': {
      const e = pending.get(msg.reqId);
      if (!e) throw new Error('This request has expired.');
      await store.unlock(msg.password);
      e.verified = true;
      armAutoLock();
      return {};
    }
    case 'req:decide':
      return requestDecide(msg);

    case 'ui:status':
      return store.status();
    case 'ui:setup': {
      const st = await store.setup(msg);
      armAutoLock();
      return st;
    }
    case 'ui:unlock':
      await store.unlock(msg.password);
      armAutoLock();
      syncSoon();
      return store.status();
    case 'ui:lock':
      await store.lock();
      return store.status();
    case 'ui:list':
      return store.listCredentials();
    case 'ui:delete':
      await store.deleteCredential(msg.id);
      syncSoon();
      return {};
    case 'ui:sync':
      await store.sync();
      return store.status();
    case 'ui:settings': {
      const s = await store.setSettings(msg.settings || {});
      armAutoLock();
      return s;
    }
    case 'ui:export':
      return store.exportBackup();
    case 'ui:import':
      return store.importBackup(msg.blob);
    case 'ui:erase':
      await store.eraseAll({ deleteRemoteCopy: !!msg.deleteRemoteCopy });
      return store.status();
    default:
      throw new Error('Unknown message');
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handle(msg, sender).then(
    (data) => sendResponse({ ok: true, data }),
    (err) => sendResponse({ ok: false, error: String((err && err.message) || err) })
  );
  return true;
});
