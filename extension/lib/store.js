// Vault store: persistence, lock state and sync orchestration.
//
// `local` and `session` are chrome.storage areas (or in-memory fakes in tests).
//   local   : encrypted vault blob, account info, settings, sync bookkeeping
//   session : the unlocked key material. Cleared when the browser closes, never written to disk,
//             and not readable by content scripts (default TRUSTED_CONTEXTS access level).

import { b64uEncode, b64uDecode, enc, hex, sha256 } from './util.js';
import {
  deriveMaterial,
  encryptVault,
  decryptVault,
  authToken,
  vaultId,
  emptyVault,
  mergeVaults,
  sameContent,
  normalizeAccount
} from './vault.js';
import { pullVault, pushVault, deleteRemote, normalizeSyncUrl } from './sync.js';

export const DEFAULT_SETTINGS = { autoLockMinutes: 15, interceptCreate: true };
const MIN_PASSWORD = 10;

async function rpHash(rpId) {
  return hex(await sha256(enc.encode(rpId)));
}

export function createStore({ local, session, fetchImpl, now = () => Date.now() }) {
  const doFetch = (...args) => (fetchImpl || globalThis.fetch)(...args);

  // All vault mutations and syncs run one at a time so they cannot overwrite each other.
  let queue = Promise.resolve();
  function serial(fn) {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  async function getMaterial() {
    const { pk_material } = await session.get('pk_material');
    return pk_material ? b64uDecode(pk_material) : null;
  }

  async function requireMaterial() {
    const m = await getMaterial();
    if (!m) throw new Error('Vault is locked');
    return m;
  }

  async function status() {
    const l = await local.get(['pk_account', 'pk_blob', 'pk_dirty', 'pk_lastSync', 'pk_syncError', 'pk_settings']);
    const m = await getMaterial();
    const acct = l.pk_account;
    return {
      configured: !!(acct && l.pk_blob),
      unlocked: !!m,
      account: acct ? { name: acct.name, syncUrl: acct.syncUrl || '', hasInvite: !!acct.inviteCode } : null,
      dirty: !!l.pk_dirty,
      lastSync: l.pk_lastSync || null,
      syncError: l.pk_syncError || null,
      settings: Object.assign({}, DEFAULT_SETTINGS, l.pk_settings)
    };
  }

  async function updateHints(vault) {
    const hashes = await Promise.all(vault.credentials.filter((c) => !c.deleted).map((c) => rpHash(c.rpId)));
    await local.set({ pk_hints: [...new Set(hashes)] });
  }

  async function readVaultUnsafe() {
    const m = await requireMaterial();
    const { pk_blob } = await local.get('pk_blob');
    if (!pk_blob) throw new Error('No vault');
    return decryptVault(m, pk_blob);
  }

  async function writeVaultUnsafe(vault, dirty = true) {
    const m = await requireMaterial();
    const blob = await encryptVault(m, vault);
    await local.set({ pk_blob: blob, pk_dirty: dirty });
    await updateHints(vault);
  }

  async function syncUnsafe() {
    const m = await requireMaterial();
    const { pk_account: acct } = await local.get('pk_account');
    if (!acct || !acct.syncUrl) return { skipped: true };
    const id = await vaultId(m);
    const token = authToken(m);
    try {
      for (let attempt = 0; attempt < 4; attempt++) {
        const { pk_blob } = await local.get('pk_blob');
        const localVault = await decryptVault(m, pk_blob);
        const remote = await pullVault(acct.syncUrl, id, token, doFetch);
        let merged = localVault;
        let baseVersion = 0;
        if (remote) {
          let remoteVault;
          try {
            remoteVault = await decryptVault(m, remote.blob);
          } catch {
            throw new Error('Remote vault could not be decrypted with this master password.');
          }
          merged = mergeVaults(localVault, remoteVault, now());
          baseVersion = remote.version;
          if (sameContent(merged, remoteVault)) {
            await writeVaultUnsafe(merged, false);
            await local.set({ pk_version: remote.version, pk_lastSync: now(), pk_syncError: null });
            return { pushed: false };
          }
        }
        const blob = await encryptVault(m, merged);
        const res = await pushVault(acct.syncUrl, id, token, baseVersion, blob, acct.inviteCode, doFetch);
        if (res.ok) {
          await local.set({
            pk_blob: blob,
            pk_dirty: false,
            pk_version: res.version,
            pk_lastSync: now(),
            pk_syncError: null
          });
          await updateHints(merged);
          return { pushed: true };
        }
      }
      throw new Error('Sync kept conflicting. Try again in a moment.');
    } catch (e) {
      await local.set({ pk_syncError: String((e && e.message) || e) });
      throw e;
    }
  }

  return {
    status,

    /** mode: 'create' (new vault) or 'signin' (existing vault on the sync server). */
    async setup({ mode, accountName, password, syncUrl, inviteCode }) {
      const name = normalizeAccount(accountName || '');
      if (!name) throw new Error('Enter an account name.');
      if (!password || password.length < MIN_PASSWORD) {
        throw new Error('Use a master password of at least ' + MIN_PASSWORD + ' characters.');
      }
      const url = syncUrl && syncUrl.trim() ? normalizeSyncUrl(syncUrl) : '';
      const invite = (inviteCode || '').trim();
      const m = await deriveMaterial(name, password);
      const id = await vaultId(m);
      const token = authToken(m);
      const remote = url ? await pullVault(url, id, token, doFetch) : null;

      let vault;
      let dirty;
      if (mode === 'create') {
        if (remote) throw new Error('A vault for this account already exists on that server. Use Sign in instead.');
        vault = emptyVault();
        dirty = true;
      } else {
        if (!url) throw new Error('Signing in needs your sync server URL.');
        if (!remote) throw new Error('No vault found for that account name and password on this server.');
        try {
          vault = await decryptVault(m, remote.blob);
        } catch {
          throw new Error('Wrong account name or master password.');
        }
        dirty = false;
      }
      await local.set({
        pk_account: { name, syncUrl: url, inviteCode: invite },
        pk_version: remote ? remote.version : 0,
        pk_lastSync: remote ? now() : null,
        pk_syncError: null
      });
      await session.set({ pk_material: b64uEncode(m) });
      await serial(() => writeVaultUnsafe(vault, dirty));
      if (mode === 'create' && url) await serial(syncUnsafe);
      return status();
    },

    async unlock(password) {
      const l = await local.get(['pk_account', 'pk_blob']);
      if (!l.pk_account || !l.pk_blob) throw new Error('No vault is set up.');
      const m = await deriveMaterial(l.pk_account.name, password || '');
      try {
        await decryptVault(m, l.pk_blob);
      } catch {
        throw new Error('Wrong master password.');
      }
      await session.set({ pk_material: b64uEncode(m) });
    },

    async verifyPassword(password) {
      const l = await local.get(['pk_account', 'pk_blob']);
      if (!l.pk_account || !l.pk_blob) return false;
      const m = await deriveMaterial(l.pk_account.name, password || '');
      try {
        await decryptVault(m, l.pk_blob);
        return true;
      } catch {
        return false;
      }
    },

    async lock() {
      await session.remove('pk_material');
    },

    /** Public listing for the UI: never includes private keys. */
    async listCredentials() {
      const v = await readVaultUnsafe();
      return v.credentials
        .filter((c) => !c.deleted)
        .map((c) => ({
          id: c.id,
          rpId: c.rpId,
          rpName: c.rpName,
          userName: c.userName,
          userDisplayName: c.userDisplayName,
          createdAt: c.createdAt
        }))
        .sort((a, b) => (a.rpId === b.rpId ? b.createdAt - a.createdAt : a.rpId < b.rpId ? -1 : 1));
    },

    /** Full records including private keys. Background use only. */
    async findCredentials(rpId, allowIds) {
      const v = await readVaultUnsafe();
      return v.credentials.filter(
        (c) => !c.deleted && c.rpId === rpId && (!allowIds || allowIds.length === 0 || allowIds.includes(c.id))
      );
    },

    async hasHint(rpId) {
      const { pk_hints } = await local.get('pk_hints');
      return !!pk_hints && pk_hints.includes(await rpHash(rpId));
    },

    addCredential(record) {
      return serial(async () => {
        const v = await readVaultUnsafe();
        v.credentials.push(record);
        await writeVaultUnsafe(v, true);
      });
    },

    deleteCredential(id) {
      return serial(async () => {
        const v = await readVaultUnsafe();
        const c = v.credentials.find((x) => x.id === id);
        if (!c) return;
        v.credentials = v.credentials.map((x) =>
          x.id === id ? { id: x.id, rpId: x.rpId, deleted: true, updatedAt: now() } : x
        );
        await writeVaultUnsafe(v, true);
      });
    },

    sync() {
      return serial(syncUnsafe);
    },

    async exportBackup() {
      const { pk_blob } = await local.get('pk_blob');
      return pk_blob;
    },

    importBackup(blob) {
      return serial(async () => {
        const m = await requireMaterial();
        let incoming;
        try {
          incoming = await decryptVault(m, blob);
        } catch {
          throw new Error('That backup was made with a different account or master password.');
        }
        const merged = mergeVaults(await readVaultUnsafe(), incoming, now());
        await writeVaultUnsafe(merged, true);
        return { count: merged.credentials.filter((c) => !c.deleted).length };
      });
    },

    async setSettings(partial) {
      const { pk_settings } = await local.get('pk_settings');
      const next = Object.assign({}, DEFAULT_SETTINGS, pk_settings);
      if (partial.autoLockMinutes !== undefined) {
        next.autoLockMinutes = Math.max(0, Math.min(1440, Math.floor(Number(partial.autoLockMinutes) || 0)));
      }
      if (partial.interceptCreate !== undefined) next.interceptCreate = !!partial.interceptCreate;
      await local.set({ pk_settings: next });
      return next;
    },

    /** Remove everything from this device. Optionally delete the vault on the server too. */
    async eraseAll({ deleteRemoteCopy } = {}) {
      if (deleteRemoteCopy) {
        const m = await requireMaterial();
        const { pk_account: acct } = await local.get('pk_account');
        if (acct && acct.syncUrl) await deleteRemote(acct.syncUrl, await vaultId(m), authToken(m), doFetch);
      }
      await local.remove([
        'pk_account', 'pk_blob', 'pk_dirty', 'pk_version', 'pk_hints',
        'pk_lastSync', 'pk_syncError', 'pk_settings'
      ]);
      await session.remove('pk_material');
    }
  };
}
