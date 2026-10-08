// Thin client for the PassportKey sync Worker. The server only ever sees ciphertext.

async function errorMessage(res) {
  try {
    const j = await res.json();
    if (j && j.error) return j.error;
  } catch {
    // ignore
  }
  return 'Server returned ' + res.status;
}

export function normalizeSyncUrl(input) {
  const u = new URL(input.trim());
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) {
    throw new Error('The sync URL must use https.');
  }
  return u.origin + u.pathname.replace(/\/+$/, '');
}

export async function pullVault(base, id, token, fetchImpl) {
  const res = await fetchImpl(base + '/v1/vault/' + id, {
    headers: { Authorization: 'Bearer ' + token }
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('Sync failed: ' + (await errorMessage(res)));
  return res.json(); // { version, blob }
}

export async function pushVault(base, id, token, baseVersion, blob, inviteCode, fetchImpl) {
  const headers = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token };
  if (inviteCode) headers['X-Invite-Code'] = inviteCode;
  const res = await fetchImpl(base + '/v1/vault/' + id, {
    method: 'PUT',
    headers,
    body: JSON.stringify({ baseVersion, blob })
  });
  if (res.status === 409) return { ok: false, conflict: true };
  if (!res.ok) throw new Error('Sync failed: ' + (await errorMessage(res)));
  const j = await res.json();
  return { ok: true, version: j.version };
}

export async function deleteRemote(base, id, token, fetchImpl) {
  const res = await fetchImpl(base + '/v1/vault/' + id, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer ' + token }
  });
  if (!res.ok && res.status !== 404) throw new Error('Delete failed: ' + (await errorMessage(res)));
}
