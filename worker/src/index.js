// PassportKey sync Worker.
//
// Stores one opaque, client-side-encrypted blob per vault in Cloudflare D1.
// The server never sees a password, an encryption key or a private key.
//
//   GET    /v1/vault/:id   -> { version, blob }
//   PUT    /v1/vault/:id   body { baseVersion, blob } -> { version }  (409 on version mismatch)
//   DELETE /v1/vault/:id
//
// :id is a 64-char hex vault id derived on the client. Every request carries
// `Authorization: Bearer <64-hex token>`. The server stores only SHA-256(token).
// Optional env var INVITE_CODE: if set, creating a new vault requires header X-Invite-Code.

const MAX_BODY_BYTES = 1000000;
const HEX64 = /^[0-9a-f]{64}$/;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Invite-Code',
  'Access-Control-Max-Age': '86400'
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, CORS)
  });
}

async function sha256Hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function bearer(request) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get('Authorization') || '');
  return m ? m[1] : null;
}

function validBlob(b) {
  return (
    b &&
    typeof b === 'object' &&
    b.v === 1 &&
    Number.isInteger(b.iter) &&
    typeof b.iv === 'string' &&
    typeof b.ct === 'string'
  );
}

function constantTimeInvite(request, env) {
  if (!env.INVITE_CODE) return true;
  return safeEqual(request.headers.get('X-Invite-Code') || '', String(env.INVITE_CODE));
}

export async function handle(request, env) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (url.pathname === '/' || url.pathname === '/health') {
    return json({ ok: true, service: 'passportkey-sync' });
  }

  const m = /^\/v1\/vault\/([0-9a-f]{64})$/.exec(url.pathname);
  if (!m) return json({ error: 'Not found' }, 404);
  const id = m[1];

  const token = bearer(request);
  if (!token) return json({ error: 'Missing or malformed Authorization header' }, 401);
  const tokenHash = await sha256Hex(token);

  const row = await env.DB.prepare('SELECT token_hash, version, blob FROM vaults WHERE id = ?').bind(id).first();

  if (request.method === 'GET') {
    if (!row) return json({ error: 'No such vault' }, 404);
    if (!safeEqual(row.token_hash, tokenHash)) return json({ error: 'Unauthorized' }, 401);
    return json({ version: row.version, blob: JSON.parse(row.blob) });
  }

  if (request.method === 'DELETE') {
    if (!row) return json({ ok: true });
    if (!safeEqual(row.token_hash, tokenHash)) return json({ error: 'Unauthorized' }, 401);
    await env.DB.prepare('DELETE FROM vaults WHERE id = ? AND token_hash = ?').bind(id, tokenHash).run();
    return json({ ok: true });
  }

  if (request.method === 'PUT') {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) return json({ error: 'Vault is too large' }, 413);
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return json({ error: 'Invalid JSON' }, 400);
    }
    if (!Number.isInteger(body.baseVersion) || body.baseVersion < 0 || !validBlob(body.blob)) {
      return json({ error: 'Invalid request body' }, 400);
    }
    const blobText = JSON.stringify(body.blob);
    const now = Date.now();

    if (row && !safeEqual(row.token_hash, tokenHash)) return json({ error: 'Unauthorized' }, 401);

    if (!row) {
      if (body.baseVersion !== 0) return json({ error: 'Version conflict' }, 409);
      if (!constantTimeInvite(request, env)) return json({ error: 'A valid invite code is required' }, 403);
      const res = await env.DB.prepare(
        'INSERT INTO vaults (id, token_hash, version, blob, updated_at) VALUES (?, ?, 1, ?, ?) ON CONFLICT(id) DO NOTHING'
      )
        .bind(id, tokenHash, blobText, now)
        .run();
      if (res.meta && res.meta.changes === 1) return json({ version: 1 });
      return json({ error: 'Version conflict' }, 409);
    }

    // Compare-and-swap on the version so two devices cannot silently overwrite each other.
    const res = await env.DB.prepare(
      'UPDATE vaults SET version = version + 1, blob = ?, updated_at = ? WHERE id = ? AND token_hash = ? AND version = ?'
    )
      .bind(blobText, now, id, tokenHash, body.baseVersion)
      .run();
    if (res.meta && res.meta.changes === 1) return json({ version: body.baseVersion + 1 });
    return json({ error: 'Version conflict' }, 409);
  }

  return json({ error: 'Method not allowed' }, 405);
}

export default { fetch: handle };
