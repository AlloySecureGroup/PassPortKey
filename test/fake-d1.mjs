// Minimal in-memory stand-in for the four D1 statements the Worker uses.
export function fakeD1() {
  const rows = new Map();
  return {
    rows,
    prepare(sql) {
      let args = [];
      const stmt = {
        bind(...a) { args = a; return stmt; },
        async first() {
          const r = rows.get(args[0]);
          return r ? { token_hash: r.token_hash, version: r.version, blob: r.blob } : null;
        },
        async run() {
          if (sql.startsWith('INSERT')) {
            const [id, token_hash, blob, updated_at] = args;
            if (rows.has(id)) return { meta: { changes: 0 } };
            rows.set(id, { token_hash, version: 1, blob, updated_at });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('UPDATE')) {
            const [blob, updated_at, id, token_hash, version] = args;
            const r = rows.get(id);
            if (!r || r.token_hash !== token_hash || r.version !== version) return { meta: { changes: 0 } };
            Object.assign(r, { blob, updated_at, version: r.version + 1 });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('DELETE')) {
            const [id, token_hash] = args;
            const r = rows.get(id);
            if (r && r.token_hash === token_hash) { rows.delete(id); return { meta: { changes: 1 } }; }
            return { meta: { changes: 0 } };
          }
          throw new Error('unexpected sql: ' + sql);
        }
      };
      return stmt;
    }
  };
}

