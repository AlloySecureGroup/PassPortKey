CREATE TABLE IF NOT EXISTS vaults (
  id         TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  version    INTEGER NOT NULL,
  blob       TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
