import type { DatabaseSync } from 'node:sqlite';

export const SCHEMA_VERSION = 1;

const MIGRATIONS: string[] = [
  // v1 — initial schema
  `
  CREATE TABLE IF NOT EXISTS meta(
    key   TEXT PRIMARY KEY,
    value BLOB
  );

  CREATE TABLE IF NOT EXISTS secrets(
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    type            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    service         TEXT NOT NULL DEFAULT '',
    env             TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    current_version INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS secret_versions(
    id         INTEGER PRIMARY KEY,
    secret_id  INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version    INTEGER NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE(secret_id, version)
  );

  CREATE TABLE IF NOT EXISTS aliases(
    alias     TEXT PRIMARY KEY,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_aliases_secret ON aliases(secret_id);

  -- Metadata only. Secret VALUES are never indexed.
  CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
    name, aliases, description, service, env, tags,
    tokenize='porter unicode61'
  );

  CREATE TABLE IF NOT EXISTS audit(
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    action      TEXT NOT NULL,
    secret_name TEXT NOT NULL DEFAULT '',
    caller      TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    ok          INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
  CREATE INDEX IF NOT EXISTS idx_audit_secret ON audit(secret_name);
  `,
];

export function migrate(db: DatabaseSync): void {
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA synchronous = NORMAL');

  db.exec(`CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)`);
  const row = db.prepare('SELECT version FROM schema_version LIMIT 1').get() as
    | { version: number }
    | undefined;
  let current = row?.version ?? 0;

  for (let i = current; i < MIGRATIONS.length; i++) {
    db.exec(MIGRATIONS[i]!);
    current = i + 1;
  }

  if (row) db.prepare('UPDATE schema_version SET version = ?').run(current);
  else db.prepare('INSERT INTO schema_version(version) VALUES (?)').run(current);
}
