# claude_secrets — SPEC

A single-user secrets service on the Mac mini. Encrypted SQLite vault, HTTP daemon,
MCP server for Claude Code, CLI for humans. Trusted LAN, one operator, no multi-tenancy.

## Decisions (locked)

| Question | Decision |
|---|---|
| Stack | TypeScript, Node 22 (`node:sqlite` built in, official MCP SDK) |
| Storage | Single encrypted SQLite file, XChaCha20-Poly1305 via libsodium |
| Unlock | Argon2id from passphrase; passphrase escrowed in login Keychain, auto-unlock at login |
| Network | `0.0.0.0:7777`, plain HTTP, authenticated with the vault password |
| Claude reads | `get_secret` returns plaintext |
| Search | SQLite FTS5 over metadata + aliases (never over values) |
| Lifecycle | Versioned writes + rollback. No expiry scheduler. |
| Backup | Nightly encrypted snapshot, 30-day retention |
| Extras | Append-only audit log + live feed; optional `run_with_secrets` |

## Components

```
~/.secretd/
  vault.db          encrypted SQLite
  password          only if the Keychain is unavailable (0600)
  backups/          nightly snapshots

secretd             daemon — owns the vault, HTTP API on :7777, launchd at login
secrets             CLI — thin HTTP client
secrets-mcp         MCP stdio shim — thin HTTP client, registered with Claude Code
skills/secret-vault Claude skill — teaches search → disambiguate → get
```

Everything goes through the daemon. The CLI and MCP shim hold no keys and touch no files —
they are HTTP clients. One unlock, one audit log, one source of truth.

## Crypto

- Passphrase → `crypto_pwhash` (Argon2id, moderate limits) → 32-byte master key. Salt in `meta`.
- Each secret version encrypted with `crypto_aead_xchacha20poly1305_ietf_encrypt`.
  Random 24-byte nonce per record. AAD = `${name}:${version}` so a ciphertext can't be
  moved between secrets or replayed as an older version.
- Master key lives in daemon RAM only, never on disk, never in a log.
- Keychain: `security add-generic-password -s secretd -a master -w <passphrase>`.
  Daemon reads it at startup with `security find-generic-password -w -s secretd -a master`.
  If the read fails, the daemon starts **locked** and every request returns 423 until
  `secrets unlock` is run.

## Schema

```sql
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
-- kdf_salt, kdf_ops, kdf_mem, schema_version

CREATE TABLE secrets(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,        -- 'github/pat', 'stripe/test/sk'
  type TEXT NOT NULL,               -- api_key|oauth|key_file|connection_string|env_bundle
                                    -- |note|login|card|bank_account|identity
  description TEXT,
  service TEXT,                     -- 'github', 'stripe'
  env TEXT,                         -- 'prod', 'dev', null
  tags TEXT,                        -- comma-separated
  url TEXT,
  current_version INTEGER NOT NULL,
  created_at INTEGER, updated_at INTEGER
);

CREATE TABLE secret_versions(
  id INTEGER PRIMARY KEY,
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  note TEXT,
  created_at INTEGER,
  UNIQUE(secret_id, version)
);

CREATE TABLE aliases(
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  alias TEXT NOT NULL UNIQUE
);

CREATE VIRTUAL TABLE secrets_fts USING fts5(
  name, aliases, description, service, env, tags,
  content='', tokenize='porter unicode61'
);
-- rebuilt on write from secrets + aliases. VALUES ARE NEVER INDEXED.

CREATE TABLE audit(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  action TEXT NOT NULL,             -- read|create|update|delete|rollback|search|exec|unlock|backup
  secret_name TEXT,
  caller TEXT,                      -- 'mcp', 'cli', 'http'
  source TEXT,                      -- source IP
  detail TEXT,
  ok INTEGER NOT NULL
);
```

Plaintext values exist in exactly one place: `secret_versions.ciphertext`, decrypted in RAM
on demand. Metadata is deliberately unencrypted so FTS5 works — the tradeoff is that anyone
with the DB file learns *what* you have, not *what they are*.

## Secret types

The encrypted blob is JSON. The `type` field determines its shape.

| type | payload |
|---|---|
| `api_key` | `{ value }` |
| `oauth` | `{ client_id, client_secret, access_token, refresh_token, expires_at, token_url, scopes }` |
| `key_file` | `{ pem, passphrase?, fingerprint? }` |
| `connection_string` | `{ url, host?, port?, user?, password?, database? }` |
| `env_bundle` | `{ KEY: value, ... }` |
| `note` | `{ text }` — catch-all for anything that doesn't fit |
| `login` | `{ username, password?, totp?, url?, notes? }` — needs a password or a totp |
| `card` | `{ number, expiry, cvv?, cardholder?, brand?, pin?, postcode?, notes? }` |
| `bank_account` | `{ holder?, bank?, iban?, account_number?, routing_number?, bic?, notes? }` |
| `identity` | `{ full_name?, dob?, email?, phone?, address?, national_id?, passport?, license? }` |

`oauth` is the only type with behavior: on read, if `expires_at` is within 60s, the daemon
POSTs the refresh grant to `token_url`, writes a new version, and returns the fresh token.
Refresh failures return the stale token plus a `stale: true` flag rather than erroring —
a broken refresh shouldn't be a hard outage.

`login` is the second type with behavior: a `totp` field holds either a bare base32 seed or
the whole `otpauth://` URI an authenticator shows behind its QR code — the URI already
carries digits/period/algorithm, so no parallel fields exist to drift out of sync with it.
`GET /api/totp` returns a generated RFC 6238 code and its remaining life, never the seed:
a code is worth 30 seconds, a seed is worth forever.

`login`, `card`, `bank_account` and `identity` have several fields and no scalar form, so
their only text form is JSON. `secrets set` sends a string whatever you type, so
`normalisePayload` parses it — the same reason an `env_bundle` accepts a JSON object.

`key_file` reads return the PEM as a string over the API; `run_with_secrets` instead writes
it to a `0600` temp file and passes the path, deleting it when the child exits.

## HTTP API

`Authorization: Bearer <vault password>` on everything except `/api/health` and
`/api/unlock`. Constant-time compare against the password held in memory since unlock.

There is exactly one secret in the system: the vault password. It derives the encryption
key, unlocks the daemon, and authenticates every client. A locked vault answers 423 to
everything rather than 401 — it holds no password to compare against, and must not become
an oracle for guessing one.

Secret names contain `/`, so the name travels in a query parameter rather than the path —
otherwise `/secrets/github/pat/versions` is ambiguous with a secret actually named
`github/pat/versions`.

```
GET    /api/health                  → { ok, locked, initialised, secrets }   (no auth)
POST   /api/unlock                  { passphrase }
POST   /api/lock

GET    /api/secrets                 ?type=&tag=&service=&env=   → metadata only, no values
GET    /api/search                  ?q=stripe+test&limit=10     → ranked metadata + score
GET    /api/secret?name=X           → full record INCLUDING decrypted value; &mask=1 to redact
POST   /api/secret                  { name, type, value, ...metadata }
PUT    /api/secret?name=X           { value, note? }            → new version
PATCH  /api/secret?name=X           { description?, tags?, aliases?, ... }  metadata only
DELETE /api/secret?name=X

GET    /api/versions?name=X         → [{ version, created_at, note, current }]   no values
POST   /api/rollback                { name, version }           → new version copying old

POST   /api/exec                    { command, args, secrets: [{name, as, mode}] }
POST   /api/backup                  → snapshot now
GET    /api/logs?follow=1           → SSE activity stream
GET    /api/audit                   ?since=&secret=&action=&limit=

GET    /                            → web CRUD UI
```

`name=` accepts a name **or** an alias. A miss returns 404 with the top 3 edit-distance
candidates in the body, so the CLI, the UI and the model self-correct instead of guessing.

**Locked means locked.** `list`, `search` and `versions` require the key even though they
only touch unencrypted metadata — otherwise a locked vault still hands an unauthenticated
caller your complete inventory.

## MCP tools

Registered as a stdio server. Every tool is a one-line HTTP call to the daemon.

| tool | returns |
|---|---|
| `search_secrets(query, limit?)` | ranked metadata — **no values** |
| `list_secrets(type?, tag?, service?, env?)` | metadata — **no values** |
| `get_secret(name)` | the plaintext value |
| `create_secret(name, type, value, description?, tags?, aliases?, ...)` | confirmation |
| `update_secret(name, value, note?)` | new version number |
| `delete_secret(name)` | confirmation |
| `update_secret_metadata(name, ...)` | metadata edit, no new version |
| `list_versions(name)` / `rollback_secret(name, version)` | version history / confirmation |
| `run_with_secrets(command, args, secrets)` | child stdout/stderr — **no values in context** |
| `vault_status()` | reachable / initialised / unlocked / count |

`run_with_secrets` maps secrets into the child by mode: `env` (default), `file` (0600 temp
path, injected as an arg), or `stdin`. The parent process never logs the materialized values
and the temp files are unlinked on exit.

## The `secret-vault` skill

Ships in `skills/secret-vault/SKILL.md`. Its job is to make natural-language retrieval work
reliably against a deterministic search index:

1. **Never guess a secret name.** Always `search_secrets` first.
2. **Disambiguate before reading.** More than one plausible hit → ask, don't pick. Reading the
   wrong credential against prod is worse than one extra question.
3. **Prefer `run_with_secrets`** when the secret is only needed to run a command. Read plaintext
   only when the value itself has to be reasoned about or shown.
4. **Never write a retrieved value** into a file, commit, comment, or issue.
5. **On create**, always populate `description`, `service`, `tags`, and at least one natural
   alias — search quality later is entirely a function of metadata quality now.

## Logging (P0 — non-negotiable)

Every operation, regardless of duration, emits a human-readable line to the activity feed —
not just to structured logs.

- Short ops log start + outcome: `read github/pat → ok (mcp, 127.0.0.1)`.
- Long ops (backup, import, FTS rebuild, bulk export) stream incremental progress:
  `backup: 412/1200 rows`. Progress advances 0→N, never only at the end.
- `secrets logs -f` tails the live SSE feed. `secrets audit` queries history.
- Values are **never** logged. Log lines carry names, callers, and outcomes only.
- Nothing runs silently. A silent operation is treated as a bug.

## Backup

launchd nightly: `sqlite3 vault.db ".backup ~/.secretd/backups/vault-YYYYMMDD.db"` —
a real online backup, not a file copy, so an in-flight write can't tear it. 30-day retention,
oldest pruned first. Progress and outcome hit the activity feed like everything else.

Backups are encrypted with the same master key. **The passphrase is the only key material.**
Lose it and the backups are as unreadable as the original.

## Build order

1. **Vault core** — schema, Argon2id KDF, encrypt/decrypt, versioning, unit tests on round-trip
   and AAD rejection. No network.
2. **Daemon + HTTP API** — CRUD, password auth, audit table, SSE feed, launchd plist, `/health`.
3. **CLI** — `secrets get|set|ls|search|rm|versions|rollback|logs|audit|unlock|lock|exec`.
4. **MCP server** — the eight tools, registered with Claude Code, verified end to end.
5. **FTS5 search + aliases** — index build/rebuild, ranking, 404-with-candidates behavior.
6. **Skill** — `secret-vault`, plus a seeding pass that imports existing `.env` files and
   loose keys with good metadata.
7. **Backup job + typed handlers** — nightly snapshot, then `oauth` refresh and `key_file`
   file-mode materialization.

Steps 1–4 are the usable product. 5–7 are what make it pleasant.

## Accepted risks

Recorded, not argued. All are deliberate calls for a trusted single-user LAN.

1. **Plaintext over MCP.** Any value Claude reads enters the transcript, goes to the API, and
   persists in `~/.claude/projects/*.jsonl` on disk unencrypted. The vault's practical boundary
   is the audit log, not the crypto. `run_with_secrets` exists for when you'd rather it didn't.
2. **Plain HTTP on 0.0.0.0, authenticated with the vault password.** One password for
   everything was an explicit requirement. The consequence is that the credential on the
   wire is now the key material itself: a LAN sniffer who captures it does not merely gain
   live API access, they can decrypt `vault.db` and every backup offline, forever. With a
   separate token the loss was bounded to the daemon's uptime. Accepted for a trusted LAN.
3. **No offline recovery key.** Forgetting the passphrase destroys the vault and every backup
   with it. Write it down somewhere physical. An `age`-wrapped recovery key is a ~30-line
   addition if you change your mind.
4. **Metadata unencrypted at rest.** Required for FTS5. The DB file reveals your inventory.
5. **The `current_version` pointer is not authenticated.** Each ciphertext is bound to
   `name:version` via AEAD associated data, so blobs cannot be swapped between secrets or
   versions. But someone who can *write* to `vault.db` could point `secrets.current_version`
   at an older row; the AAD for that row still validates, so a revoked credential would be
   served as current. Closing this needs a keyed head tag over (id, type, version,
   ciphertext hash) — a schema change defending only against an attacker who already has
   write access to the vault file but cannot decrypt it. Deliberately deferred as
   disproportionate for a single-operator host.

### Review

Codex reviewed the implementation (1 high, 8 medium, 2 low; no critical). Everything except
item 5 above was fixed: the OAuth refresh race (compare-and-swap on version), plaintext
served after a concurrent lock (lock-generation check across the await), non-transactional
first-run init, raw exception text reaching the audit table, raw search queries reaching the
audit table, credential-carrying OAuth redirects, `as`-driven path traversal in file-mode
injection, orphaned descendants after an exec timeout, unmasked `token_url`, and a leaked
SSE reader. It found no SQL injection, nonce reuse, auth bypass, or exploitable static-file
traversal.
