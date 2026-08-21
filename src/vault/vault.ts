import { DatabaseSync } from 'node:sqlite';
import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';
import { migrate } from './schema.js';
import {
  deriveKey,
  defaultKdfParams,
  seal,
  open,
  wipe,
  timingSafeEqual,
  type KdfParams,
} from './crypto.js';
import {
  normalisePayload,
  SECRET_TYPES,
  type Payload,
  type SecretType,
} from './types.js';

export class VaultError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}
export class LockedError extends VaultError {
  constructor() {
    super('vault is locked', 423);
  }
}
export class ConflictError extends VaultError {
  constructor(message: string) {
    super(message, 409);
  }
}
export class NotFoundError extends VaultError {
  constructor(
    readonly query: string,
    readonly candidates: string[],
  ) {
    super(
      candidates.length
        ? `no secret named '${query}' — did you mean: ${candidates.join(', ')}?`
        : `no secret named '${query}'`,
      404,
    );
  }
}

export interface SecretMeta {
  name: string;
  type: SecretType;
  description: string;
  service: string;
  env: string;
  tags: string[];
  url: string;
  aliases: string[];
  current_version: number;
  created_at: number;
  updated_at: number;
}

export interface SecretRecord extends SecretMeta {
  value: Payload;
  /** Which version `value` came from — `current_version` unless an older one was asked for. */
  version: number;
}

export interface CreateInput {
  name: string;
  type: SecretType;
  value: unknown;
  description?: string;
  service?: string;
  env?: string;
  tags?: string[] | string;
  url?: string;
  aliases?: string[];
  note?: string;
}

export type PatchInput = Partial<
  Pick<CreateInput, 'description' | 'service' | 'env' | 'tags' | 'url' | 'aliases'>
>;

export interface ListFilter {
  type?: string;
  tag?: string;
  service?: string;
  env?: string;
}

export interface SearchHit extends SecretMeta {
  score: number;
}

export interface AuditEntry {
  id: number;
  ts: number;
  action: string;
  secret_name: string;
  caller: string;
  source: string;
  detail: string;
  ok: boolean;
}

export interface AuditContext {
  caller?: string;
  source?: string;
}

interface SecretRow {
  id: number;
  name: string;
  type: string;
  description: string;
  service: string;
  env: string;
  tags: string;
  url: string;
  current_version: number;
  created_at: number;
  updated_at: number;
}

const VERIFIER_PLAINTEXT = 'claude_secrets/v1';
const VERIFIER_AAD = 'meta:verifier';
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/]{0,127}$/;

const now = (): number => Math.floor(Date.now() / 1000);

export class Vault {
  private db: DatabaseSync;
  private key: Uint8Array | null = null;
  private generation = 0;
  /**
   * Retained so the daemon can authenticate API callers against the same password that
   * unlocks the vault — one password for everything. Cleared on lock, which is why a
   * locked vault cannot authenticate anyone and answers 423 rather than 401.
   */
  private password: string | null = null;

  private constructor(db: DatabaseSync) {
    this.db = db;
  }

  static open(path: string): Vault {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    const db = new DatabaseSync(path);
    migrate(db);
    return new Vault(db);
  }

  close(): void {
    this.lock();
    this.db.close();
  }

  // ---------------------------------------------------------------- lifecycle

  get initialised(): boolean {
    return this.getMeta('kdf_salt') !== null;
  }

  get locked(): boolean {
    return this.key === null;
  }

  /**
   * First-run setup. All five meta rows are written in one transaction: `initialised`
   * keys off kdf_salt, so a partial write would leave a vault that refuses to
   * re-initialise but can never unlock. BEGIN IMMEDIATE also serialises two racing
   * initialisers, which would otherwise interleave salts and leave one process
   * encrypting under a key the stored verifier no longer matches.
   */
  init(passphrase: string): void {
    if (!passphrase) throw new VaultError('passphrase must not be empty');
    const params = defaultKdfParams();
    const key = deriveKey(passphrase, params);
    const verifier = seal(VERIFIER_PLAINTEXT, VERIFIER_AAD, key);

    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (this.initialised) throw new ConflictError('vault is already initialised');
      this.setMeta('kdf_salt', params.salt);
      this.setMeta('kdf_ops', Buffer.from(String(params.ops)));
      this.setMeta('kdf_mem', Buffer.from(String(params.mem)));
      this.setMeta('verifier_nonce', verifier.nonce);
      this.setMeta('verifier_ct', verifier.ciphertext);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      wipe(key);
      throw e;
    }
    // Only adopt the key once it is durably the vault's key.
    this.key = key;
    this.password = passphrase;
    this.generation++;
  }

  unlock(passphrase: string): boolean {
    if (!this.initialised) throw new VaultError('vault is not initialised');
    const key = deriveKey(passphrase, this.kdfParams());
    const nonce = this.getMeta('verifier_nonce');
    const ciphertext = this.getMeta('verifier_ct');
    if (!nonce || !ciphertext) throw new VaultError('vault verifier is missing — db corrupt');
    try {
      const plain = open({ nonce, ciphertext }, VERIFIER_AAD, key);
      if (plain !== VERIFIER_PLAINTEXT) throw new Error('mismatch');
    } catch {
      wipe(key);
      return false;
    }
    wipe(this.key);
    this.key = key;
    this.password = passphrase;
    this.generation++;
    return true;
  }

  lock(): void {
    wipe(this.key);
    this.key = null;
    this.password = null;
    this.generation++;
  }

  /**
   * Constant-time check of an API caller's password against the one that unlocked the
   * vault. Returns false while locked — there is nothing to compare against, and a
   * locked vault must not be probeable for password guesses either.
   */
  checkPassword(candidate: string): boolean {
    if (!this.password || !candidate) return false;
    return timingSafeEqual(candidate, this.password);
  }

  /**
   * Bumped on every lock and unlock. A handler that awaits between decrypting and
   * responding captures this first and re-checks it afterwards — otherwise a lock
   * (or a lock/unlock pair) landing mid-await still lets the old plaintext out.
   */
  get lockGeneration(): number {
    return this.generation;
  }

  private requireKey(): Uint8Array {
    if (!this.key) throw new LockedError();
    return this.key;
  }

  private kdfParams(): KdfParams {
    const salt = this.getMeta('kdf_salt');
    if (!salt) throw new VaultError('vault is not initialised');
    return {
      salt,
      ops: Number(Buffer.from(this.getMeta('kdf_ops')!).toString()),
      mem: Number(Buffer.from(this.getMeta('kdf_mem')!).toString()),
    };
  }

  private getMeta(key: string): Uint8Array | null {
    const row = this.db.prepare('SELECT value FROM meta WHERE key = ?').get(key) as
      | { value: Uint8Array }
      | undefined;
    return row ? new Uint8Array(row.value) : null;
  }

  private setMeta(key: string, value: Uint8Array): void {
    this.db
      .prepare('INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?')
      .run(key, value, value);
  }

  // ---------------------------------------------------------------------- CRUD

  create(input: CreateInput): SecretMeta {
    const key = this.requireKey();
    const name = input.name?.trim();
    if (!name || !NAME_RE.test(name)) {
      throw new VaultError(
        `invalid name '${input.name}' — use letters, digits, and . _ - / (e.g. 'github/pat')`,
      );
    }
    if (!SECRET_TYPES.includes(input.type)) {
      throw new VaultError(`unknown type '${input.type}' — one of: ${SECRET_TYPES.join(', ')}`);
    }
    if (this.findRow(name)) throw new ConflictError(`secret '${name}' already exists`);

    const payload = normalisePayload(input.type, input.value);
    const ts = now();
    const tags = normaliseTags(input.tags);

    this.db.exec('BEGIN');
    try {
      const res = this.db
        .prepare(
          `INSERT INTO secrets(name, type, description, service, env, tags, url,
                               current_version, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
        )
        .run(
          name,
          input.type,
          input.description ?? '',
          input.service ?? '',
          input.env ?? '',
          tags,
          input.url ?? '',
          ts,
          ts,
        );
      const id = Number(res.lastInsertRowid);
      this.writeVersion(id, name, 1, payload, input.note ?? 'created', key);
      this.setAliases(id, input.aliases ?? []);
      this.reindex(id);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return this.meta(this.findRow(name)!);
  }

  /**
   * Reads and decrypts. This is the call that hands back plaintext.
   * Pass `version` to inspect an older one without disturbing what is current.
   */
  read(nameOrAlias: string, version?: number): SecretRecord {
    this.requireKey();
    const row = this.mustFind(nameOrAlias);
    const v = version ?? row.current_version;
    return { ...this.meta(row), value: this.decryptVersion(row, v), version: v };
  }

  /**
   * Decrypts one version's payload. The AAD binds name and version, so a ciphertext
   * moved between rows — by a tampered database file — fails to open rather than
   * decrypting as some other secret.
   */
  private decryptVersion(row: SecretRow, version: number): Payload {
    const key = this.requireKey();
    const v = this.db
      .prepare('SELECT nonce, ciphertext FROM secret_versions WHERE secret_id = ? AND version = ?')
      .get(row.id, version) as { nonce: Uint8Array; ciphertext: Uint8Array } | undefined;
    if (!v) throw new NotFoundError(`${row.name}@${version}`, []);
    const json = open(
      { nonce: new Uint8Array(v.nonce), ciphertext: new Uint8Array(v.ciphertext) },
      `${row.name}:${version}`,
      key,
    );
    return parseStored(json, row.name);
  }

  /** Writes a new version. Old versions are retained for rollback. */
  update(nameOrAlias: string, value: unknown, note = ''): number {
    const key = this.requireKey();
    const row = this.mustFind(nameOrAlias);
    const payload = normalisePayload(row.type as SecretType, value);
    const next = row.current_version + 1;

    this.db.exec('BEGIN');
    try {
      this.writeVersion(row.id, row.name, next, payload, note, key);
      this.db
        .prepare('UPDATE secrets SET current_version = ?, updated_at = ? WHERE id = ?')
        .run(next, now(), row.id);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return next;
  }

  /**
   * Compare-and-swap write. Returns null if the secret moved on since `expectedVersion`,
   * meaning the caller's value is stale and must not be written.
   *
   * Needed because callers that await between reading and writing (OAuth refresh awaits
   * the token endpoint) would otherwise clobber a rotation that landed while they waited.
   * There is no await inside this method, so the check and the write are atomic with
   * respect to other request handlers.
   */
  updateIfVersion(nameOrAlias: string, expectedVersion: number, value: unknown, note = ''): number | null {
    this.requireKey();
    const row = this.mustFind(nameOrAlias);
    if (row.current_version !== expectedVersion) return null;
    return this.update(nameOrAlias, value, note);
  }

  /** Metadata-only edit — does not create a version. */
  patch(nameOrAlias: string, input: PatchInput): SecretMeta {
    this.requireKey();
    const row = this.mustFind(nameOrAlias);
    const sets: string[] = [];
    const params: unknown[] = [];
    const put = (col: string, val: unknown): void => {
      sets.push(`${col} = ?`);
      params.push(val);
    };
    if (input.description !== undefined) put('description', input.description);
    if (input.service !== undefined) put('service', input.service);
    if (input.env !== undefined) put('env', input.env);
    if (input.url !== undefined) put('url', input.url);
    if (input.tags !== undefined) put('tags', normaliseTags(input.tags));

    this.db.exec('BEGIN');
    try {
      if (sets.length) {
        put('updated_at', now());
        params.push(row.id);
        this.db.prepare(`UPDATE secrets SET ${sets.join(', ')} WHERE id = ?`).run(...(params as never[]));
      }
      if (input.aliases !== undefined) this.setAliases(row.id, input.aliases);
      this.reindex(row.id);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return this.meta(this.findRow(row.name)!);
  }

  remove(nameOrAlias: string): string {
    this.requireKey();
    const row = this.mustFind(nameOrAlias);
    this.db.exec('BEGIN');
    try {
      this.db.prepare('DELETE FROM secrets WHERE id = ?').run(row.id);
      this.db.prepare('DELETE FROM secrets_fts WHERE rowid = ?').run(row.id);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return row.name;
  }

  // ------------------------------------------------------------------ versions

  versions(nameOrAlias: string): Array<{ version: number; created_at: number; note: string; current: boolean }> {
    this.requireKey();
    const row = this.mustFind(nameOrAlias);
    const rows = this.db
      .prepare(
        'SELECT version, created_at, note FROM secret_versions WHERE secret_id = ? ORDER BY version DESC',
      )
      .all(row.id) as Array<{ version: number; created_at: number; note: string }>;
    return rows.map((r) => ({ ...r, current: r.version === row.current_version }));
  }

  /** Rollback copies an old version forward as a new one — history is never destroyed. */
  rollback(nameOrAlias: string, version: number): number {
    const key = this.requireKey();
    const row = this.mustFind(nameOrAlias);
    const payload = this.decryptVersion(row, version);
    const next = row.current_version + 1;
    this.db.exec('BEGIN');
    try {
      this.writeVersion(row.id, row.name, next, payload, `rollback to v${version}`, key);
      this.db
        .prepare('UPDATE secrets SET current_version = ?, updated_at = ? WHERE id = ?')
        .run(next, now(), row.id);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return next;
  }

  // ------------------------------------------------------------ list & search

  list(filter: ListFilter = {}): SecretMeta[] {
    // Metadata is unencrypted so FTS5 can index it, but a locked vault must still
    // reveal nothing — the inventory itself is sensitive.
    this.requireKey();
    const where: string[] = [];
    const params: unknown[] = [];
    if (filter.type) {
      where.push('type = ?');
      params.push(filter.type);
    }
    if (filter.service) {
      where.push('service = ?');
      params.push(filter.service);
    }
    if (filter.env) {
      where.push('env = ?');
      params.push(filter.env);
    }
    if (filter.tag) {
      where.push("(',' || tags || ',') LIKE ?");
      params.push(`%,${filter.tag},%`);
    }
    const sql = `SELECT * FROM secrets ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY name`;
    const rows = this.db.prepare(sql).all(...(params as never[])) as unknown as SecretRow[];
    return rows.map((r) => this.meta(r));
  }

  /**
   * Natural-language lookup over metadata. Terms are OR-ed with prefix matching and
   * ranked by bm25 with name/alias columns weighted highest, so "the stripe test key"
   * ranks stripe/test/sk above a stripe webhook secret without needing exact wording.
   */
  search(query: string, limit = 10): SearchHit[] {
    this.requireKey();
    const match = toFtsQuery(query);
    if (!match) return [];
    let rows: Array<SecretRow & { score: number }>;
    try {
      rows = this.db
        .prepare(
          `SELECT s.*, bm25(secrets_fts, 10.0, 8.0, 3.0, 5.0, 2.0, 4.0) AS score
             FROM secrets_fts f JOIN secrets s ON s.id = f.rowid
            WHERE secrets_fts MATCH ?
            ORDER BY score
            LIMIT ?`,
        )
        .all(match, limit) as unknown as Array<SecretRow & { score: number }>;
    } catch {
      return [];
    }
    return rows.map((r) => ({ ...this.meta(r), score: Math.round(-r.score * 1000) / 1000 }));
  }

  /** Closest names by edit distance — powers the "did you mean" on a 404. */
  candidates(query: string, n = 3): string[] {
    const q = query.toLowerCase();
    const names = this.db.prepare('SELECT name FROM secrets').all() as Array<{ name: string }>;
    const alias = this.db.prepare('SELECT alias, secret_id FROM aliases').all() as Array<{
      alias: string;
      secret_id: number;
    }>;
    const byId = new Map(
      (this.db.prepare('SELECT id, name FROM secrets').all() as Array<{ id: number; name: string }>).map(
        (r) => [r.id, r.name],
      ),
    );
    const pool: Array<{ label: string; name: string }> = [
      ...names.map((r) => ({ label: r.name, name: r.name })),
      ...alias.map((r) => ({ label: r.alias, name: byId.get(r.secret_id) ?? r.alias })),
    ];
    return pool
      .map((p) => ({ name: p.name, d: distance(q, p.label.toLowerCase()) }))
      .filter((p) => p.d <= Math.max(3, Math.floor(q.length / 2)))
      .sort((a, b) => a.d - b.d)
      .map((p) => p.name)
      .filter((v, i, arr) => arr.indexOf(v) === i)
      .slice(0, n);
  }

  // --------------------------------------------------------------------- audit

  recordAudit(
    action: string,
    ok: boolean,
    opts: AuditContext & { secret?: string; detail?: string } = {},
  ): void {
    this.db
      .prepare(
        'INSERT INTO audit(ts, action, secret_name, caller, source, detail, ok) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        now(),
        action,
        opts.secret ?? '',
        opts.caller ?? '',
        opts.source ?? '',
        opts.detail ?? '',
        ok ? 1 : 0,
      );
  }

  auditLog(opts: { since?: number; secret?: string; action?: string; limit?: number } = {}): AuditEntry[] {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.since) {
      where.push('ts >= ?');
      params.push(opts.since);
    }
    if (opts.secret) {
      where.push('secret_name = ?');
      params.push(opts.secret);
    }
    if (opts.action) {
      where.push('action = ?');
      params.push(opts.action);
    }
    params.push(opts.limit ?? 100);
    const rows = this.db
      .prepare(
        `SELECT * FROM audit ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY ts DESC, id DESC LIMIT ?`,
      )
      .all(...(params as never[])) as unknown as Array<Omit<AuditEntry, 'ok'> & { ok: number }>;
    return rows.map((r) => ({ ...r, ok: r.ok === 1 }));
  }

  count(): number {
    const r = this.db.prepare('SELECT COUNT(*) AS n FROM secrets').get() as { n: number };
    return r.n;
  }

  /** Online backup — safe against concurrent writers, unlike copying the file. */
  backupTo(path: string): void {
    mkdirSync(dirname(path), { recursive: true });
    this.db.exec(`VACUUM INTO '${path.replace(/'/g, "''")}'`);
  }

  // ------------------------------------------------------------------ internal

  private writeVersion(
    secretId: number,
    name: string,
    version: number,
    payload: Payload,
    note: string,
    key: Uint8Array,
  ): void {
    const sealed = seal(JSON.stringify(payload), `${name}:${version}`, key);
    this.db
      .prepare(
        'INSERT INTO secret_versions(secret_id, version, nonce, ciphertext, note, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      )
      .run(secretId, version, sealed.nonce, sealed.ciphertext, note, now());
  }

  private findRow(nameOrAlias: string): SecretRow | null {
    const direct = this.db.prepare('SELECT * FROM secrets WHERE name = ?').get(nameOrAlias) as
      | SecretRow
      | undefined;
    if (direct) return direct;
    const viaAlias = this.db
      .prepare('SELECT s.* FROM secrets s JOIN aliases a ON a.secret_id = s.id WHERE a.alias = ?')
      .get(nameOrAlias) as SecretRow | undefined;
    return viaAlias ?? null;
  }

  private mustFind(nameOrAlias: string): SecretRow {
    const row = this.findRow(nameOrAlias);
    if (!row) throw new NotFoundError(nameOrAlias, this.candidates(nameOrAlias));
    return row;
  }

  private aliasesFor(id: number): string[] {
    return (
      this.db.prepare('SELECT alias FROM aliases WHERE secret_id = ? ORDER BY alias').all(id) as Array<{
        alias: string;
      }>
    ).map((r) => r.alias);
  }

  private setAliases(id: number, aliases: string[]): void {
    this.db.prepare('DELETE FROM aliases WHERE secret_id = ?').run(id);
    const stmt = this.db.prepare('INSERT INTO aliases(alias, secret_id) VALUES (?, ?)');
    for (const raw of aliases) {
      const alias = raw.trim();
      if (!alias) continue;
      const owner = this.findRow(alias);
      if (owner && owner.id !== id) {
        throw new ConflictError(`alias '${alias}' already points at '${owner.name}'`);
      }
      stmt.run(alias, id);
    }
  }

  private reindex(id: number): void {
    const row = this.db.prepare('SELECT * FROM secrets WHERE id = ?').get(id) as SecretRow | undefined;
    this.db.prepare('DELETE FROM secrets_fts WHERE rowid = ?').run(id);
    if (!row) return;
    this.db
      .prepare(
        'INSERT INTO secrets_fts(rowid, name, aliases, description, service, env, tags) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        id,
        row.name.replace(/[/_.-]/g, ' '),
        this.aliasesFor(id).join(' '),
        row.description,
        row.service,
        row.env,
        row.tags.replace(/,/g, ' '),
      );
  }

  private meta(row: SecretRow): SecretMeta {
    return {
      name: row.name,
      type: row.type as SecretType,
      description: row.description,
      service: row.service,
      env: row.env,
      tags: row.tags ? row.tags.split(',').filter(Boolean) : [],
      url: row.url,
      aliases: this.aliasesFor(row.id),
      current_version: row.current_version,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }
}

/**
 * Parses a decrypted payload. Node's own JSON.parse error text embeds a fragment of the
 * offending string — which here is decrypted plaintext, and would then flow into the log
 * and the audit table. Never let the original error escape.
 */
function parseStored(json: string, name: string): Payload {
  try {
    return JSON.parse(json) as Payload;
  } catch {
    throw new VaultError(`stored payload for '${name}' is corrupt (not valid JSON)`, 500);
  }
}

function normaliseTags(tags: string[] | string | undefined): string {
  if (!tags) return '';
  const arr = Array.isArray(tags) ? tags : tags.split(',');
  return arr
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean)
    .filter((v, i, a) => a.indexOf(v) === i)
    .join(',');
}

/** Strip FTS5 operators, then OR the terms with prefix matching. */
export function toFtsQuery(query: string): string {
  const terms = query
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 1 && !STOPWORDS.has(t));
  if (!terms.length) return '';
  return terms.map((t) => `"${t}"*`).join(' OR ');
}

const STOPWORDS = new Set([
  'the', 'my', 'our', 'for', 'and', 'with', 'that', 'this', 'get', 'give',
  'find', 'what', 'which', 'from', 'use', 'used', 'using', 'need', 'want',
  'secret', 'secrets', 'key', 'credential', 'credentials', 'please',
]);

/** Levenshtein, capped rows for speed. Small vaults, so the naive version is fine. */
function distance(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1]! + 1, prev[j]! + 1, prev[j - 1]! + cost);
    }
    prev = cur;
  }
  return prev[b.length]!;
}
