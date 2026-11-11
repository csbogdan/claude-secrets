import type { SecretMeta, SearchHit, AuditEntry } from '../vault/vault.js';
import type { Payload, SecretType } from '../vault/types.js';
import { resolvePassword } from './credentials.js';
import { runWithSecrets, type SecretMapping } from './exec.js';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

/** How long a health probe may take before a daemon counts as unreachable. */
const PROBE_MS = 1500;
/** How long a healthy daemon is reused before it is probed again. */
const STICKY_MS = 15_000;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly candidates: string[] = [],
  ) {
    super(message);
  }
}

export interface SecretResponse extends SecretMeta {
  value: Payload;
  /** Which version `value` came from. */
  version: number;
  primary: string | null;
  stale: boolean;
  refreshed: boolean;
}

export interface VersionInfo {
  version: number;
  created_at: number;
  note: string;
  current: boolean;
}

export interface ExecResponse {
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

export interface CreateBody {
  name: string;
  type: SecretType;
  value: unknown;
  description?: string;
  service?: string;
  env?: string;
  url?: string;
  tags?: string[] | string;
  aliases?: string[];
  note?: string;
}

/**
 * SECRETD_URL may list several daemons, primary first, comma-separated:
 *   SECRETD_URL=http://macmini:7777,http://127.0.0.1:7777
 * Each call goes to the first one that is up and unlocked. A laptop therefore falls back
 * to its local replica when the primary is unreachable, and returns to the primary as
 * soon as it answers again.
 */
export function defaultBaseUrl(): string {
  return process.env['SECRETD_URL'] ?? `http://127.0.0.1:${process.env['SECRETD_PORT'] ?? 7777}`;
}

/** The vault password doubles as the API credential — there is no separate token. */
export function defaultPassword(): string {
  return resolvePassword() ?? '';
}

export class SecretdClient {
  private readonly bases: string[];
  private picked: { base: string; at: number } | null = null;
  /** The daemon that answered the most recent request. */
  lastBase = '';

  constructor(
    baseUrl: string = defaultBaseUrl(),
    private password: string = defaultPassword(),
    private readonly caller: string = 'cli',
  ) {
    const list = baseUrl.split(',').map((b) => b.trim()).filter(Boolean);
    this.bases = list.length ? list : ['http://127.0.0.1:7777'];
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'x-secretd-caller': this.caller };
    if (this.password) h['authorization'] = `Bearer ${this.password}`;
    return h;
  }

  /** The daemons to try for the next call, the preferred one first. */
  private async order(): Promise<string[]> {
    if (this.bases.length === 1) return this.bases;
    const first = (b: string): string[] => [b, ...this.bases.filter((x) => x !== b)];
    if (this.picked && Date.now() - this.picked.at < STICKY_MS) return first(this.picked.base);
    for (const b of this.bases) {
      const h = await probe(b);
      if (h && !h.locked) {
        this.picked = { base: b, at: Date.now() };
        return first(b);
      }
    }
    return this.bases; // nothing healthy: try them in order and report what fails
  }

  /** Used by `secrets login` / `secrets unlock` once the user has typed a password. */
  usePassword(password: string): void {
    this.password = password;
  }

  private async req<T>(
    method: string,
    path: string,
    opts: { query?: Record<string, string | number | undefined>; body?: unknown } = {},
  ): Promise<T> {
    const query = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== '') query.set(k, String(v));
    }
    const headers = this.headers();
    if (opts.body !== undefined) headers['content-type'] = 'application/json';

    const order = await this.order();
    let res: Response | null = null;
    let lastError = '';
    for (const [i, base] of order.entries()) {
      const url = new URL(path, base);
      url.search = query.toString();
      try {
        res = await fetch(url, {
          method,
          headers,
          body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        });
      } catch (err) {
        this.picked = null;
        lastError = err instanceof Error ? err.message : String(err);
        continue;
      }
      // A locked primary cannot serve anything, so a replica that can is the better answer.
      if (res.status === 423 && i < order.length - 1) {
        this.picked = null;
        continue;
      }
      this.lastBase = base;
      break;
    }
    if (!res) {
      throw new ApiError(
        `cannot reach secretd at ${order.join(' or ')} (${lastError}) — is the daemon running? try \`secrets serve\``,
        0,
      );
    }

    const text = await res.text();
    const parsed: unknown = text ? safeJson(text) : {};
    if (!res.ok) {
      const b = parsed as { error?: string; candidates?: string[] };
      throw new ApiError(b.error ?? `${res.status} ${res.statusText}`, res.status, b.candidates ?? []);
    }
    return parsed as T;
  }

  health = () =>
    this.req<{
      ok: boolean;
      locked: boolean;
      initialised: boolean;
      secrets: number | null;
      /** Present on a replica: this answer came from a copy of the primary. */
      replica?: boolean;
      /** On a replica: writes made here that the primary has not received yet. */
      pending?: number;
    }>(
      'GET',
      '/api/health',
    );

  unlock = (passphrase: string) =>
    this.req<{ ok: boolean; locked: boolean }>('POST', '/api/unlock', { body: { passphrase } });

  lock = () => this.req<{ ok: boolean }>('POST', '/api/lock');

  list = (filter: { type?: string; tag?: string; service?: string; env?: string } = {}) =>
    this.req<{ items: SecretMeta[] }>('GET', '/api/secrets', { query: filter }).then((r) => r.items);

  search = (q: string, limit = 10) =>
    this.req<{ items: SearchHit[] }>('GET', '/api/search', { query: { q, limit } }).then((r) => r.items);

  /** `version` reads an older version without restoring it; omit it for the current one. */
  get = (name: string, mask = false, version?: number) =>
    this.req<SecretResponse>('GET', '/api/secret', {
      query: { name, mask: mask ? '1' : undefined, version },
    });

  /** Returns a generated code and its remaining life — never the seed itself. */
  totp = (name: string, version?: number) =>
    this.req<{ name: string; code: string; expires_in: number }>('GET', '/api/totp', {
      query: { name, version },
    });

  create = (body: CreateBody) => this.req<SecretMeta>('POST', '/api/secret', { body });

  update = (name: string, value: unknown, note?: string) =>
    this.req<{ name: string; version: number }>('PUT', '/api/secret', {
      query: { name },
      body: { value, note },
    });

  patch = (name: string, body: Record<string, unknown>) =>
    this.req<SecretMeta>('PATCH', '/api/secret', { query: { name }, body });

  remove = (name: string) =>
    this.req<{ ok: boolean; name: string }>('DELETE', '/api/secret', { query: { name } });

  versions = (name: string) =>
    this.req<{ name: string; items: VersionInfo[] }>('GET', '/api/versions', { query: { name } }).then(
      (r) => r.items,
    );

  rollback = (name: string, version: number) =>
    this.req<{ name: string; version: number; restored_from: number }>('POST', '/api/rollback', {
      body: { name, version },
    });

  /** Runs the command HERE, in this process's machine and cwd. Only the values come from the daemon. */
  exec = (
    command: string,
    args: string[],
    secrets: Array<{ name: string; as?: string; mode?: string }>,
    opts: { cwd?: string; timeoutMs?: number } = {},
  ): Promise<ExecResponse> =>
    runWithSecrets(
      async (name) => {
        const r = await this.get(name);
        return { type: r.type, value: r.value };
      },
      command,
      args,
      secrets as SecretMapping[],
      { timeoutMs: 120_000, ...opts },
    );

  /** A consistent copy of the whole (still encrypted) vault file, from the first daemon listed. */
  async exportSnapshot(): Promise<Buffer> {
    const base = this.bases[0]!;
    let res: Response;
    try {
      res = await fetch(new URL('/api/export', base), { headers: this.headers() });
    } catch (err) {
      throw new ApiError(`cannot reach secretd at ${base} (${err instanceof Error ? err.message : String(err)})`, 0);
    }
    if (!res.ok) throw new ApiError(`export from ${base} failed: ${res.status} ${await res.text()}`, res.status);
    return Buffer.from(await res.arrayBuffer());
  }

  backup = () => this.req<{ path: string; bytes: number; pruned: number }>('POST', '/api/backup');

  audit = (opts: { since?: number; secret?: string; action?: string; limit?: number } = {}) =>
    this.req<{ items: AuditEntry[] }>('GET', '/api/audit', { query: opts }).then((r) => r.items);

  /** Streams the live activity feed, invoking `onLine` for each event. */
  async streamLogs(onLine: (line: string, event: Record<string, unknown>) => void, follow = true): Promise<void> {
    const url = new URL('/api/logs', (await this.order())[0]);
    url.searchParams.set('follow', follow ? '1' : '0');

    const res = await fetch(url, { headers: this.headers() });
    if (!res.ok || !res.body) throw new ApiError(`log stream failed: ${res.status}`, res.status);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop() ?? '';
        for (const part of parts) {
          const line = part.split('\n').find((l) => l.startsWith('data: '));
          if (!line) continue;
          const evt = safeJson(line.slice(6)) as Record<string, unknown>;
          onLine(String(evt['line'] ?? ''), evt);
        }
      }
    } finally {
      // Without this, an onLine that throws leaves the socket — and the daemon's SSE
      // listener behind it — alive until GC gets round to it.
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  }
}

/**
 * GET /api/health with a hard deadline. Not fetch: an aborted fetch leaves its connect
 * attempt alive for undici's 10s connect timeout, which kept every CLI call alive for
 * 10s whenever the primary was unreachable. Destroying the socket ends it.
 */
function probe(base: string): Promise<{ locked?: boolean } | null> {
  return new Promise((resolve) => {
    let url: URL;
    try {
      url = new URL('/api/health', base);
    } catch {
      return resolve(null);
    }
    const req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { timeout: PROBE_MS }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c: string) => (body += c));
      res.on('end', () => resolve(res.statusCode === 200 ? (safeJson(body) as { locked?: boolean }) : null));
      res.on('error', () => resolve(null));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { error: text.slice(0, 500) };
  }
}
