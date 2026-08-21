import type { SecretMeta, SearchHit, AuditEntry } from '../vault/vault.js';
import type { Payload, SecretType } from '../vault/types.js';
import { resolvePassword } from './credentials.js';

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

export function defaultBaseUrl(): string {
  return process.env['SECRETD_URL'] ?? `http://127.0.0.1:${process.env['SECRETD_PORT'] ?? 7777}`;
}

/** The vault password doubles as the API credential — there is no separate token. */
export function defaultPassword(): string {
  return resolvePassword() ?? '';
}

export class SecretdClient {
  constructor(
    private readonly baseUrl: string = defaultBaseUrl(),
    private password: string = defaultPassword(),
    private readonly caller: string = 'cli',
  ) {}

  /** Used by `secrets login` / `secrets unlock` once the user has typed a password. */
  usePassword(password: string): void {
    this.password = password;
  }

  private async req<T>(
    method: string,
    path: string,
    opts: { query?: Record<string, string | number | undefined>; body?: unknown } = {},
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== '') url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = { 'x-secretd-caller': this.caller };
    if (this.password) headers['authorization'] = `Bearer ${this.password}`;
    if (opts.body !== undefined) headers['content-type'] = 'application/json';

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new ApiError(
        `cannot reach secretd at ${this.baseUrl} (${msg}) — is the daemon running? try \`secrets serve\``,
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
    this.req<{ ok: boolean; locked: boolean; initialised: boolean; secrets: number | null }>(
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

  exec = (
    command: string,
    args: string[],
    secrets: Array<{ name: string; as?: string; mode?: string }>,
    opts: { cwd?: string; timeoutMs?: number } = {},
  ) => this.req<ExecResponse>('POST', '/api/exec', { body: { command, args, secrets, ...opts } });

  backup = () => this.req<{ path: string; bytes: number; pruned: number }>('POST', '/api/backup');

  audit = (opts: { since?: number; secret?: string; action?: string; limit?: number } = {}) =>
    this.req<{ items: AuditEntry[] }>('GET', '/api/audit', { query: opts }).then((r) => r.items);

  /** Streams the live activity feed, invoking `onLine` for each event. */
  async streamLogs(onLine: (line: string, event: Record<string, unknown>) => void, follow = true): Promise<void> {
    const url = new URL('/api/logs', this.baseUrl);
    url.searchParams.set('follow', follow ? '1' : '0');
    const headers: Record<string, string> = { 'x-secretd-caller': this.caller };
    if (this.password) headers['authorization'] = `Bearer ${this.password}`;

    const res = await fetch(url, { headers });
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

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { error: text.slice(0, 500) };
  }
}
