import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, sep } from 'node:path';
import { Vault, VaultError, NotFoundError, LockedError } from '../vault/vault.js';
import { primaryValue, maskValue, SECRET_TYPES, type SecretType, type Payload } from '../vault/types.js';
import type { Config } from './config.js';
import { feed, formatEvent, log, type FeedEvent } from './log.js';
import { refreshIfNeeded, isExpired } from './oauth.js';
import { totpFrom } from '../vault/totp.js';
import { runWithSecrets, type SecretMapping } from './exec.js';
import { runBackup } from './backup.js';

const UI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'ui');
const MAX_BODY = 5 * 1024 * 1024;

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

export function createServer(vault: Vault, cfg: Config) {
  return createHttpServer((req, res) => {
    void handle(req, res, vault, cfg).catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`unhandled request error: ${msg}`, { ok: false });
      if (!res.headersSent) json(res, 500, { error: msg });
      else res.end();
    });
  });
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  vault: Vault,
  cfg: Config,
): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const path = url.pathname;
  const method = req.method ?? 'GET';
  const source = clientIp(req);
  const caller = String(req.headers['x-secretd-caller'] ?? 'http');

  if (method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }

  // Health is unauthenticated so a probe can tell "down" from "locked".
  if (path === '/api/health') {
    json(res, 200, {
      ok: true,
      locked: vault.locked,
      initialised: vault.initialised,
      secrets: vault.locked ? null : vault.count(),
      version: 1,
    });
    return;
  }

  if (path === '/' || path.startsWith('/ui/') || path === '/favicon.ico') {
    await serveUi(path, res);
    return;
  }

  // Unlock authenticates itself: the password in its body IS the credential.
  const isUnlock = method === 'POST' && path === '/api/unlock';

  if (cfg.requireAuth && !isUnlock) {
    if (vault.locked) {
      // Nothing to compare against, and a locked vault must not be a password oracle.
      json(res, 423, { error: 'vault is locked — run `secrets unlock` on the host' });
      return;
    }
    if (!authorised(req, url, vault)) {
      log.warn(`unauthorised ${method} ${path}`, { source, caller, ok: false });
      vault.recordAudit('auth', false, { source, caller, detail: `${method} ${path}` });
      json(res, 401, {
        error: 'unauthorised — send Authorization: Bearer <your vault password>',
      });
      return;
    }
  }

  const ctx = { caller, source };

  try {
    switch (`${method} ${path}`) {
      case 'POST /api/unlock': {
        const body = await readJson(req);
        const pass = String((body as { passphrase?: string }).passphrase ?? '');
        const ok = vault.unlock(pass);
        log.op('unlock', ok, ok ? 'vault unlocked' : 'wrong passphrase', ctx);
        vault.recordAudit('unlock', ok, ctx);
        json(res, ok ? 200 : 401, { ok, locked: vault.locked });
        return;
      }

      case 'POST /api/lock': {
        vault.lock();
        log.op('lock', true, 'vault locked', ctx);
        vault.recordAudit('lock', true, ctx);
        json(res, 200, { ok: true, locked: true });
        return;
      }

      case 'GET /api/secrets': {
        const items = vault.list({
          type: url.searchParams.get('type') ?? undefined,
          tag: url.searchParams.get('tag') ?? undefined,
          service: url.searchParams.get('service') ?? undefined,
          env: url.searchParams.get('env') ?? undefined,
        });
        log.op('list', true, `${items.length} secret(s)`, ctx);
        json(res, 200, { items });
        return;
      }

      case 'GET /api/search': {
        const q = url.searchParams.get('q') ?? '';
        const limit = clampInt(url.searchParams.get('limit'), 10, 1, 100);
        const items = vault.search(q, limit);
        // The raw query never reaches the feed or the unencrypted audit table: someone
        // pasting a secret value into the search box would otherwise persist it there,
        // breaking the "audit never contains values" guarantee.
        const shape = `${q.trim().split(/\s+/).filter(Boolean).length} term(s)`;
        log.op('search', true, `${shape} -> ${items.length} hit(s)`, ctx);
        vault.recordAudit('search', true, { ...ctx, detail: `${shape}, ${items.length} hit(s)` });
        json(res, 200, { items });
        return;
      }

      case 'GET /api/secret': {
        const name = requireName(url);
        const mask = url.searchParams.get('mask') === '1';
        const version = versionParam(url);
        const generation = vault.lockGeneration;
        const rec = vault.read(name, version);
        // An older version is being inspected, not consumed, so it is never refreshed —
        // that would write a new version as a side effect of looking at history.
        const out =
          version === undefined
            ? await refreshIfNeeded(vault, rec, ctx)
            : {
                record: rec,
                refreshed: false,
                stale: rec.type === 'oauth' && isExpired(rec.value as { expires_at?: number }),
              };
        // refreshIfNeeded may have awaited the token endpoint. If the vault was locked
        // meanwhile — even if it was unlocked again — we must not serve the plaintext
        // we decrypted before that happened.
        if (vault.locked || vault.lockGeneration !== generation) throw new LockedError();
        const record = out.record;
        const primary = safePrimary(record.type, record.value);

        const at = version === undefined ? '' : `@v${version}`;
        log.op('read', true, `${name}${at}${mask ? ' (masked)' : ''}`, { ...ctx, secret: name });
        vault.recordAudit('read', true, {
          ...ctx,
          secret: name,
          detail: `${mask ? 'masked' : 'plaintext'}${at}`,
        });

        json(res, 200, {
          ...record,
          value: mask ? maskPayload(record.type, record.value) : record.value,
          primary: primary === null ? null : mask ? maskValue(primary) : primary,
          stale: out.stale,
          refreshed: out.refreshed,
        });
        return;
      }

      case 'GET /api/totp': {
        const name = requireName(url);
        const rec = vault.read(name, versionParam(url));
        const spec = (rec.value as Record<string, unknown>)['totp'];
        if (typeof spec !== 'string' || !spec.trim()) {
          throw new VaultError(`secret '${name}' has no totp seed`);
        }
        // The code goes out, never the seed: a code is worth 30 seconds, a seed forever.
        const { code, expires_in } = totpFrom(spec);
        log.op('totp', true, name, { ...ctx, secret: name });
        vault.recordAudit('totp', true, { ...ctx, secret: name, detail: 'code generated' });
        json(res, 200, { name, code, expires_in });
        return;
      }

      case 'POST /api/secret': {
        const body = (await readJson(req)) as Record<string, unknown>;
        const type = body['type'] as SecretType;
        if (!SECRET_TYPES.includes(type)) {
          throw new VaultError(`unknown type '${String(type)}' — one of: ${SECRET_TYPES.join(', ')}`);
        }
        const meta = vault.create({
          name: String(body['name'] ?? ''),
          type,
          value: body['value'],
          description: str(body['description']),
          service: str(body['service']),
          env: str(body['env']),
          url: str(body['url']),
          tags: body['tags'] as string[] | string | undefined,
          aliases: body['aliases'] as string[] | undefined,
          note: str(body['note']),
        });
        log.op('create', true, `${meta.name} (${meta.type})`, { ...ctx, secret: meta.name });
        vault.recordAudit('create', true, { ...ctx, secret: meta.name, detail: meta.type });
        json(res, 201, meta);
        return;
      }

      case 'PUT /api/secret': {
        const name = requireName(url);
        const body = (await readJson(req)) as Record<string, unknown>;
        const version = vault.update(name, body['value'], str(body['note']));
        log.op('update', true, `${name} -> v${version}`, { ...ctx, secret: name });
        vault.recordAudit('update', true, { ...ctx, secret: name, detail: `v${version}` });
        json(res, 200, { name, version });
        return;
      }

      case 'PATCH /api/secret': {
        const name = requireName(url);
        const body = (await readJson(req)) as Record<string, unknown>;
        const meta = vault.patch(name, {
          description: body['description'] as string | undefined,
          service: body['service'] as string | undefined,
          env: body['env'] as string | undefined,
          url: body['url'] as string | undefined,
          tags: body['tags'] as string[] | string | undefined,
          aliases: body['aliases'] as string[] | undefined,
        });
        log.op('patch', true, name, { ...ctx, secret: name });
        vault.recordAudit('patch', true, { ...ctx, secret: name });
        json(res, 200, meta);
        return;
      }

      case 'DELETE /api/secret': {
        const name = requireName(url);
        const removed = vault.remove(name);
        log.op('delete', true, removed, { ...ctx, secret: removed });
        vault.recordAudit('delete', true, { ...ctx, secret: removed });
        json(res, 200, { ok: true, name: removed });
        return;
      }

      case 'GET /api/versions': {
        const name = requireName(url);
        const items = vault.versions(name);
        log.op('versions', true, `${name} (${items.length})`, { ...ctx, secret: name });
        json(res, 200, { name, items });
        return;
      }

      case 'POST /api/rollback': {
        const body = (await readJson(req)) as { name?: string; version?: number };
        const name = String(body.name ?? '');
        const version = Number(body.version);
        if (!name || !Number.isInteger(version)) {
          throw new VaultError('rollback requires { name, version }');
        }
        const next = vault.rollback(name, version);
        log.op('rollback', true, `${name} v${version} -> v${next}`, { ...ctx, secret: name });
        vault.recordAudit('rollback', true, { ...ctx, secret: name, detail: `v${version}->v${next}` });
        json(res, 200, { name, version: next, restored_from: version });
        return;
      }

      case 'POST /api/exec': {
        const body = (await readJson(req)) as {
          command?: string;
          args?: string[];
          secrets?: SecretMapping[];
          cwd?: string;
          timeoutMs?: number;
        };
        if (!body.command) throw new VaultError('exec requires { command }');
        if (vault.locked) throw new LockedError();
        const result = await runWithSecrets(
          vault,
          body.command,
          body.args ?? [],
          body.secrets ?? [],
          { cwd: body.cwd, timeoutMs: body.timeoutMs ?? 120_000, ...ctx },
        );
        log.op('exec', result.code === 0, `${body.command} -> exit ${result.code}`, ctx);
        json(res, 200, result);
        return;
      }

      case 'POST /api/backup': {
        if (vault.locked) throw new LockedError();
        json(res, 200, runBackup(vault, cfg));
        return;
      }

      case 'GET /api/audit': {
        const items = vault.auditLog({
          since: url.searchParams.get('since') ? Number(url.searchParams.get('since')) : undefined,
          secret: url.searchParams.get('secret') ?? undefined,
          action: url.searchParams.get('action') ?? undefined,
          limit: clampInt(url.searchParams.get('limit'), 100, 1, 1000),
        });
        json(res, 200, { items });
        return;
      }

      case 'GET /api/logs': {
        streamLogs(req, res, url.searchParams.get('follow') !== '0');
        return;
      }

      default:
        json(res, 404, { error: `no route for ${method} ${path}` });
    }
  } catch (err) {
    handleError(err, res, vault, ctx, `${method} ${path}`);
  }
}

// ------------------------------------------------------------------- helpers

function handleError(
  err: unknown,
  res: ServerResponse,
  vault: Vault,
  ctx: { caller: string; source: string },
  what: string,
): void {
  if (err instanceof NotFoundError) {
    log.op('lookup', false, `${err.query} not found`, { ...ctx, secret: err.query });
    vault.recordAudit('lookup', false, { ...ctx, secret: err.query, detail: 'not found' });
    json(res, 404, { error: err.message, query: err.query, candidates: err.candidates });
    return;
  }
  if (err instanceof VaultError) {
    log.warn(`${what}: ${err.message}`, { ...ctx, ok: false });
    json(res, err.status, { error: err.message });
    return;
  }
  const msg = err instanceof Error ? err.message : String(err);
  log.error(`${what}: ${msg}`, { ...ctx, ok: false });
  vault.recordAudit('error', false, { ...ctx, detail: msg });
  json(res, 500, { error: msg });
}

/** The vault password is the only credential. Same secret that unlocks it. */
function authorised(req: IncomingMessage, url: URL, vault: Vault): boolean {
  const header = req.headers.authorization ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(header);
  const presented = m?.[1] ?? url.searchParams.get('password') ?? '';
  if (!presented) return false;
  return vault.checkPassword(presented);
}

function clientIp(req: IncomingMessage): string {
  return req.socket.remoteAddress?.replace(/^::ffff:/, '') ?? 'unknown';
}

/** Optional ?version=N on a read. Absent means "whatever is current". */
function versionParam(url: URL): number | undefined {
  const raw = url.searchParams.get('version');
  if (raw === null || raw === '') return undefined;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new VaultError(`invalid version '${raw}'`);
  return n;
}

function requireName(url: URL): string {
  const name = url.searchParams.get('name');
  if (!name) throw new VaultError('missing ?name= parameter');
  return name;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function clampInt(raw: string | null, dflt: number, min: number, max: number): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

/** env_bundle has no single scalar; every other type does. */
function safePrimary(type: SecretType, payload: Payload): string | null {
  try {
    return primaryValue(type, payload);
  } catch {
    return null;
  }
}

function maskPayload(type: SecretType, payload: Payload): Payload {
  if (type === 'env_bundle') {
    return Object.fromEntries(
      Object.entries(payload as Record<string, string>).map(([k, v]) => [k, maskValue(v)]),
    );
  }
  // An allowlist, not a denylist. A denylist fails open: every field added to a payload
  // is rendered in full until someone remembers to list it, which for a vault is exactly
  // the wrong direction to be wrong in. Anything not named here is masked.
  // Note `url` is absent deliberately — a connection_string URL carries its own password.
  const PUBLIC = new Set([
    'host', 'port', 'database', 'user', 'username', 'scopes', 'expires_at', 'fingerprint',
    'brand', 'cardholder', 'expiry', 'bank', 'holder', 'issuer', 'account',
    'digits', 'period', 'algorithm',
  ]);
  return Object.fromEntries(
    Object.entries(payload as Record<string, unknown>).map(([k, v]) => [
      k,
      !PUBLIC.has(k) && typeof v === 'string' ? maskValue(v) : v,
    ]),
  ) as Payload;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(data),
    'cache-control': 'no-store',
  });
  res.end(data);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new VaultError('request body too large', 413);
    chunks.push(chunk as Buffer);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new VaultError('request body is not valid JSON');
  }
}

/**
 * Live activity feed. Replays recent history so a late subscriber has context,
 * then streams. A 15s heartbeat keeps proxies and idle sockets from reaping it.
 */
function streamLogs(req: IncomingMessage, res: ServerResponse, follow: boolean): void {
  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });

  const send = (e: FeedEvent): void => {
    res.write(`data: ${JSON.stringify({ ...e, line: formatEvent(e) })}\n\n`);
  };

  for (const e of feed.recent(100)) send(e);

  if (!follow) {
    res.end();
    return;
  }

  const onEvent = (e: FeedEvent): void => send(e);
  feed.on('event', onEvent);

  const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 15_000);
  heartbeat.unref();

  const cleanup = (): void => {
    clearInterval(heartbeat);
    feed.off('event', onEvent);
  };
  req.on('close', cleanup);
  res.on('close', cleanup);
}

async function serveUi(path: string, res: ServerResponse): Promise<void> {
  const rel = path === '/' ? 'index.html' : path.replace(/^\/ui\//, '').replace(/^\//, '');
  // Contain traversal: the resolved path must stay inside UI_DIR.
  const target = normalize(join(UI_DIR, rel));
  // The separator matters: a bare startsWith would also accept a sibling "…/uievil".
  if (target !== UI_DIR && !target.startsWith(UI_DIR + sep)) {
    json(res, 403, { error: 'forbidden' });
    return;
  }
  try {
    const data = await readFile(target);
    const ext = target.slice(target.lastIndexOf('.'));
    res.writeHead(200, {
      'content-type': MIME[ext] ?? 'application/octet-stream',
      'cache-control': 'no-cache',
    });
    res.end(data);
  } catch {
    json(res, 404, { error: 'not found' });
  }
}
