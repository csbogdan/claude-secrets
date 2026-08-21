import type { Vault, SecretRecord } from '../vault/vault.js';
import type { OAuthPayload } from '../vault/types.js';
import { log } from './log.js';
import { z } from 'zod';

/** Refresh this many seconds before actual expiry. */
const SKEW_SECONDS = 60;

/**
 * Expired, allowing for clock skew. Reading a historical version reports staleness with
 * this instead of refreshing — an old version is being inspected, not consumed.
 */
export function isExpired(payload: { expires_at?: number }): boolean {
  return !!payload.expires_at && payload.expires_at <= Math.floor(Date.now() / 1000) + SKEW_SECONDS;
}
const REFRESH_TIMEOUT_MS = 10_000;

const TokenResponse = z.object({
  access_token: z.string(),
  refresh_token: z.string().optional(),
  expires_in: z.number().optional(),
});

/** A failure whose message we authored and have confirmed carries no payload data. */
class RefreshError extends Error {}

/**
 * Refresh failures must never surface a raw exception. Node embeds the offending URL in
 * fetch/URL errors and a fragment of the offending text in JSON errors — here that URL is
 * the encrypted `token_url` (which can carry userinfo) and that text is a token response.
 * Both would then be written to the unencrypted audit table. Only fixed categories escape.
 */
function describeRefreshFailure(err: unknown): string {
  if (err instanceof RefreshError) return err.message;
  if (err instanceof Error) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') return 'token endpoint timed out';
    if (err.name === 'TypeError') return 'token endpoint unreachable, or it redirected';
  }
  return 'token endpoint request failed';
}

export interface RefreshOutcome {
  record: SecretRecord;
  refreshed: boolean;
  /** True when the token is expired and refresh was impossible or failed. */
  stale: boolean;
}

/**
 * OAuth secrets refresh themselves on read so consumers never receive a dead token.
 * A failed refresh returns the stale token with `stale: true` rather than erroring —
 * a flaky identity provider should not become a hard outage for every caller.
 */
export async function refreshIfNeeded(
  vault: Vault,
  record: SecretRecord,
  ctx: { caller?: string; source?: string } = {},
): Promise<RefreshOutcome> {
  if (record.type !== 'oauth') return { record, refreshed: false, stale: false };

  const payload = record.value as z.infer<typeof OAuthPayload>;
  const now = Math.floor(Date.now() / 1000);

  if (!isExpired(payload)) return { record, refreshed: false, stale: false };

  if (!payload.refresh_token || !payload.token_url) {
    log.warn(`oauth ${record.name} is expired and has no refresh_token/token_url`, {
      action: 'refresh',
      secret: record.name,
      ...ctx,
    });
    vault.recordAudit('refresh', false, {
      secret: record.name,
      detail: 'expired, not refreshable',
      ...ctx,
    });
    return { record, refreshed: false, stale: true };
  }

  log.info(`refreshing oauth ${record.name}`, { action: 'refresh', secret: record.name, ...ctx });

  try {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: payload.refresh_token,
    });
    if (payload.client_id) body.set('client_id', payload.client_id);
    if (payload.client_secret) body.set('client_secret', payload.client_secret);

    const res = await fetch(payload.token_url, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body,
      // A 307/308 preserves the POST body, so an open redirect at the provider would
      // forward refresh_token and client_secret to the redirect target. Never follow.
      redirect: 'error',
      signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS),
    });
    if (!res.ok) throw new RefreshError(`token endpoint returned HTTP ${res.status}`);

    let body_json: unknown;
    try {
      body_json = await res.json();
    } catch {
      throw new RefreshError('token endpoint returned a malformed JSON body');
    }
    const parsed = TokenResponse.safeParse(body_json);
    if (!parsed.success) throw new RefreshError('token endpoint response missing access_token');

    const next: z.infer<typeof OAuthPayload> = {
      ...payload,
      access_token: parsed.data.access_token,
      refresh_token: parsed.data.refresh_token ?? payload.refresh_token,
      ...(parsed.data.expires_in ? { expires_at: now + parsed.data.expires_in } : {}),
    };

    // We just awaited the token endpoint. If the operator rotated this secret while we
    // were waiting, their value is newer than ours — writing would silently roll it back.
    const version = vault.updateIfVersion(
      record.name,
      record.current_version,
      next,
      'oauth auto-refresh',
    );
    if (version === null) {
      log.warn(`oauth ${record.name} was rotated during refresh — keeping the newer value`, {
        action: 'refresh',
        secret: record.name,
        ...ctx,
      });
      vault.recordAudit('refresh', false, {
        secret: record.name,
        detail: 'superseded by concurrent write',
        ...ctx,
      });
      return { record: vault.read(record.name), refreshed: false, stale: false };
    }

    vault.recordAudit('refresh', true, { secret: record.name, detail: `-> v${version}`, ...ctx });
    log.op('refresh', true, record.name, { secret: record.name, ...ctx });

    return {
      record: { ...record, value: next, current_version: version },
      refreshed: true,
      stale: false,
    };
  } catch (err) {
    const msg = describeRefreshFailure(err);
    log.warn(`oauth refresh failed for ${record.name}: ${msg} — serving stale token`, {
      action: 'refresh',
      secret: record.name,
      ...ctx,
    });
    vault.recordAudit('refresh', false, { secret: record.name, detail: msg, ...ctx });
    return { record, refreshed: false, stale: true };
  }
}
