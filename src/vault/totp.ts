import { createHmac } from 'node:crypto';

/**
 * RFC 6238 time-based one-time passwords.
 *
 * A seed is stored as a plain string on any payload that has a `totp` field, and may be
 * either a bare base32 secret or the whole `otpauth://` URI an authenticator app shows
 * behind its QR code. The URI already carries digits/period/algorithm, so there is no
 * need for parallel fields to hold them — paste what you were given and it works.
 */

export class TotpError extends Error {}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface TotpParams {
  secret: string;
  digits?: number;
  period?: number;
  algorithm?: 'sha1' | 'sha256' | 'sha512';
  issuer?: string;
  account?: string;
}

/** RFC 4648 base32. Case-insensitive; padding and the spaces sites add are ignored. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean) throw new TotpError('totp seed is empty');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    // The offending character is not echoed — it is part of a secret.
    if (idx === -1) throw new TotpError('totp seed is not valid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** The code for a moment in time. `at` is unix milliseconds. */
export function totpCode(p: TotpParams, at: number = Date.now()): string {
  const digits = p.digits ?? 6;
  const counter = Math.floor(at / 1000 / (p.period ?? 30));
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));

  const mac = createHmac(p.algorithm ?? 'sha1', base32Decode(p.secret)).update(buf).digest();
  // Dynamic truncation: the low nibble of the last byte picks the 4-byte window.
  const offset = mac[mac.length - 1]! & 0x0f;
  const truncated = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(truncated % 10 ** digits).padStart(digits, '0');
}

/** Seconds until the current code rolls over. */
export function totpRemaining(period = 30, at: number = Date.now()): number {
  return period - (Math.floor(at / 1000) % period);
}

/**
 * `otpauth://totp/Issuer:account?secret=...&digits=6&period=30&algorithm=SHA1`.
 * Returns null for anything that is not such a URI, so callers can fall back to
 * treating the string as a bare seed.
 */
export function parseOtpauth(raw: string): TotpParams | null {
  const s = raw.trim();
  if (!s.toLowerCase().startsWith('otpauth://totp/')) return null;

  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new TotpError('malformed otpauth:// URI');
  }
  const secret = u.searchParams.get('secret');
  if (!secret) throw new TotpError('otpauth:// URI has no secret parameter');

  const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
  const split = label.indexOf(':');
  const algorithm = (u.searchParams.get('algorithm') ?? 'SHA1').toLowerCase();
  if (algorithm !== 'sha1' && algorithm !== 'sha256' && algorithm !== 'sha512') {
    throw new TotpError(`unsupported totp algorithm '${algorithm}'`);
  }

  return {
    secret,
    algorithm,
    ...(u.searchParams.get('digits') ? { digits: Number(u.searchParams.get('digits')) } : {}),
    ...(u.searchParams.get('period') ? { period: Number(u.searchParams.get('period')) } : {}),
    ...(u.searchParams.get('issuer') ? { issuer: u.searchParams.get('issuer')! } : {}),
    ...(split === -1 ? { account: label } : { issuer: label.slice(0, split), account: label.slice(split + 1) }),
  };
}

/** A stored seed — bare base32 or an otpauth:// URI — turned into a code you can type. */
export function totpFrom(spec: string, at: number = Date.now()): { code: string; expires_in: number } {
  const params = parseOtpauth(spec) ?? { secret: spec };
  return { code: totpCode(params, at), expires_in: totpRemaining(params.period ?? 30, at) };
}
