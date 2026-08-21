import { createRequire } from 'node:module';

// libsodium-wrappers-sumo@0.7.16 ships a broken ESM entry point: its .mjs resolves
// ./libsodium-sumo.mjs inside its own dist directory rather than the sibling package,
// so `import` fails at runtime. The CJS build is intact, hence createRequire.
const _require = createRequire(import.meta.url);
const _sodium = _require('libsodium-wrappers-sumo') as typeof import('libsodium-wrappers-sumo');

export type Sodium = typeof _sodium;

let sodium: Sodium | null = null;

/** Must be awaited once before any crypto call. Idempotent. */
export async function initCrypto(): Promise<Sodium> {
  if (sodium) return sodium;
  await _sodium.ready;
  sodium = _sodium;
  return sodium;
}

function s(): Sodium {
  if (!sodium) throw new Error('crypto not initialised — call initCrypto() first');
  return sodium;
}

export interface KdfParams {
  salt: Uint8Array;
  ops: number;
  mem: number;
}

export function defaultKdfParams(): KdfParams {
  const so = s();
  return {
    salt: so.randombytes_buf(so.crypto_pwhash_SALTBYTES),
    ops: so.crypto_pwhash_OPSLIMIT_MODERATE,
    mem: so.crypto_pwhash_MEMLIMIT_MODERATE,
  };
}

/** Argon2id: passphrase + salt -> 32-byte master key. */
export function deriveKey(passphrase: string, p: KdfParams): Uint8Array {
  const so = s();
  return so.crypto_pwhash(
    so.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase,
    p.salt,
    p.ops,
    p.mem,
    so.crypto_pwhash_ALG_ARGON2ID13,
  );
}

export interface Sealed {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * XChaCha20-Poly1305. `aad` binds the ciphertext to its identity (`name:version`)
 * so a blob cannot be moved between secrets or replayed as a different version.
 */
export function seal(plaintext: string, aad: string, key: Uint8Array): Sealed {
  const so = s();
  const nonce = so.randombytes_buf(so.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = so.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key,
  );
  return { nonce, ciphertext };
}

export function open(sealed: Sealed, aad: string, key: Uint8Array): string {
  const so = s();
  const plain = so.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    sealed.ciphertext,
    aad,
    sealed.nonce,
    key,
  );
  return new TextDecoder().decode(plain);
}

export function wipe(buf: Uint8Array | null): void {
  if (buf) s().memzero(buf);
}

export function randomToken(bytes = 32): string {
  return Buffer.from(s().randombytes_buf(bytes)).toString('base64url');
}

/** Constant-time string compare for bearer tokens. */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Still burn a comparison so length isn't leaked through timing alone.
    try {
      s().memcmp(ab, ab);
    } catch {
      /* ignore */
    }
    return false;
  }
  return s().memcmp(ab, bb);
}
