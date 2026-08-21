import { homedir } from 'node:os';
import { join } from 'node:path';
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync, unlinkSync } from 'node:fs';
import { readPassphrase, storePassphrase, keychainAvailable } from './keychain.js';

/** SECRETD_NO_KEYCHAIN=1 bypasses the Keychain entirely — for tests, CI, and Linux. */
function useKeychain(): boolean {
  return keychainAvailable() && process.env['SECRETD_NO_KEYCHAIN'] !== '1';
}

/**
 * There is exactly one secret in this system: the vault password. It unlocks the vault
 * and it authenticates API callers. No tokens, no key files, nothing else to rotate.
 *
 * Resolution order, first hit wins:
 *   1. SECRETD_PASSWORD (or the older SECRETD_PASSPHRASE) — for scripts and tests
 *   2. the login Keychain — the normal path on the host itself, zero config
 *   3. ~/.secretd/password — for a remote machine with no Keychain, written by `secrets login`
 *
 * Returns null when nothing is stored, which means the caller must prompt.
 */
export function secretdHome(): string {
  return process.env['SECRETD_HOME'] ?? join(homedir(), '.secretd');
}

export function passwordFilePath(): string {
  return join(secretdHome(), 'password');
}

export function resolvePassword(): string | null {
  const fromEnv = process.env['SECRETD_PASSWORD'] ?? process.env['SECRETD_PASSPHRASE'];
  if (fromEnv) return fromEnv;

  if (useKeychain()) {
    const fromKeychain = readPassphrase();
    if (fromKeychain) return fromKeychain;
  }

  const path = passwordFilePath();
  if (existsSync(path)) {
    const fromFile = readFileSync(path, 'utf8').replace(/\r?\n$/, '');
    if (fromFile) return fromFile;
  }
  return null;
}

/** Where the password came from — used to tell the user what `secrets login` changed. */
export function passwordSource(): string {
  if (process.env['SECRETD_PASSWORD'] ?? process.env['SECRETD_PASSPHRASE']) return 'environment';
  if (useKeychain() && readPassphrase()) return 'login Keychain';
  if (existsSync(passwordFilePath())) return passwordFilePath();
  return 'nowhere — run `secrets login`';
}

/**
 * Remembers the password for future commands. Prefers the Keychain; falls back to a
 * 0600 file so a Linux box or a non-login context still works.
 */
export function rememberPassword(password: string): string {
  if (useKeychain()) {
    try {
      storePassphrase(password);
      return 'login Keychain';
    } catch {
      /* fall through to the file */
    }
  }
  const path = passwordFilePath();
  mkdirSync(secretdHome(), { recursive: true });
  writeFileSync(path, `${password}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

export function forgetPassword(): void {
  const path = passwordFilePath();
  if (existsSync(path)) unlinkSync(path);
}
