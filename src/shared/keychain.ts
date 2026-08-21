import { execFileSync } from 'node:child_process';

const SERVICE = 'secretd';
const ACCOUNT = 'master';

/**
 * The vault passphrase is escrowed in the login Keychain so the mini can unlock
 * itself unattended after a reboot. Anyone with your unlocked login session can
 * therefore read it — which is already true of ~/.claude.
 */
export function readPassphrase(): string | null {
  try {
    const out = execFileSync(
      'security',
      ['find-generic-password', '-w', '-s', SERVICE, '-a', ACCOUNT],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
    return out.replace(/\r?\n$/, '');
  } catch {
    return null;
  }
}

// Note: the passphrase appears in this process's argv for the lifetime of the call,
// so it is briefly visible to `ps` on a multi-user machine. Acceptable for a
// single-operator host; `security` offers no stdin path for this.
export function storePassphrase(passphrase: string): void {
  execFileSync(
    'security',
    ['add-generic-password', '-U', '-s', SERVICE, '-a', ACCOUNT, '-w', passphrase],
    { stdio: 'ignore' },
  );
}

export function deletePassphrase(): boolean {
  try {
    execFileSync('security', ['delete-generic-password', '-s', SERVICE, '-a', ACCOUNT], {
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

export function keychainAvailable(): boolean {
  return process.platform === 'darwin';
}
