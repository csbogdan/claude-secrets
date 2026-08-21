import { readdirSync, statSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Vault } from '../vault/vault.js';
import type { Config } from './config.js';
import { log } from './log.js';

export interface BackupResult {
  path: string;
  bytes: number;
  pruned: number;
}

function stampName(d = new Date()): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return `vault-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.db`;
}

/**
 * Online backup via `VACUUM INTO` — safe against concurrent writers, unlike copying
 * the file. Snapshots stay encrypted with the same master key, so the passphrase is
 * still the only thing that can read them.
 */
export function runBackup(vault: Vault, cfg: Config): BackupResult {
  mkdirSync(cfg.backupDir, { recursive: true });
  const path = join(cfg.backupDir, stampName());

  log.progress('backup', 0, 3, 'starting snapshot');
  vault.backupTo(path);
  const bytes = statSync(path).size;
  log.progress('backup', 1, 3, `wrote ${(bytes / 1024).toFixed(0)} KiB`);

  const pruned = prune(cfg);
  log.progress('backup', 2, 3, `pruned ${pruned} expired snapshot(s)`);
  log.op('backup', true, `${path} (${(bytes / 1024).toFixed(0)} KiB, ${pruned} pruned)`, {
    caller: 'daemon',
  });
  log.progress('backup', 3, 3, 'complete');

  vault.recordAudit('backup', true, { caller: 'daemon', detail: `${path} ${bytes}B` });
  return { path, bytes, pruned };
}

function prune(cfg: Config): number {
  const cutoff = Date.now() - cfg.backupRetentionDays * 86_400_000;
  let pruned = 0;
  for (const f of readdirSync(cfg.backupDir)) {
    if (!f.startsWith('vault-') || !f.endsWith('.db')) continue;
    const p = join(cfg.backupDir, f);
    try {
      if (statSync(p).mtimeMs < cutoff) {
        unlinkSync(p);
        pruned++;
      }
    } catch {
      /* a snapshot vanishing under us is not worth failing the run */
    }
  }
  return pruned;
}

/** Fires the first backup shortly after boot, then every 24h. */
export function scheduleBackups(vault: Vault, cfg: Config): NodeJS.Timeout {
  const DAY = 86_400_000;
  const tick = (): void => {
    if (vault.locked) {
      log.warn('backup skipped — vault is locked', { action: 'backup' });
      return;
    }
    try {
      runBackup(vault, cfg);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`backup failed: ${msg}`, { action: 'backup', ok: false });
      vault.recordAudit('backup', false, { caller: 'daemon', detail: msg });
    }
  };
  setTimeout(tick, 60_000).unref();
  const timer = setInterval(tick, DAY);
  timer.unref();
  return timer;
}
