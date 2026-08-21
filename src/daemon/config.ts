import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { secretdHome } from '../shared/credentials.js';

export interface Config {
  home: string;
  dbPath: string;
  backupDir: string;
  host: string;
  port: number;
  backupRetentionDays: number;
  /** Set SECRETD_NO_AUTH=1 only on a trusted, isolated host. */
  requireAuth: boolean;
}

export function loadConfig(): Config {
  const home = secretdHome();
  mkdirSync(home, { recursive: true });
  return {
    home,
    dbPath: process.env['SECRETD_DB'] ?? join(home, 'vault.db'),
    backupDir: join(home, 'backups'),
    host: process.env['SECRETD_HOST'] ?? '0.0.0.0',
    port: Number(process.env['SECRETD_PORT'] ?? 7777),
    backupRetentionDays: Number(process.env['SECRETD_BACKUP_DAYS'] ?? 30),
    requireAuth: process.env['SECRETD_NO_AUTH'] !== '1',
  };
}
