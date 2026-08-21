#!/usr/bin/env -S node --no-warnings
import '../shared/quiet.js';
import { initCrypto } from '../vault/crypto.js';
import { Vault } from '../vault/vault.js';
import { loadConfig } from './config.js';
import { resolvePassword } from '../shared/credentials.js';
import { createServer } from './server.js';
import { scheduleBackups } from './backup.js';
import { log } from './log.js';
import { networkInterfaces } from 'node:os';

async function main(): Promise<void> {
  await initCrypto();
  const cfg = loadConfig();
  const vault = Vault.open(cfg.dbPath);

  log.info(`secretd starting — home ${cfg.home}`);

  if (!vault.initialised) {
    log.warn('vault is not initialised — run `secrets init` to create it');
  } else {
    const password = resolvePassword();
    if (!password) {
      log.warn('no stored password — vault starts locked, run `secrets unlock`');
    } else if (vault.unlock(password)) {
      log.op('unlock', true, `vault unlocked (${vault.count()} secrets)`, { caller: 'daemon' });
      vault.recordAudit('unlock', true, { caller: 'daemon', detail: 'auto-unlock at start' });
    } else {
      log.error('stored password did not match — vault starts locked', { ok: false });
      vault.recordAudit('unlock', false, { caller: 'daemon', detail: 'stored password rejected' });
    }
  }

  const server = createServer(vault, cfg);

  server.listen(cfg.port, cfg.host, () => {
    log.info(
      `listening on http://${cfg.host}:${cfg.port}  (auth: ${cfg.requireAuth ? 'vault password' : 'DISABLED'})`,
    );
    for (const addr of lanAddresses()) {
      log.info(`  reachable at http://${addr}:${cfg.port}/`);
    }
    log.info(`  web UI at http://localhost:${cfg.port}/`);
  });

  server.on('error', (err) => {
    log.error(`server error: ${err.message}`, { ok: false });
    process.exitCode = 1;
  });

  scheduleBackups(vault, cfg);

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info(`${signal} received — shutting down`);
    server.close(() => {
      vault.close();
      log.info('secretd stopped');
      process.exit(0);
    });
    // Don't hang forever on a wedged keep-alive connection.
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

function lanAddresses(): string[] {
  const out: string[] = [];
  for (const [, addrs] of Object.entries(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === 'IPv4' && !a.internal) out.push(a.address);
    }
  }
  return out;
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  log.error(`secretd failed to start: ${msg}`, { ok: false });
  process.exit(1);
});
