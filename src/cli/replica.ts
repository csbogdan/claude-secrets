import { existsSync, readFileSync, writeFileSync, unlinkSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { SecretdClient, ApiError, defaultPassword, type SecretResponse } from '../shared/client.js';
import { loadConfig } from '../daemon/config.js';
import { initCrypto } from '../vault/crypto.js';
import { Vault } from '../vault/vault.js';

const DAEMON_LABEL = 'com.stefan.secretd';
const NOTE = 'replayed from replica';

interface Entry {
  op: 'upsert' | 'delete';
  name: string;
}

const say = (msg: string): void => void process.stdout.write(`${new Date().toISOString()} ${msg}\n`);

function readOutbox(path: string): Entry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Entry);
}

const notFound = (err: unknown): boolean => err instanceof ApiError && err.status === 404;

/**
 * One sync cycle, run hourly on the replica machine by launchd:
 *   1. replay the writes journaled on this replica onto the primary,
 *   2. download a fresh snapshot of the primary,
 *   3. stop the local daemon, swap the snapshot in, start it again.
 * Primary unreachable or locked: nothing changes, the replica keeps serving, exit 0.
 */
export async function replicaSync(primaryUrl: string): Promise<number> {
  const cfg = loadConfig();
  if (!cfg.replica) {
    process.stderr.write('refusing: SECRETD_REPLICA=1 is not set, so this vault is not a replica\n');
    return 1;
  }
  const password = defaultPassword();
  const local = new SecretdClient(`http://127.0.0.1:${cfg.port}`, password, 'replica-sync');
  const primary = new SecretdClient(primaryUrl, password, 'replica-sync');

  try {
    const h = await primary.health();
    if (h.replica) {
      process.stderr.write(`refusing: ${primaryUrl} is itself a replica\n`);
      return 1;
    }
    if (h.locked) {
      say(`primary ${primaryUrl} is locked; replica unchanged`);
      return 0;
    }
  } catch {
    say(`primary ${primaryUrl} unreachable; replica unchanged`);
    return 0;
  }

  const entries = readOutbox(cfg.outboxPath);
  if (entries.length) {
    try {
      await replay(entries, local, primary);
    } catch (err) {
      say(`replay failed, replica unchanged and writes kept for the next run: ${err instanceof Error ? err.message : String(err)}`);
      return 1;
    }
  }

  const dir = mkdtempSync(join(tmpdir(), 'secretd-sync-'));
  const uid = process.getuid?.() ?? 501;
  const plist = join(homedir(), 'Library', 'LaunchAgents', `${DAEMON_LABEL}.plist`);
  try {
    const file = join(dir, 'vault.db');
    writeFileSync(file, await primary.exportSnapshot(), { mode: 0o600 });

    try {
      execFileSync('launchctl', ['bootout', `gui/${uid}/${DAEMON_LABEL}`], { stdio: 'ignore' });
    } catch {
      /* not running: nothing to stop */
    }
    try {
      // A write that landed between the replay and the stop is not on the primary yet.
      if (readOutbox(cfg.outboxPath).length !== entries.length) {
        say('new writes arrived during the sync; kept them, will replay next run');
        return 0;
      }
      await swapIn(file, cfg.dbPath);
      if (existsSync(cfg.outboxPath)) unlinkSync(cfg.outboxPath);
      say(`synced from ${primaryUrl}${entries.length ? `, replayed ${entries.length} write(s)` : ''}`);
      return 0;
    } finally {
      execFileSync('launchctl', ['bootstrap', `gui/${uid}`, plist], { stdio: 'ignore' });
    }
  } catch (err) {
    say(`sync failed, replica unchanged: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Replaces the vault file with the daemon stopped. Keeps one previous copy, and puts it back if the new file is not a vault. */
async function swapIn(file: string, dbPath: string): Promise<void> {
  await initCrypto();
  const previous = `${dbPath}.previous`;
  if (existsSync(dbPath)) copyFileSync(dbPath, previous);
  // A stale WAL from the old file would be replayed onto the new one and corrupt it.
  for (const suffix of ['-wal', '-shm']) if (existsSync(dbPath + suffix)) unlinkSync(dbPath + suffix);
  copyFileSync(file, dbPath);
  const v = Vault.open(dbPath);
  const ok = v.initialised;
  v.close();
  if (!ok) {
    if (existsSync(previous)) copyFileSync(previous, dbPath);
    throw new Error('downloaded snapshot is not a secretd vault');
  }
}

/**
 * Brings the primary up to the replica's current state for every name written here.
 * Idempotent: running it twice changes nothing the second time, so a failed sync can
 * simply retry. Only the latest value is replayed, not every intermediate version.
 */
async function replay(entries: Entry[], local: SecretdClient, primary: SecretdClient): Promise<void> {
  const current = new Map<string, SecretResponse>();
  for (const name of new Set(entries.map((e) => e.name))) {
    try {
      const r = await local.get(name);
      current.set(r.name, r);
    } catch (err) {
      if (!notFound(err)) throw err;
    }
  }
  for (const rec of current.values()) say(`replay ${rec.name}: ${await push(rec, primary)}`);

  for (const e of entries) {
    if (e.op !== 'delete' || current.has(e.name)) continue;
    try {
      await primary.remove(e.name);
      say(`replay ${e.name}: deleted`);
    } catch (err) {
      if (!notFound(err)) throw err;
    }
  }
}

async function push(rec: SecretResponse, primary: SecretdClient): Promise<string> {
  const meta = {
    description: rec.description,
    service: rec.service,
    env: rec.env,
    url: rec.url,
    tags: rec.tags,
    aliases: rec.aliases,
  };
  let cur: SecretResponse | null = null;
  try {
    cur = await primary.get(rec.name);
  } catch (err) {
    if (!notFound(err)) throw err;
  }
  if (cur && cur.type !== rec.type) {
    await primary.remove(rec.name);
    cur = null;
  }
  if (!cur) {
    await primary.create({ name: rec.name, type: rec.type, value: rec.value, ...meta, note: NOTE });
    return 'created';
  }
  const changes: string[] = [];
  if (!isDeepStrictEqual(cur.value, rec.value)) {
    await primary.update(rec.name, rec.value, NOTE);
    changes.push('value');
  }
  const curMeta = { description: cur.description, service: cur.service, env: cur.env, url: cur.url, tags: cur.tags, aliases: cur.aliases };
  if (!isDeepStrictEqual(curMeta, meta)) {
    await primary.patch(rec.name, meta);
    changes.push('metadata');
  }
  return changes.length ? `updated ${changes.join(' + ')}` : 'already current';
}
