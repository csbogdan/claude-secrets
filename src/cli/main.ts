#!/usr/bin/env -S node --no-warnings
import '../shared/quiet.js';
import { parseArgs } from 'node:util';
import { readFileSync, existsSync, copyFileSync, unlinkSync, statSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { SecretdClient, ApiError, defaultBaseUrl, defaultPassword } from '../shared/client.js';
import { initCrypto } from '../vault/crypto.js';
import { Vault } from '../vault/vault.js';
import { loadConfig } from '../daemon/config.js';
import { rememberPassword, forgetPassword, passwordSource } from '../shared/credentials.js';
import { SECRET_TYPES, parseDotenv, type SecretType } from '../vault/types.js';

const USE_COLOR = process.stdout.isTTY && !process.env['NO_COLOR'];
const c = {
  dim: (s: string) => (USE_COLOR ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s: string) => (USE_COLOR ? `\x1b[1m${s}\x1b[0m` : s),
  red: (s: string) => (USE_COLOR ? `\x1b[31m${s}\x1b[0m` : s),
  green: (s: string) => (USE_COLOR ? `\x1b[32m${s}\x1b[0m` : s),
  yellow: (s: string) => (USE_COLOR ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s: string) => (USE_COLOR ? `\x1b[36m${s}\x1b[0m` : s),
};

const HELP = `${c.bold('secrets')} — CRUD for the local secrets vault

${c.bold('Setup')}
  secrets init                       create the vault (prompts for a password)
  secrets serve                      run the daemon in the foreground
  secrets status                     daemon health, lock state, secret count
  secrets login                      remember the password on this machine
  secrets logout                     forget it again
  secrets unlock | lock              unlock/lock the running daemon

${c.bold('Read')}
  secrets ls [--type T] [--tag T] [--service S] [--env E]
  secrets search <query...>          natural-language lookup over metadata
  secrets get <name> [--json] [--mask] [--field F] [--version N]
  secrets totp <name>                current 2FA code for a secret with a totp seed
  secrets versions <name>
  secrets audit [--secret N] [--action A] [--limit N]
  secrets logs [-f]                  live activity feed

${c.bold('Write')}
  secrets set <name> [value] [--type T] [--desc D] [--tags a,b] [--aliases x,y]
                     [--service S] [--env E] [--url U] [--from-file F] [--stdin] [--note N]
  secrets edit <name> [--desc D] [--tags a,b] [--aliases x,y] [--service S] [--env E] [--url U]
  secrets rm <name>
  secrets rollback <name> <version>   restore an old version (view one with get --version)
  secrets import <file> --name <name>   import a .env file as an env_bundle
  secrets backup                     snapshot now

${c.bold('Move to another machine')}
  secrets export <file> [-y]         write a portable encrypted copy of the whole vault
  secrets restore <file> [-y]        install one here as this machine's vault

${c.bold('Use without exposing the value')}
  secrets exec <name>[,<name>...] -- <command> [args...]
      Injects secrets into the child's environment. Values never hit your terminal.
      e.g. secrets exec github/pat -- gh repo list
           secrets exec deploy-key:file -- ssh -i {{deploy-key}} host

${c.bold('Types')}  ${SECRET_TYPES.join(', ')}
${c.bold('Env')}    SECRETD_URL (${defaultBaseUrl()}), SECRETD_PASSWORD, SECRETD_HOME

One password does everything: it encrypts the vault, unlocks the daemon, and
authenticates every client. There is no separate token.
`;

async function main(): Promise<number> {
  const argvAll = process.argv.slice(2);
  const dashdash = argvAll.indexOf('--');
  const argv = dashdash === -1 ? argvAll : argvAll.slice(0, dashdash);
  const passthrough = dashdash === -1 ? [] : argvAll.slice(dashdash + 1);
  const cmd = argv[0];

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(HELP);
    return 0;
  }

  const { values, positionals } = parseArgs({
    args: argv.slice(1),
    allowPositionals: true,
    strict: false,
    options: {
      json: { type: 'boolean' },
      mask: { type: 'boolean' },
      follow: { type: 'boolean', short: 'f' },
      stdin: { type: 'boolean' },
      yes: { type: 'boolean', short: 'y' },
      type: { type: 'string' },
      desc: { type: 'string' },
      tags: { type: 'string' },
      aliases: { type: 'string' },
      service: { type: 'string' },
      env: { type: 'string' },
      url: { type: 'string' },
      note: { type: 'string' },
      field: { type: 'string' },
      version: { type: 'string' },
      name: { type: 'string' },
      'from-file': { type: 'string' },
      secret: { type: 'string' },
      action: { type: 'string' },
      limit: { type: 'string' },
    },
  });

  const v = values as Record<string, string | boolean | undefined>;
  const api = new SecretdClient(defaultBaseUrl(), defaultPassword(), 'cli');

  switch (cmd) {
    case 'init':
      return cmdInit();
    case 'serve':
      await import('../daemon/main.js');
      return new Promise<number>(() => {
        /* daemon owns the process from here */
      });
    case 'status':
      return cmdStatus(api);
    case 'login':
      return cmdLogin(api);
    case 'logout':
      forgetPassword();
      process.stdout.write(
        `${c.green('forgot')} the local password file. ` +
          `${c.dim('Keychain entry (if any) is left alone — remove it in Keychain Access.')}\n`,
      );
      return 0;
    case 'unlock': {
      const pass = defaultPassword() || (await promptSecret('Password: '));
      api.usePassword(pass);
      const r = await api.unlock(pass);
      process.stdout.write(r.ok ? c.green('vault unlocked\n') : c.red('wrong password\n'));
      return r.ok ? 0 : 1;
    }
    case 'lock':
      await api.lock();
      process.stdout.write(c.green('vault locked\n'));
      return 0;
    case 'ls':
      return cmdList(api, v);
    case 'search':
      return cmdSearch(api, positionals.join(' '), v);
    case 'get':
      return cmdGet(api, must(positionals[0], 'get <name>'), v);
    case 'set':
      return cmdSet(api, must(positionals[0], 'set <name> [value]'), positionals[1], v);
    case 'edit':
      return cmdEdit(api, must(positionals[0], 'edit <name>'), v);
    case 'rm':
      return cmdRemove(api, must(positionals[0], 'rm <name>'));
    case 'totp':
      return cmdTotp(api, must(positionals[0], 'totp <name>'), v);
    case 'versions':
      return cmdVersions(api, must(positionals[0], 'versions <name>'));
    case 'rollback':
      return cmdRollback(api, must(positionals[0], 'rollback <name> <version>'), Number(positionals[1]));
    case 'import':
      return cmdImport(api, must(positionals[0], 'import <file> --name <name>'), v);
    case 'exec':
      return cmdExec(api, must(positionals[0], 'exec <names> -- <command>'), passthrough);
    case 'logs':
      return cmdLogs(api, v.follow === true);
    case 'audit':
      return cmdAudit(api, v);
    case 'export':
      return cmdExport(must(positionals[0], 'export <file>'), v['yes'] === true);
    case 'restore':
      return cmdRestore(must(positionals[0], 'restore <file>'), v['yes'] === true);
    case 'backup': {
      const r = await api.backup();
      process.stdout.write(`${c.green('backup written')} ${r.path} (${(r.bytes / 1024).toFixed(0)} KiB, ${r.pruned} pruned)\n`);
      return 0;
    }
    default:
      process.stderr.write(c.red(`unknown command '${cmd}'\n\n`));
      process.stdout.write(HELP);
      return 1;
  }
}

// ------------------------------------------------------------------ commands

async function cmdInit(): Promise<number> {
  await initCrypto();
  const cfg = loadConfig();
  const vault = Vault.open(cfg.dbPath);

  if (vault.initialised) {
    process.stderr.write(c.yellow(`vault already exists at ${cfg.dbPath}\n`));
    vault.close();
    return 1;
  }

  process.stdout.write(`Creating vault at ${c.cyan(cfg.dbPath)}\n`);
  process.stdout.write(
    c.yellow('This password is the ONLY key. Lose it and every secret and backup is gone.\n'),
  );
  // SECRETD_PASSWORD lets an install script or test drive this without a TTY.
  const preset = process.env['SECRETD_PASSWORD'] ?? process.env['SECRETD_PASSPHRASE'];
  const p1 = preset ?? (await promptSecret('Password: '));
  if (p1.length < 8) {
    process.stderr.write(c.red('password must be at least 8 characters\n'));
    vault.close();
    return 1;
  }
  const p2 = preset ?? (await promptSecret('Confirm:  '));
  if (p1 !== p2) {
    process.stderr.write(c.red('passwords do not match\n'));
    vault.close();
    return 1;
  }

  vault.init(p1);
  vault.recordAudit('init', true, { caller: 'cli', detail: 'vault created' });
  vault.close();
  process.stdout.write(c.green('vault created\n'));

  if (process.env['SECRETD_NO_KEYCHAIN'] !== '1') {
    const where = rememberPassword(p1);
    process.stdout.write(`${c.green('password remembered')} in ${c.cyan(where)} — the daemon auto-unlocks at login\n`);
  }

  process.stdout.write(
    `\nThat one password is all there is: it encrypts the vault, unlocks the daemon,\n` +
      `and authenticates the CLI, the web UI and Claude. No tokens to manage.\n`,
  );
  process.stdout.write(`\nNext: ${c.cyan('secrets serve')}  then open ${c.cyan(`http://localhost:${cfg.port}/`)}\n`);
  return 0;
}

/**
 * Stores the vault password on this machine so every later command is silent.
 * Verified against the daemon before it is written — remembering a wrong password
 * just moves the failure somewhere more confusing.
 */
async function cmdLogin(api: SecretdClient): Promise<number> {
  const password = process.env['SECRETD_PASSWORD'] ?? (await promptSecret('Password: '));
  if (!password) {
    process.stderr.write(c.red('no password given\n'));
    return 1;
  }
  api.usePassword(password);
  try {
    const r = await api.unlock(password);
    if (!r.ok) {
      process.stderr.write(c.red('wrong password — nothing saved\n'));
      return 1;
    }
  } catch (err) {
    process.stderr.write(c.red(`${err instanceof Error ? err.message : String(err)}\n`));
    return 1;
  }
  const where = rememberPassword(password);
  process.stdout.write(`${c.green('logged in')} — password remembered in ${c.cyan(where)}\n`);
  return 0;
}

async function cmdStatus(api: SecretdClient): Promise<number> {
  const h = await api.health();
  process.stdout.write(
    `${c.bold('secretd')} ${defaultBaseUrl()}\n` +
      `  initialised : ${h.initialised ? c.green('yes') : c.red('no')}\n` +
      `  locked      : ${h.locked ? c.yellow('yes') : c.green('no')}\n` +
      `  secrets     : ${h.secrets ?? c.dim('(locked)')}\n` +
      `  password    : ${c.dim(passwordSource())}\n`,
  );
  return h.locked ? 1 : 0;
}

async function cmdList(api: SecretdClient, v: Record<string, unknown>): Promise<number> {
  const items = await api.list({
    type: v['type'] as string | undefined,
    tag: v['tags'] as string | undefined,
    service: v['service'] as string | undefined,
    env: v['env'] as string | undefined,
  });
  if (v['json']) {
    process.stdout.write(`${JSON.stringify(items, null, 2)}\n`);
    return 0;
  }
  if (!items.length) {
    process.stdout.write(c.dim('no secrets\n'));
    return 0;
  }
  const w = Math.max(...items.map((i) => i.name.length));
  for (const i of items) {
    const tags = i.tags.length ? c.dim(` [${i.tags.join(' ')}]`) : '';
    const desc = i.description ? ` ${c.dim(i.description)}` : '';
    process.stdout.write(`${i.name.padEnd(w)}  ${c.cyan(i.type)}${desc}${tags}\n`);
  }
  process.stdout.write(c.dim(`\n${items.length} secret(s)\n`));
  return 0;
}

async function cmdSearch(api: SecretdClient, query: string, v: Record<string, unknown>): Promise<number> {
  if (!query.trim()) {
    process.stderr.write(c.red('usage: secrets search <query...>\n'));
    return 1;
  }
  const items = await api.search(query, Number(v['limit'] ?? 10));
  if (v['json']) {
    process.stdout.write(`${JSON.stringify(items, null, 2)}\n`);
    return 0;
  }
  if (!items.length) {
    process.stdout.write(c.dim(`no matches for "${query}"\n`));
    return 1;
  }
  for (const i of items) {
    process.stdout.write(
      `${c.bold(i.name)}  ${c.cyan(i.type)}${i.env ? c.dim(` ${i.env}`) : ''}\n` +
        (i.description ? `  ${i.description}\n` : '') +
        (i.aliases.length ? `  ${c.dim(`aka ${i.aliases.join(', ')}`)}\n` : ''),
    );
  }
  return 0;
}

async function cmdGet(api: SecretdClient, name: string, v: Record<string, unknown>): Promise<number> {
  const want = v['version'] === undefined ? undefined : Number(v['version']);
  if (want !== undefined && (!Number.isInteger(want) || want < 1)) {
    process.stderr.write(c.red(`invalid --version '${String(v['version'])}'\n`));
    return 1;
  }
  const rec = await api.get(name, v['mask'] === true, want);
  if (want !== undefined && want !== rec.current_version) {
    // Loud, because the value on stdout is not what a consumer of this secret would get.
    process.stderr.write(c.yellow(`note: showing v${want}, current is v${rec.current_version}\n`));
  }
  if (rec.stale) process.stderr.write(c.yellow(`warning: ${name} is expired and could not be refreshed\n`));

  if (v['json']) {
    process.stdout.write(`${JSON.stringify(rec, null, 2)}\n`);
    return 0;
  }
  const field = v['field'] as string | undefined;
  if (field) {
    const val = (rec.value as Record<string, unknown>)[field];
    if (val === undefined) {
      process.stderr.write(c.red(`no field '${field}' on ${name}\n`));
      return 1;
    }
    process.stdout.write(`${String(val)}\n`);
    return 0;
  }
  if (rec.type === 'env_bundle') {
    for (const [k, val] of Object.entries(rec.value as Record<string, string>)) {
      process.stdout.write(`${k}=${val}\n`);
    }
    return 0;
  }
  // Bare value on stdout so `export X=$(secrets get foo)` works.
  process.stdout.write(`${rec.primary ?? ''}\n`);
  return 0;
}

async function cmdSet(
  api: SecretdClient,
  name: string,
  positionalValue: string | undefined,
  v: Record<string, unknown>,
): Promise<number> {
  let value: unknown = positionalValue;
  if (v['from-file']) value = readFileSync(String(v['from-file']), 'utf8');
  else if (v['stdin'] || value === undefined) value = await readStdin();

  if (value === undefined || value === '') {
    process.stderr.write(c.red('no value given — pass it as an argument, --from-file, or on stdin\n'));
    return 1;
  }
  if (typeof value === 'string') value = value.replace(/\n$/, '');

  // Probe with versions(), not get() — get() decrypts the value and records a
  // plaintext `read` in the audit log, which is a lie about what `set` did.
  const exists = await api
    .versions(name)
    .then(() => true)
    .catch((e: unknown) => {
      if (e instanceof ApiError && e.status === 404) return false;
      throw e;
    });

  if (exists) {
    const r = await api.update(name, value, (v['note'] as string) ?? '');
    process.stdout.write(`${c.green('updated')} ${name} ${c.dim(`-> v${r.version}`)}\n`);
    // Metadata flags on an existing secret should still apply.
    if (v['desc'] || v['tags'] || v['aliases'] || v['service'] || v['env'] || v['url']) {
      await api.patch(name, metaFields(v));
      process.stdout.write(`${c.green('updated')} ${name} metadata\n`);
    }
    return 0;
  }

  const type = (v['type'] as SecretType | undefined) ?? 'api_key';
  if (!SECRET_TYPES.includes(type)) {
    process.stderr.write(c.red(`unknown type '${type}' — one of: ${SECRET_TYPES.join(', ')}\n`));
    return 1;
  }
  const meta = await api.create({ name, type, value, ...metaFields(v), note: v['note'] as string | undefined });
  process.stdout.write(`${c.green('created')} ${meta.name} ${c.dim(`(${meta.type})`)}\n`);
  if (!meta.description) {
    process.stdout.write(
      c.dim('  tip: add --desc and --aliases so natural-language search can find this later\n'),
    );
  }
  return 0;
}

async function cmdTotp(
  api: SecretdClient,
  name: string,
  v: Record<string, unknown>,
): Promise<number> {
  const { code, expires_in } = await api.totp(name);
  if (v['json']) {
    process.stdout.write(`${JSON.stringify({ name, code, expires_in }, null, 2)}\n`);
    return 0;
  }
  // Code alone on stdout so it pipes; its lifetime goes to stderr.
  process.stdout.write(`${code}\n`);
  process.stderr.write(c.dim(`valid ${expires_in}s\n`));
  return 0;
}

async function cmdEdit(api: SecretdClient, name: string, v: Record<string, unknown>): Promise<number> {
  const meta = await api.patch(name, metaFields(v));
  process.stdout.write(`${c.green('updated')} ${meta.name} metadata\n`);
  return 0;
}

async function cmdRemove(api: SecretdClient, name: string): Promise<number> {
  const r = await api.remove(name);
  process.stdout.write(`${c.green('deleted')} ${r.name}\n`);
  return 0;
}

async function cmdVersions(api: SecretdClient, name: string): Promise<number> {
  const items = await api.versions(name);
  for (const i of items) {
    const when = new Date(i.created_at * 1000).toISOString().replace('T', ' ').slice(0, 19);
    const marker = i.current ? c.green(' *current') : '';
    process.stdout.write(`v${String(i.version).padStart(3)}  ${c.dim(when)}  ${i.note}${marker}\n`);
  }
  process.stdout.write(c.dim(`\nsecrets get ${name} --version N   view one without restoring it\n`));
  return 0;
}

async function cmdRollback(api: SecretdClient, name: string, version: number): Promise<number> {
  if (!Number.isInteger(version)) {
    process.stderr.write(c.red('usage: secrets rollback <name> <version>\n'));
    return 1;
  }
  const r = await api.rollback(name, version);
  process.stdout.write(`${c.green('rolled back')} ${name} to v${version} ${c.dim(`(now v${r.version})`)}\n`);
  return 0;
}

async function cmdImport(api: SecretdClient, file: string, v: Record<string, unknown>): Promise<number> {
  const name = v['name'] as string | undefined;
  if (!name) {
    process.stderr.write(c.red('usage: secrets import <file> --name <name>\n'));
    return 1;
  }
  const text = readFileSync(file, 'utf8');
  const meta = await api.create({
    name,
    type: 'env_bundle',
    value: text,
    description: (v['desc'] as string) ?? `imported from ${file}`,
    ...metaFields(v),
  });
  // Count locally rather than reading the secret back — no need to pull plaintext
  // across the wire just to print a number.
  const count = Object.keys(parseDotenv(text)).length;
  process.stdout.write(`${c.green('imported')} ${meta.name} ${c.dim(`(${count} vars)`)}\n`);
  return 0;
}

/** `secrets exec name1,name2:file -- cmd args` */
async function cmdExec(api: SecretdClient, spec: string, passthrough: string[]): Promise<number> {
  if (!passthrough.length) {
    process.stderr.write(c.red('usage: secrets exec <names> -- <command> [args...]\n'));
    return 1;
  }
  const secrets = spec.split(',').filter(Boolean).map((entry) => {
    const [name, mode] = entry.split(':');
    return { name: name!.trim(), mode: (mode?.trim() as 'env' | 'file' | 'stdin') ?? 'env' };
  });
  const [command, ...args] = passthrough;
  const r = await api.exec(command!, args, secrets);
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.truncated) process.stderr.write(c.dim('\n[output truncated]\n'));
  return r.code ?? 1;
}

async function cmdLogs(api: SecretdClient, follow: boolean): Promise<number> {
  await api.streamLogs((line) => process.stdout.write(`${line}\n`), follow);
  return 0;
}

async function cmdAudit(api: SecretdClient, v: Record<string, unknown>): Promise<number> {
  const items = await api.audit({
    secret: v['secret'] as string | undefined,
    action: v['action'] as string | undefined,
    limit: Number(v['limit'] ?? 50),
  });
  if (v['json']) {
    process.stdout.write(`${JSON.stringify(items, null, 2)}\n`);
    return 0;
  }
  for (const e of items.reverse()) {
    const when = new Date(e.ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
    const status = e.ok ? c.green('ok  ') : c.red('FAIL');
    const who = [e.caller, e.source].filter(Boolean).join(' ');
    process.stdout.write(
      `${c.dim(when)}  ${status}  ${e.action.padEnd(8)} ${e.secret_name.padEnd(20)} ${c.dim(who)} ${c.dim(e.detail)}\n`,
    );
  }
  return 0;
}

/**
 * Writes a self-contained encrypted copy of the vault. Uses VACUUM INTO rather than
 * copying the file, so it folds in the write-ahead log and is safe to run while the
 * daemon is live — a plain `cp` of vault.db can miss recent writes still in the WAL.
 *
 * The output is still encrypted under the same password. It is useless without it,
 * which is what makes it safe to move over AirDrop, scp, or a USB stick.
 */
async function cmdExport(file: string, force: boolean): Promise<number> {
  await initCrypto();
  const cfg = loadConfig();
  const out = resolve(file);

  if (!existsSync(cfg.dbPath)) {
    process.stderr.write(c.red(`no vault at ${cfg.dbPath}\n`));
    return 1;
  }
  if (existsSync(out)) {
    if (!force) {
      process.stderr.write(c.red(`${out} already exists — pass -y to overwrite\n`));
      return 1;
    }
    unlinkSync(out);
  }

  const vault = Vault.open(cfg.dbPath);
  if (!vault.initialised) {
    process.stderr.write(c.red('vault is not initialised — nothing to export\n'));
    vault.close();
    return 1;
  }
  const count = vault.locked ? null : vault.count();
  mkdirSync(dirname(out), { recursive: true });
  vault.backupTo(out);
  vault.close();

  const kib = (statSync(out).size / 1024).toFixed(0);
  process.stdout.write(
    `${c.green('exported')} ${out} ${c.dim(`(${kib} KiB${count === null ? '' : `, ${count} secrets`})`)}\n`,
  );
  process.stdout.write(
    c.dim('  still encrypted — the same password is required to open it on the other machine\n'),
  );
  return 0;
}

/** Installs an exported vault as this machine's vault. Refuses to clobber by default. */
async function cmdRestore(file: string, force: boolean): Promise<number> {
  await initCrypto();
  const cfg = loadConfig();
  const src = resolve(file);

  if (!existsSync(src)) {
    process.stderr.write(c.red(`no such file: ${src}\n`));
    return 1;
  }
  if (existsSync(cfg.dbPath) && !force) {
    process.stderr.write(
      c.red(`a vault already exists at ${cfg.dbPath} — pass -y to replace it\n`) +
        c.dim('  its secrets are NOT merged; the existing vault is overwritten\n'),
    );
    return 1;
  }

  // Keep a rollback copy, and clear stale WAL/SHM so SQLite cannot pair the new
  // database file with the old journal.
  const backup = existsSync(cfg.dbPath) ? `${cfg.dbPath}.replaced-${Date.now()}` : null;
  if (backup) copyFileSync(cfg.dbPath, backup);
  for (const suffix of ['-wal', '-shm']) {
    const p = `${cfg.dbPath}${suffix}`;
    if (existsSync(p)) unlinkSync(p);
  }

  mkdirSync(dirname(cfg.dbPath), { recursive: true });
  copyFileSync(src, cfg.dbPath);

  const vault = Vault.open(cfg.dbPath);
  const ok = vault.initialised;
  const count = ok ? '(locked — unlock to count)' : '';
  vault.close();

  if (!ok) {
    // Not a vault. Put back whatever was there rather than leaving a broken state.
    if (backup) copyFileSync(backup, cfg.dbPath);
    else unlinkSync(cfg.dbPath);
    process.stderr.write(c.red(`${src} is not a secretd vault — nothing changed\n`));
    return 1;
  }

  process.stdout.write(`${c.green('restored')} ${cfg.dbPath} ${c.dim(count)}\n`);
  if (backup) process.stdout.write(c.dim(`  previous vault kept at ${backup}\n`));
  process.stdout.write(
    `\nNext: ${c.cyan('secrets login')} with the password from the old machine, then ` +
      `${c.cyan('secrets serve')}\n`,
  );
  return 0;
}

// ------------------------------------------------------------------- helpers

function metaFields(v: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (v['desc'] !== undefined) out['description'] = v['desc'];
  if (v['service'] !== undefined) out['service'] = v['service'];
  if (v['env'] !== undefined) out['env'] = v['env'];
  if (v['url'] !== undefined) out['url'] = v['url'];
  if (v['tags'] !== undefined) out['tags'] = String(v['tags']).split(',');
  if (v['aliases'] !== undefined) out['aliases'] = String(v['aliases']).split(',');
  return out;
}

function must(value: string | undefined, usage: string): string {
  if (!value) {
    process.stderr.write(c.red(`usage: secrets ${usage}\n`));
    process.exit(1);
  }
  return value;
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function promptSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      resolve('');
      return;
    }
    process.stdout.write(question);
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    let buf = '';
    const onData = (chunk: Buffer): void => {
      for (const ch of chunk.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(wasRaw);
          stdin.pause();
          stdin.off('data', onData);
          process.stdout.write('\n');
          resolve(buf);
          return;
        }
        if (ch === '\u0003') {
          stdin.setRawMode(wasRaw);
          process.stdout.write('\n');
          process.exit(130);
        }
        if (ch === '\u007f' || ch === '\b') buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    if (err instanceof ApiError) {
      process.stderr.write(c.red(`${err.message}\n`));
      if (err.candidates.length) {
        process.stderr.write(c.dim(`did you mean: ${err.candidates.join(', ')}\n`));
      }
    } else {
      process.stderr.write(c.red(`${err instanceof Error ? err.message : String(err)}\n`));
    }
    process.exitCode = 1;
  });
