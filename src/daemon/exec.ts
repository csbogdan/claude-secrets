import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Vault } from '../vault/vault.js';
import { primaryValue, type SecretType, type Payload } from '../vault/types.js';
import { totpFrom } from '../vault/totp.js';
import { log } from './log.js';

export type InjectMode = 'env' | 'file' | 'stdin' | 'totp';

export const INJECT_MODES: readonly InjectMode[] = ['env', 'file', 'stdin', 'totp'];

export interface SecretMapping {
  name: string;
  /** Env var name (env/file modes). Defaults to the secret name upper-snake-cased. */
  as?: string;
  mode?: InjectMode;
}

export interface ExecResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

const MAX_OUTPUT = 200_000;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function envNameFor(secretName: string): string {
  return secretName
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}

/**
 * Runs a command with secrets materialised into its environment, a 0600 temp file,
 * or its stdin — so values reach the child process without ever entering the
 * model's context. Temp files are removed when the child exits.
 *
 * `{{secret-name}}` placeholders in argv are substituted with the temp file path
 * (file mode) or the value itself (env mode), which is what makes things like
 * `ssh -i {{deploy-key}}` work.
 */
export async function runWithSecrets(
  vault: Vault,
  command: string,
  args: string[],
  mappings: SecretMapping[],
  opts: { cwd?: string; timeoutMs?: number; caller?: string; source?: string } = {},
): Promise<ExecResult> {
  // The child inherits our environment, which on this daemon can hold the master
  // passphrase and the API token. Neither belongs in an arbitrary subprocess.
  const env: Record<string, string> = { ...(process.env as Record<string, string>) };
  for (const k of ['SECRETD_PASSPHRASE', 'SECRETD_TOKEN']) delete env[k];
  const stdinParts: string[] = [];
  const substitutions = new Map<string, string>();
  let tmpDir: string | null = null;
  let fileIndex = 0;

  try {
    for (const m of mappings) {
      const rec = vault.read(m.name);
      const mode: InjectMode = m.mode ?? 'env';
      // Validated here rather than in each client: an unknown mode used to fall through
      // to 'env', which since totp mode exists would inject the password where the
      // caller asked for a one-time code.
      if (!INJECT_MODES.includes(mode)) {
        throw new Error(`unknown inject mode '${mode}' — one of: ${INJECT_MODES.join(', ')}`);
      }
      const type = rec.type as SecretType;
      const payload = rec.value as Payload;

      if (type === 'env_bundle') {
        // A bundle has no single value — expand every key into the environment.
        for (const [k, v] of Object.entries(payload as Record<string, string>)) env[k] = v;
        vault.recordAudit('exec', true, {
          secret: m.name,
          caller: opts.caller,
          source: opts.source,
          detail: 'env_bundle expanded',
        });
        continue;
      }

      // totp mode injects a generated code, not the stored secret.
      // ponytail: the code is only valid for its window (30s by default), so this suits a
      // command that authenticates immediately and not one that reads the variable later.
      const value =
        mode === 'totp' ? totpValue(payload, m.name) : primaryValue(type, payload);
      const varName = m.as ?? envNameFor(m.name);
      if (!ENV_NAME_RE.test(varName)) {
        throw new Error(
          `invalid 'as' value '${varName}' — must be a valid environment variable name`,
        );
      }

      if (mode === 'file') {
        tmpDir ??= mkdtempSync(join(tmpdir(), 'secretd-'));
        // Filename is derived from the loop index, never from caller input, so no
        // mapping can steer the write outside tmpDir. 'wx' refuses to follow an
        // existing file or symlink, where mode 0600 would not have applied.
        const path = join(tmpDir, `s${fileIndex++}`);
        writeFileSync(path, value.endsWith('\n') ? value : `${value}\n`, {
          mode: 0o600,
          flag: 'wx',
        });
        env[varName] = path;
        substitutions.set(m.name, path);
      } else if (mode === 'stdin') {
        stdinParts.push(value);
      } else {
        env[varName] = value;
        substitutions.set(m.name, value);
      }

      vault.recordAudit('exec', true, {
        secret: m.name,
        caller: opts.caller,
        source: opts.source,
        detail: `injected as ${mode}`,
      });
    }

    const finalArgs = args.map((a) =>
      a.replace(/\{\{([^}]+)\}\}/g, (whole, key: string) => substitutions.get(key.trim()) ?? whole),
    );

    log.info(`exec ${command} with ${mappings.length} secret(s)`, {
      action: 'exec',
      caller: opts.caller,
      source: opts.source,
    });

    return await new Promise<ExecResult>((resolve, reject) => {
      const child = spawn(command, finalArgs, {
        cwd: opts.cwd,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        // Own process group, so a timeout can reap the whole tree. A shell that
        // backgrounds a descendant would otherwise leave it running with the injected
        // secrets in its environment, and holding our output pipes open past the timeout.
        detached: true,
      });
      let stdout = '';
      let stderr = '';
      let truncated = false;
      let timer: NodeJS.Timeout | null = null;

      const append = (buf: Buffer, which: 'out' | 'err'): void => {
        const s = buf.toString();
        if (which === 'out') {
          if (stdout.length < MAX_OUTPUT) stdout += s;
          else truncated = true;
        } else if (stderr.length < MAX_OUTPUT) stderr += s;
        else truncated = true;
      };

      child.stdout.on('data', (b: Buffer) => append(b, 'out'));
      child.stderr.on('data', (b: Buffer) => append(b, 'err'));
      child.on('error', (err) => {
        if (timer) clearTimeout(timer);
        reject(err);
      });
      child.on('close', (code, signal) => {
        if (timer) clearTimeout(timer);
        resolve({
          code,
          signal,
          stdout: stdout.slice(0, MAX_OUTPUT),
          stderr: stderr.slice(0, MAX_OUTPUT),
          truncated,
        });
      });

      if (stdinParts.length) child.stdin.write(stdinParts.join('\n'));
      child.stdin.end();

      if (opts.timeoutMs && opts.timeoutMs > 0) {
        timer = setTimeout(() => {
          // We spawned this tree ourselves, so terminating it is ours to do.
          // Negative pid targets the whole process group, not just the direct child.
          try {
            if (child.pid) process.kill(-child.pid, 'SIGKILL');
          } catch {
            child.kill('SIGKILL');
          }
        }, opts.timeoutMs);
      }
    });
  } finally {
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** The current code for a payload carrying a totp seed. */
function totpValue(payload: Payload, name: string): string {
  const spec = (payload as Record<string, unknown>)['totp'];
  if (typeof spec !== 'string' || !spec.trim()) {
    throw new Error(`secret '${name}' has no totp seed, so ':totp' has nothing to generate`);
  }
  return totpFrom(spec).code;
}
