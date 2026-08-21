import { z } from 'zod';

export const SECRET_TYPES = [
  'api_key',
  'oauth',
  'key_file',
  'connection_string',
  'env_bundle',
  'note',
] as const;

export type SecretType = (typeof SECRET_TYPES)[number];

export const ApiKeyPayload = z.object({ value: z.string() });

export const OAuthPayload = z.object({
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
  access_token: z.string(),
  refresh_token: z.string().optional(),
  /** Unix seconds. */
  expires_at: z.number().optional(),
  token_url: z.string().optional(),
  scopes: z.string().optional(),
});

export const KeyFilePayload = z.object({
  pem: z.string(),
  passphrase: z.string().optional(),
  fingerprint: z.string().optional(),
});

export const ConnectionStringPayload = z.object({
  url: z.string(),
  host: z.string().optional(),
  port: z.number().optional(),
  user: z.string().optional(),
  password: z.string().optional(),
  database: z.string().optional(),
});

/** Environment variable names. Anything else means the text was not really a .env file. */
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export const EnvBundlePayload = z.record(
  z.string().regex(ENV_KEY_RE, 'not a valid environment variable name'),
  z.string(),
);

export const NotePayload = z.object({ text: z.string() });

export const PAYLOAD_SCHEMAS = {
  api_key: ApiKeyPayload,
  oauth: OAuthPayload,
  key_file: KeyFilePayload,
  connection_string: ConnectionStringPayload,
  env_bundle: EnvBundlePayload,
  note: NotePayload,
} as const;

export type Payload =
  | z.infer<typeof ApiKeyPayload>
  | z.infer<typeof OAuthPayload>
  | z.infer<typeof KeyFilePayload>
  | z.infer<typeof ConnectionStringPayload>
  | z.infer<typeof EnvBundlePayload>
  | z.infer<typeof NotePayload>;

/**
 * Callers may pass a bare string for the simple types instead of the full object.
 * `secrets set github/pat ghp_xxx` should just work.
 */
export function normalisePayload(type: SecretType, value: unknown): Payload {
  let v = value;
  if (typeof v === 'string') {
    if (type === 'api_key') v = { value: v };
    else if (type === 'note') v = { text: v };
    else if (type === 'connection_string') v = { url: v };
    else if (type === 'key_file') v = { pem: v };
    else if (type === 'oauth') v = { access_token: v };
    else if (type === 'env_bundle') v = parseEnvText(v);
  }
  const schema = PAYLOAD_SCHEMAS[type];
  const parsed = schema.safeParse(v);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    throw new PayloadError(`invalid payload for type '${type}' — ${issues}`);
  }
  return parsed.data as Payload;
}

export class PayloadError extends Error {}

/**
 * An env bundle handed over as text. A JSON object is a bundle already — accept it rather
 * than feeding it to the .env parser, which would silently drop every line without an '='
 * and split the rest on the first '=' inside a value.
 *
 * Empty output is an error, not an empty bundle: text went in, so something was meant.
 */
function parseEnvText(text: string): Record<string, string> {
  const s = text.trim();
  if (s.startsWith('{')) {
    try {
      const o: unknown = JSON.parse(s);
      if (o && typeof o === 'object' && !Array.isArray(o)) return o as Record<string, string>;
    } catch {
      // Not JSON after all — fall through and read it as .env text.
    }
  }
  const out = parseDotenv(text);
  if (!Object.keys(out).length) {
    throw new PayloadError(
      'no KEY=value pairs found — an env bundle takes .env text or a JSON object of strings',
    );
  }
  return out;
}

/** Minimal .env parser: KEY=value, ignores blanks/comments, strips matched quotes. */
export function parseDotenv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim().replace(/^export\s+/, '');
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"') && val.length > 1) ||
      (val.startsWith("'") && val.endsWith("'") && val.length > 1)
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

/**
 * The single scalar a consumer wants when injecting into an env var or a command.
 * Env bundles have no single value — callers must expand them instead.
 */
export function primaryValue(type: SecretType, payload: Payload): string {
  const p = payload as Record<string, unknown>;
  switch (type) {
    case 'api_key':
      return String(p['value']);
    case 'oauth':
      return String(p['access_token']);
    case 'key_file':
      return String(p['pem']);
    case 'connection_string':
      return String(p['url']);
    case 'note':
      return String(p['text']);
    case 'env_bundle':
      throw new PayloadError('env_bundle has no single value — expand it into multiple vars');
  }
}

export function maskValue(v: string): string {
  if (v.length <= 8) return '*'.repeat(v.length);
  return `${v.slice(0, 3)}${'*'.repeat(Math.min(8, v.length - 7))}${v.slice(-4)}`;
}
