import { z } from 'zod';

export const SECRET_TYPES = [
  'api_key',
  'oauth',
  'key_file',
  'connection_string',
  'env_bundle',
  'note',
  'login',
  'card',
  'bank_account',
  'identity',
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

/**
 * `totp` holds either a bare base32 seed or a whole `otpauth://` URI — the URI already
 * carries digits/period/algorithm, so no parallel fields are needed. See vault/totp.ts.
 */
export const LoginPayload = z
  .object({
    username: z.string(),
    password: z.string().optional(),
    totp: z.string().optional(),
    url: z.string().optional(),
    notes: z.string().optional(),
  })
  .refine((v) => Boolean(v.password ?? v.totp), {
    message: 'a login needs a password, a totp seed, or both',
  });

export const CardPayload = z.object({
  number: z.string(),
  expiry: z.string(),
  cvv: z.string().optional(),
  cardholder: z.string().optional(),
  brand: z.string().optional(),
  pin: z.string().optional(),
  postcode: z.string().optional(),
  notes: z.string().optional(),
});

export const BankAccountPayload = z
  .object({
    holder: z.string().optional(),
    bank: z.string().optional(),
    iban: z.string().optional(),
    account_number: z.string().optional(),
    routing_number: z.string().optional(),
    bic: z.string().optional(),
    notes: z.string().optional(),
  })
  .refine((v) => Boolean(v.iban ?? v.account_number), {
    message: 'a bank account needs an iban or an account_number',
  });

export const IdentityPayload = z
  .object({
    full_name: z.string().optional(),
    dob: z.string().optional(),
    email: z.string().optional(),
    phone: z.string().optional(),
    address: z.string().optional(),
    national_id: z.string().optional(),
    passport: z.string().optional(),
    license: z.string().optional(),
    notes: z.string().optional(),
  })
  .refine((v) => Object.values(v).some(Boolean), {
    message: 'an identity needs at least one field',
  });

export const PAYLOAD_SCHEMAS = {
  api_key: ApiKeyPayload,
  oauth: OAuthPayload,
  key_file: KeyFilePayload,
  connection_string: ConnectionStringPayload,
  env_bundle: EnvBundlePayload,
  note: NotePayload,
  login: LoginPayload,
  card: CardPayload,
  bank_account: BankAccountPayload,
  identity: IdentityPayload,
} as const;

export type Payload =
  | z.infer<typeof ApiKeyPayload>
  | z.infer<typeof OAuthPayload>
  | z.infer<typeof KeyFilePayload>
  | z.infer<typeof ConnectionStringPayload>
  | z.infer<typeof EnvBundlePayload>
  | z.infer<typeof NotePayload>
  | z.infer<typeof LoginPayload>
  | z.infer<typeof CardPayload>
  | z.infer<typeof BankAccountPayload>
  | z.infer<typeof IdentityPayload>;

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
    else v = jsonObject(type, v);
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
 * Fields that are not secret in themselves. Used to mask payloads on the way out and to
 * mark inputs in the UI. An allowlist, so a field added later is treated as secret until
 * someone decides otherwise — for a vault that is the right direction to be wrong in.
 */
export const PUBLIC_FIELDS = new Set([
  'host', 'port', 'database', 'user', 'username', 'scopes', 'expires_at', 'fingerprint',
  'brand', 'cardholder', 'expiry', 'bank', 'holder', 'issuer', 'account',
  'digits', 'period', 'algorithm',
]);

const MULTILINE_FIELDS = new Set(['pem', 'text', 'address', 'notes']);

export interface FieldSpec {
  name: string;
  required: boolean;
  multiline: boolean;
  numeric: boolean;
  secret: boolean;
}

/**
 * The shape of a type, derived from its schema so a client can render a real form
 * instead of asking someone to hand-write JSON. Returns [] for `env_bundle`, which is
 * an open record of keys rather than a fixed set of fields.
 */
export function describeType(type: SecretType): FieldSpec[] {
  type ZodLike = { isOptional(): boolean; _def?: { typeName?: string; innerType?: ZodLike } };
  const schema = PAYLOAD_SCHEMAS[type] as unknown as {
    shape?: Record<string, ZodLike>;
    _def?: { schema?: { shape?: Record<string, ZodLike> } };
  };
  // `.refine()` wraps the object one level deeper.
  const shape = schema.shape ?? schema._def?.schema?.shape;
  if (!shape) return [];
  return Object.entries(shape).map(([name, f]) => ({
    name,
    required: !f.isOptional(),
    multiline: MULTILINE_FIELDS.has(name),
    numeric: (f._def?.innerType?._def?.typeName ?? f._def?.typeName) === 'ZodNumber',
    secret: !PUBLIC_FIELDS.has(name),
  }));
}

/** Field names of a payload schema — `.refine()` wraps the object one level deeper. */
function fieldsOf(type: SecretType): string[] {
  const schema = PAYLOAD_SCHEMAS[type] as unknown as {
    shape?: Record<string, unknown>;
    _def?: { schema?: { shape?: Record<string, unknown> } };
  };
  return Object.keys(schema.shape ?? schema._def?.schema?.shape ?? {});
}

/**
 * Types with several fields and no scalar form. A bare string cannot say which field it
 * is, so the only text form is JSON — `secrets set` sends a string whatever you type,
 * which is why this lives here rather than in each client.
 */
function jsonObject(type: SecretType, text: string): unknown {
  const s = text.trim();
  if (!s.startsWith('{')) {
    const fields = fieldsOf(type);
    throw new PayloadError(
      `'${type}' has no single value — pass a JSON object` +
        (fields.length ? ` with fields: ${fields.join(', ')}` : ''),
    );
  }
  try {
    return JSON.parse(s);
  } catch {
    throw new PayloadError(`'${type}' expects a JSON object, and this is not valid JSON`);
  }
}

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
  // parseDotenv is deliberately lenient: it skips whatever it cannot read. On the way
  // *into* the vault that leniency is silent data loss — the second line of a multi-line
  // value, or a stray line, would vanish from a credential. Refuse instead.
  // The offending line is named by number only: it may itself be secret material.
  const bad = text
    .split(/\r?\n/)
    .findIndex((l) => l.trim() && !l.trim().startsWith('#') && l.trim().indexOf('=') <= 0);
  if (bad !== -1) {
    throw new PayloadError(
      `line ${bad + 1} is not KEY=value — an env bundle takes .env text or a JSON object of ` +
        'strings. .env cannot hold a multi-line value; use the JSON form for those',
    );
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
    case 'login':
      if (!p['password']) {
        throw new PayloadError(`login '${String(p['username'])}' has no password — use its totp instead`);
      }
      return String(p['password']);
    case 'card':
      return String(p['number']);
    case 'bank_account':
      return String(p['iban'] ?? p['account_number']);
    case 'env_bundle':
      throw new PayloadError('env_bundle has no single value — expand it into multiple vars');
    case 'identity':
      throw new PayloadError('identity has no single value — read the field you need');
  }
}

export function maskValue(v: string): string {
  if (v.length <= 8) return '*'.repeat(v.length);
  return `${v.slice(0, 3)}${'*'.repeat(Math.min(8, v.length - 7))}${v.slice(-4)}`;
}
