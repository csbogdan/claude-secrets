/**
 * The text form of a payload, and its inverse.
 *
 * These two functions must agree: whatever `fmtValue` puts on screen is what a user
 * edits and hands straight back to `parseValue`. They drifted once — `fmtValue`
 * JSON-printed every type except api_key while `parseValue` passed everything except
 * oauth through as raw text, so saving a note stored the rendered JSON *as the note*:
 *   {"text":"1 cm"}  ->  {"text":"{\n  \"text\": \"1 cm\"\n}"}
 *
 * Mirrors normalisePayload / primaryValue in src/vault/types.ts.
 * Self-check: node dist/ui/payload.js
 */

/** The single field each type collapses to as text. null = no scalar form. */
const PRIMARY = {
  api_key: 'value',
  note: 'text',
  connection_string: 'url',
  key_file: 'pem',
  oauth: 'access_token',
  env_bundle: null,
  login: 'password',
  card: 'number',
  bank_account: null,
  identity: null,
};

/** Several fields, no scalar form — the only text form these have is JSON. */
const OBJECT_ONLY = new Set(['login', 'card', 'bank_account', 'identity']);

export function fmtValue(type, v) {
  if (v === null || v === undefined) return '';
  if (typeof v !== 'object') return String(v);
  if (type === 'env_bundle') {
    const pairs = Object.entries(v);
    // .env has no line continuation, so a value containing a newline cannot be shown as
    // KEY=value without the tail being read back as separate junk lines. Show JSON instead.
    if (pairs.every(([, x]) => !String(x).includes('\n'))) {
      return pairs.map(([k, x]) => `${k}=${x}`).join('\n');
    }
  }
  const field = PRIMARY[type];
  // Bare scalar only when the payload holds nothing else a round-trip would drop.
  if (field && field in v && Object.keys(v).length === 1) return String(v[field]);
  return JSON.stringify(v, null, 2);
}

/** Simple types take a bare string; env_bundle takes .env text; either may arrive as JSON. */
export function parseValue(type, raw) {
  const s = raw.trim();
  if (type === 'env_bundle') return s; // the server's parseDotenv owns this form
  // Hand a non-object straight through: the server owns the error message for it.
  if (OBJECT_ONLY.has(type)) { try { return JSON.parse(s); } catch { return s; } }
  const obj = jsonPayload(type, s);
  if (obj) return obj;
  return type === 'oauth' ? { access_token: s } : s;
}

/**
 * Read back the JSON form fmtValue may have rendered. Requires the type's primary field
 * so free text that merely looks like JSON stays free text.
 *
 * ponytail: a note whose literal text is `{"text":"…"}` is still read as the object form.
 * Add an explicit format toggle to the editor if that ever bites someone.
 */
function jsonPayload(type, s) {
  if (!s.startsWith('{')) return null;
  let o;
  try {
    o = JSON.parse(s);
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  const field = PRIMARY[type];
  return field && field in o ? o : null;
}

// --------------------------------------------------------------------- self-check

if (typeof process !== 'undefined' && process.argv?.[1]?.endsWith('payload.js')) {
  const { default: assert } = await import('node:assert/strict');

  // What the server does with a bare string, so the round-trip can be compared to the payload.
  const rewrap = (type, out) => {
    if (typeof out !== 'string') return out;
    if (out.startsWith('{')) return JSON.parse(out);
    if (type !== 'env_bundle') return { [PRIMARY[type]]: out };
    return Object.fromEntries(
      out
        .split('\n')
        .filter(Boolean)
        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
    );
  };

  const cases = [
    ['api_key', { value: 'sk_test_abc123' }],
    ['note', { text: '1 cm' }],
    ['note', { text: '1 cm=abcd' }],
    ['note', { text: 'multi\nline free text' }],
    ['connection_string', { url: 'postgres://u:p@h:5432/db' }],
    ['connection_string', { url: 'postgres://h/db', user: 'u', port: 5432 }],
    ['key_file', { pem: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----' }],
    ['key_file', { pem: 'x', passphrase: 'p' }],
    ['oauth', { access_token: 'a' }],
    ['oauth', { access_token: 'a', refresh_token: 'r', expires_at: 1700000000 }],
    ['env_bundle', { API_KEY: 'abc', DATABASE_URL: 'postgres://x' }],
    // A multi-line value cannot survive as .env text, so it must be shown as JSON.
    ['env_bundle', { PROJECT: 'acme', CREDS: '-----BEGIN KEY-----\nabc\n-----END-----' }],
    ['login', { username: 'me@x.com', password: 'hunter2', totp: 'JBSWY3DPEHPK3PXP' }],
    ['card', { number: '4111111111111111', expiry: '12/29', cvv: '123' }],
    ['bank_account', { iban: 'DE89370400440532013000', holder: 'B C' }],
    ['identity', { full_name: 'B C', passport: 'X1234567' }],
  ];

  for (const [type, payload] of cases) {
    assert.deepEqual(
      rewrap(type, parseValue(type, fmtValue(type, payload))),
      payload,
      `${type} did not survive fmtValue -> parseValue`,
    );
  }

  // The regression that started this: editing a note must not nest it.
  assert.deepEqual(parseValue('note', fmtValue('note', { text: '1 cm' })), '1 cm');

  // Free text that looks like JSON but is not this type's shape stays text.
  assert.deepEqual(parseValue('note', '{"a":1}'), '{"a":1}');

  // Documented ceiling: free text that *is* this type's object literal is read as the object.
  assert.deepEqual(parseValue('note', '{"text":"x"}'), { text: 'x' });

  console.log(`ok — ${cases.length} payload round-trips`);
}
