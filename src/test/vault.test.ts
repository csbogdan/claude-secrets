import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { initCrypto } from '../vault/crypto.js';
import { Vault, LockedError, ConflictError, NotFoundError } from '../vault/vault.js';
import { parseDotenv, normalisePayload, primaryValue, maskValue, PayloadError } from '../vault/types.js';

const PASS = 'correct horse battery staple';

async function freshVault(): Promise<Vault> {
  await initCrypto();
  const v = Vault.open(':memory:');
  v.init(PASS);
  return v;
}

describe('lifecycle', () => {
  before(async () => initCrypto());

  test('init leaves the vault unlocked and initialised', async () => {
    const v = await freshVault();
    assert.equal(v.initialised, true);
    assert.equal(v.locked, false);
    v.close();
  });

  test('double init is rejected', async () => {
    const v = await freshVault();
    assert.throws(() => v.init(PASS), ConflictError);
    v.close();
  });

  test('unlock accepts the right passphrase and rejects the wrong one', async () => {
    const v = await freshVault();
    v.lock();
    assert.equal(v.locked, true);
    assert.equal(v.unlock('wrong passphrase'), false);
    assert.equal(v.locked, true, 'a failed unlock must not leave a key resident');
    assert.equal(v.unlock(PASS), true);
    assert.equal(v.locked, false);
    v.close();
  });

  test('every operation fails while locked', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'x' });
    v.lock();
    assert.throws(() => v.read('a/b'), LockedError);
    assert.throws(() => v.create({ name: 'c/d', type: 'api_key', value: 'x' }), LockedError);
    assert.throws(() => v.update('a/b', 'y'), LockedError);
    assert.throws(() => v.remove('a/b'), LockedError);
    v.close();
  });

  test('a locked vault does not leak the inventory via list or search', async () => {
    const v = await freshVault();
    v.create({ name: 'acme/prod/db', type: 'api_key', value: 'x', description: 'unmistakable' });
    v.lock();
    // Metadata is unencrypted for FTS5, so these must be key-gated explicitly —
    // otherwise "locked" still tells an unauthenticated caller what you own.
    assert.throws(() => v.list(), LockedError);
    assert.throws(() => v.search('unmistakable'), LockedError);
    assert.throws(() => v.versions('acme/prod/db'), LockedError);
    v.close();
  });
});

describe('crud', () => {
  before(async () => initCrypto());

  test('create then read round-trips the value', async () => {
    const v = await freshVault();
    v.create({
      name: 'github/pat',
      type: 'api_key',
      value: 'ghp_abc123',
      description: 'GitHub personal access token',
      service: 'github',
      tags: ['git', 'ci'],
      aliases: ['gh'],
    });
    const rec = v.read('github/pat');
    assert.deepEqual(rec.value, { value: 'ghp_abc123' });
    assert.equal(rec.service, 'github');
    assert.deepEqual(rec.tags, ['git', 'ci']);
    assert.deepEqual(rec.aliases, ['gh']);
    assert.equal(rec.current_version, 1);
    v.close();
  });

  test('aliases resolve for every operation', async () => {
    const v = await freshVault();
    v.create({ name: 'stripe/test/sk', type: 'api_key', value: 'sk_test_1', aliases: ['stripe-test'] });
    assert.equal(v.read('stripe-test').value['value' as never], 'sk_test_1');
    v.update('stripe-test', 'sk_test_2');
    assert.equal(v.read('stripe/test/sk').value['value' as never], 'sk_test_2');
    v.close();
  });

  test('duplicate names and stolen aliases are rejected', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'x', aliases: ['ab'] });
    assert.throws(() => v.create({ name: 'a/b', type: 'api_key', value: 'y' }), ConflictError);
    assert.throws(
      () => v.create({ name: 'c/d', type: 'api_key', value: 'y', aliases: ['ab'] }),
      ConflictError,
    );
    v.close();
  });

  test('invalid names are rejected', async () => {
    const v = await freshVault();
    for (const bad of ['', ' ', 'has space', 'has$dollar', '/leading']) {
      assert.throws(() => v.create({ name: bad, type: 'api_key', value: 'x' }), /invalid name/);
    }
    v.close();
  });

  test('missing secrets 404 with edit-distance candidates', async () => {
    const v = await freshVault();
    v.create({ name: 'github/pat', type: 'api_key', value: 'x' });
    try {
      v.read('github/pta');
      assert.fail('expected NotFoundError');
    } catch (e) {
      assert.ok(e instanceof NotFoundError);
      assert.deepEqual(e.candidates, ['github/pat']);
      assert.equal(e.status, 404);
    }
    v.close();
  });

  test('delete removes the secret and its search index entry', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'x', description: 'zebra' });
    assert.equal(v.search('zebra').length, 1);
    v.remove('a/b');
    assert.equal(v.count(), 0);
    assert.equal(v.search('zebra').length, 0);
    v.close();
  });

  test('patch edits metadata without creating a version', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'x' });
    const m = v.patch('a/b', { description: 'updated', tags: ['one', 'two'], aliases: ['ab'] });
    assert.equal(m.description, 'updated');
    assert.deepEqual(m.tags, ['one', 'two']);
    assert.deepEqual(m.aliases, ['ab']);
    assert.equal(m.current_version, 1, 'metadata edits must not bump the version');
    v.close();
  });
});

describe('versioning', () => {
  before(async () => initCrypto());

  test('updates create versions and rollback restores an old value', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'v1' });
    assert.equal(v.update('a/b', 'v2', 'rotated'), 2);
    assert.equal(v.update('a/b', 'v3'), 3);
    assert.equal(v.read('a/b').value['value' as never], 'v3');

    const hist = v.versions('a/b');
    assert.equal(hist.length, 3);
    assert.equal(hist[0]!.version, 3);
    assert.equal(hist[0]!.current, true);
    assert.equal(hist[1]!.note, 'rotated');

    const next = v.rollback('a/b', 1);
    assert.equal(next, 4, 'rollback moves forward, it never destroys history');
    assert.equal(v.read('a/b').value['value' as never], 'v1');
    assert.equal(v.versions('a/b').length, 4);
    v.close();
  });

  test('rolling back to a version that never existed fails', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'v1' });
    assert.throws(() => v.rollback('a/b', 9), NotFoundError);
    v.close();
  });

  test('an old version can be read without restoring it', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'v1' });
    v.update('a/b', 'v2');
    v.update('a/b', 'v3');

    const old = v.read('a/b', 1);
    assert.equal(old.value['value' as never], 'v1');
    assert.equal(old.version, 1, 'the record says which version it came from');
    assert.equal(old.current_version, 3, 'reading history leaves current alone');

    // The whole point: looking is not restoring.
    assert.equal(v.versions('a/b').length, 3, 'no version was written by reading one');
    assert.equal(v.read('a/b').value['value' as never], 'v3');
    assert.equal(v.read('a/b').version, 3);

    assert.throws(() => v.read('a/b', 9), NotFoundError);
    v.close();
  });
});

describe('concurrency guards', () => {
  before(async () => initCrypto());

  test('compare-and-swap update refuses to clobber a newer version', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'v1' });

    // Simulates an OAuth refresh that read v1, then awaited the network while the
    // operator rotated the secret to v2. Writing v1-derived data would roll that back.
    const staleVersion = 1;
    v.update('a/b', 'rotated-by-operator');

    assert.equal(v.updateIfVersion('a/b', staleVersion, 'stale-refresh'), null);
    assert.equal(v.read('a/b').value['value' as never], 'rotated-by-operator');

    // Still works when nothing moved underneath.
    assert.equal(v.updateIfVersion('a/b', 2, 'fresh'), 3);
    assert.equal(v.read('a/b').value['value' as never], 'fresh');
    v.close();
  });

  test('lockGeneration changes on every lock and unlock', async () => {
    const v = await freshVault();
    const g0 = v.lockGeneration;
    v.lock();
    const g1 = v.lockGeneration;
    assert.notEqual(g1, g0);
    v.unlock(PASS);
    assert.notEqual(v.lockGeneration, g1);
    // A lock/unlock pair must be detectable — otherwise a handler that awaited across
    // it would see `locked === false` and happily serve pre-lock plaintext.
    assert.notEqual(v.lockGeneration, g0);
    v.close();
  });

  test('a failed init leaves no partial state behind', async () => {
    await initCrypto();
    const v = Vault.open(':memory:');
    v.init(PASS);
    assert.throws(() => v.init('another passphrase'), ConflictError);
    // The rejected init must not have overwritten the salt or verifier.
    v.lock();
    assert.equal(v.unlock('another passphrase'), false);
    assert.equal(v.unlock(PASS), true);
    v.close();
  });
});

describe('crypto binding', () => {
  before(async () => initCrypto());

  test('a ciphertext moved to another version fails to decrypt (AAD binding)', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'v1' });
    v.update('a/b', 'v2');

    // Splice v1's blob into the v2 slot. Without AAD binding this would silently
    // succeed and serve a stale credential as if it were current.
    const db = (v as unknown as { db: import('node:sqlite').DatabaseSync }).db;
    const one = db
      .prepare('SELECT nonce, ciphertext FROM secret_versions WHERE version = 1')
      .get() as { nonce: Uint8Array; ciphertext: Uint8Array };
    db.prepare('UPDATE secret_versions SET nonce = ?, ciphertext = ? WHERE version = 2').run(
      one.nonce,
      one.ciphertext,
    );

    assert.throws(() => v.read('a/b'), /cannot be decrypted/i);
    v.close();
  });

  test('a tampered ciphertext is rejected', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'v1' });
    const db = (v as unknown as { db: import('node:sqlite').DatabaseSync }).db;
    const row = db.prepare('SELECT ciphertext FROM secret_versions WHERE version = 1').get() as {
      ciphertext: Uint8Array;
    };
    const ct = new Uint8Array(row.ciphertext);
    ct[0] = ct[0]! ^ 0xff;
    db.prepare('UPDATE secret_versions SET ciphertext = ? WHERE version = 1').run(ct);
    assert.throws(() => v.read('a/b'));
    v.close();
  });

  test('data survives a lock/unlock cycle', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'persisted' });
    v.lock();
    assert.equal(v.unlock(PASS), true);
    assert.equal(v.read('a/b').value['value' as never], 'persisted');
    v.close();
  });
});

describe('search', () => {
  before(async () => initCrypto());

  async function seeded(): Promise<Vault> {
    const v = await freshVault();
    v.create({
      name: 'stripe/test/sk',
      type: 'api_key',
      value: 'sk_test',
      description: 'Stripe test mode secret key',
      service: 'stripe',
      env: 'test',
      tags: ['payments'],
      aliases: ['stripe-test'],
    });
    v.create({
      name: 'stripe/live/sk',
      type: 'api_key',
      value: 'sk_live',
      description: 'Stripe live mode secret key',
      service: 'stripe',
      env: 'prod',
      tags: ['payments'],
    });
    v.create({
      name: 'postgres/prod',
      type: 'connection_string',
      value: 'postgres://u:p@h/db',
      description: 'Production Postgres database',
      service: 'postgres',
      env: 'prod',
      tags: ['database'],
    });
    return v;
  }

  test('natural language resolves to the right secret', async () => {
    const v = await seeded();
    assert.equal(v.search('the stripe test key')[0]!.name, 'stripe/test/sk');
    assert.equal(v.search('prod postgres database')[0]!.name, 'postgres/prod');
    v.close();
  });

  test('search never returns values', async () => {
    const v = await seeded();
    for (const hit of v.search('stripe')) {
      assert.equal('value' in hit, false, 'search results must not carry plaintext');
    }
    v.close();
  });

  test('stopword-only and empty queries return nothing rather than everything', async () => {
    const v = await seeded();
    assert.deepEqual(v.search('the my secret key'), []);
    assert.deepEqual(v.search(''), []);
    v.close();
  });

  test('fts operators in user input do not blow up the query', async () => {
    const v = await seeded();
    for (const q of ['stripe AND (', 'a" OR b', 'NEAR/3', '*', '^^^']) {
      assert.doesNotThrow(() => v.search(q));
    }
    v.close();
  });

  test('list filters by type, service, env and tag', async () => {
    const v = await seeded();
    assert.equal(v.list({ service: 'stripe' }).length, 2);
    assert.equal(v.list({ env: 'prod' }).length, 2);
    assert.equal(v.list({ type: 'connection_string' }).length, 1);
    assert.equal(v.list({ tag: 'payments' }).length, 2);
    assert.equal(v.list().length, 3);
    v.close();
  });
});

describe('payloads', () => {
  test('bare strings normalise per type', () => {
    assert.deepEqual(normalisePayload('api_key', 'abc'), { value: 'abc' });
    assert.deepEqual(normalisePayload('note', 'hello'), { text: 'hello' });
    assert.deepEqual(normalisePayload('connection_string', 'postgres://x'), { url: 'postgres://x' });
  });

  test('structured payloads validate', () => {
    assert.deepEqual(normalisePayload('env_bundle', 'A=1\nB=2'), { A: '1', B: '2' });

    // A bundle pasted as JSON is a bundle — not .env text to be shredded.
    assert.deepEqual(
      normalisePayload('env_bundle', '{\n  "EMAIL": "me@x.com",\n  "TOKEN": "xxxx=D809AFE3"\n}'),
      { EMAIL: 'me@x.com', TOKEN: 'xxxx=D809AFE3' },
    );

    // Junk that yields no pairs, or keys that are not env var names, must fail loudly
    // rather than storing a mangled bundle over a working credential.
    assert.throws(() => normalisePayload('env_bundle', 'not a dotenv file at all'), PayloadError);
    assert.throws(() => normalisePayload('env_bundle', '"TOKEN": "xxxx=abc"'), PayloadError);

    assert.throws(() => normalisePayload('oauth', { refresh_token: 'r' }), PayloadError);
    assert.doesNotThrow(() => normalisePayload('oauth', { access_token: 'a', expires_at: 123 }));
  });

  test('dotenv parsing handles quotes, exports, comments and = in values', () => {
    const env = parseDotenv(
      ['# comment', 'export A=1', 'B="two"', "C='three'", 'D=', 'URL=postgres://u:p@h/db?x=1', 'junk'].join('\n'),
    );
    assert.deepEqual(env, { A: '1', B: 'two', C: 'three', D: '', URL: 'postgres://u:p@h/db?x=1' });
  });

  test('env bundles round-trip through the vault', async () => {
    const v = await freshVault();
    v.create({ name: 'proj/env', type: 'env_bundle', value: 'A=1\nB=2' });
    assert.deepEqual(v.read('proj/env').value, { A: '1', B: '2' });
    v.close();
  });

  test('primaryValue extracts the scalar, and refuses for env bundles', () => {
    assert.equal(primaryValue('api_key', { value: 'x' }), 'x');
    assert.equal(primaryValue('oauth', { access_token: 'a' }), 'a');
    assert.throws(() => primaryValue('env_bundle', { A: '1' }), PayloadError);
  });

  test('masking keeps a recognisable prefix and suffix', () => {
    assert.equal(maskValue('sk_live_abcdefgh'), 'sk_********efgh');
    assert.equal(maskValue('short'), '*****');
  });
});

describe('audit', () => {
  before(async () => initCrypto());

  test('entries are recorded and queryable, and never contain values', async () => {
    const v = await freshVault();
    v.create({ name: 'a/b', type: 'api_key', value: 'super-secret-value' });
    v.recordAudit('read', true, { secret: 'a/b', caller: 'mcp', source: '127.0.0.1' });
    v.recordAudit('read', false, { secret: 'nope', caller: 'cli', detail: 'not found' });

    const all = v.auditLog({ limit: 10 });
    assert.equal(all.length, 2);
    assert.equal(all.some((e) => e.ok === false), true);
    assert.equal(v.auditLog({ secret: 'a/b' }).length, 1);
    assert.equal(v.auditLog({ action: 'read' }).length, 2);
    assert.equal(JSON.stringify(all).includes('super-secret-value'), false);
    v.close();
  });
});
