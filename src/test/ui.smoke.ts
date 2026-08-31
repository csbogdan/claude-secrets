import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium, type Browser, type Page } from 'playwright';
import { initCrypto } from '../vault/crypto.js';
import { Vault } from '../vault/vault.js';

/**
 * Drives the real web UI in a real browser against a real daemon.
 *
 * Everything here is throwaway: a vault in a temp dir, its own port, its own password in
 * an env var, deleted on the way out. It never touches ~/.secretd.
 *
 * Separate from the main suite (`npm run test:ui`) because it costs seconds rather than
 * milliseconds, and the fast suite should stay fast enough to run on every save.
 */

const PASS = 'ui-smoke-pass';
const PORT = 7799;
const BASE = `http://127.0.0.1:${PORT}`;
const DAEMON = fileURLToPath(new URL('../daemon/main.js', import.meta.url));

let home: string;
let daemon: ChildProcess;
let browser: Browser;
let page: Page;

async function waitForDaemon(): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${BASE}/api/health`)).ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('daemon did not come up');
}

/** Reads a secret straight from the API, to check what the form actually stored. */
async function stored(name: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${BASE}/api/secret?name=${encodeURIComponent(name)}`);
  assert.ok(res.ok, `reading ${name}: ${res.status}`);
  const body = (await res.json()) as { value: Record<string, unknown> };
  return body.value;
}

async function startNewSecret(name: string, type: string): Promise<void> {
  await page.getByRole('button', { name: '+ New' }).click();
  await page.getByLabel('name', { exact: true }).fill(name);
  await page.selectOption('select', type);
}

describe('web UI', () => {
  before(async () => {
    await initCrypto();
    home = mkdtempSync(join(tmpdir(), 'secretd-ui-'));
    const v = Vault.open(join(home, 'vault.db'));
    v.init(PASS);
    v.close();

    daemon = spawn(process.execPath, ['--no-warnings', DAEMON], {
      env: {
        ...process.env,
        SECRETD_HOME: home,
        SECRETD_PORT: String(PORT),
        SECRETD_HOST: '127.0.0.1',
        SECRETD_PASSWORD: PASS,
        SECRETD_NO_KEYCHAIN: '1',
        SECRETD_NO_AUTH: '1',
      },
      stdio: 'ignore',
    });
    await waitForDaemon();

    browser = await chromium.launch();
    page = await browser.newPage();
    // A thrown exception in the UI must fail the test, not disappear into the console.
    page.on('pageerror', (err) => assert.fail(`uncaught in page: ${err.message}`));
    await page.goto(BASE);
  });

  after(async () => {
    await browser?.close();
    daemon?.kill();
    if (home) rmSync(home, { recursive: true, force: true });
  });

  test('a login is created from labelled fields, with no JSON typed anywhere', async () => {
    await startNewSecret('site/login', 'login');

    await page.getByLabel('username').fill('me@example.com');
    await page.getByLabel('password').fill('hunter2');
    await page.getByLabel('totp').fill('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    await page.getByRole('button', { name: 'Create' }).click();
    await page.getByText('site/login').first().waitFor();

    assert.deepEqual(await stored('site/login'), {
      username: 'me@example.com',
      password: 'hunter2',
      totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    });
  });

  test('the 2FA button turns that seed into a code', async () => {
    await page.getByText('site/login').first().click();
    await page.getByRole('button', { name: '2FA code' }).click();
    // The button relabels itself to the code, so it has to be found by the new text.
    const code = page.locator('button').filter({ hasText: /^\d{6} \(\d+s\)$/ });
    await code.waitFor({ timeout: 5000 });
    assert.match(await code.innerText(), /^\d{6} \(\d+s\)$/, 'shows the code and its life');
  });

  test('an env bundle is built from rows, not from .env text', async () => {
    await startNewSecret('proj/env', 'env_bundle');

    await page.getByPlaceholder('KEY', { exact: true }).nth(0).fill('API_KEY');
    await page.getByPlaceholder('value', { exact: true }).nth(0).fill('abc123');
    await page.getByRole('button', { name: 'Add key' }).click();
    await page.getByPlaceholder('KEY', { exact: true }).nth(1).fill('DATABASE_URL');
    await page.getByPlaceholder('value', { exact: true }).nth(1).fill('postgres://u:p@h/db');
    await page.getByRole('button', { name: 'Create' }).click();
    await page.getByText('proj/env').first().waitFor();

    assert.deepEqual(await stored('proj/env'), {
      API_KEY: 'abc123',
      DATABASE_URL: 'postgres://u:p@h/db',
    });
  });

  test('a row value may contain newlines, which .env text could never carry', async () => {
    await startNewSecret('proj/creds', 'env_bundle');

    await page.getByPlaceholder('KEY', { exact: true }).nth(0).fill('PRIVATE_KEY');
    await page.getByPlaceholder('value', { exact: true }).nth(0).fill('-----BEGIN-----\nabc\ndef\n-----END-----');
    await page.getByRole('button', { name: 'Create' }).click();
    await page.getByText('proj/creds').first().waitFor();

    assert.deepEqual(await stored('proj/creds'), {
      PRIVATE_KEY: '-----BEGIN-----\nabc\ndef\n-----END-----',
    });
  });

  test('a secret can be hidden from the list, and brought back', async () => {
    // Scoped to #list on purpose: the name also appears in the live activity feed, which
    // is a log of what happened and not somewhere hiding should rewrite history.
    const inList = page.locator('#list').getByText('site/login');

    await inList.click();
    await page.getByRole('button', { name: 'Hide', exact: true }).click();
    await page.getByText('Hidden.').waitFor({ timeout: 5000 });
    await inList.waitFor({ state: 'detached', timeout: 5000 });

    // Still fully readable over the API — a screen-sharing courtesy, not access control.
    assert.equal((await stored('site/login')).username, 'me@example.com');

    await page.getByRole('button', { name: 'Show hidden' }).click();
    await inList.waitFor({ timeout: 5000 });
    await inList.click();
    await page.getByRole('button', { name: 'Unhide' }).click();
    await page.getByRole('button', { name: 'Showing hidden' }).click();
    await inList.waitFor({ timeout: 5000 });
  });

  test('a required field the form left empty is refused by the server, not stored half-made', async () => {
    await startNewSecret('bank/card', 'card');

    await page.getByLabel('number').fill('4111111111111111');
    // expiry is required and deliberately left blank.
    await page.getByRole('button', { name: 'Create' }).click();

    await page.getByText(/expiry/i).first().waitFor({ timeout: 5000 });
    const res = await fetch(`${BASE}/api/secret?name=bank/card`);
    assert.equal(res.status, 404, 'nothing was stored');
  });
});
