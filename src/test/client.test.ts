import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SecretdClient } from '../shared/client.js';

/** A stand-in daemon: answers health with `locked`, and serves one api_key secret. */
function fakeDaemon(name: string, locked = false): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    res.setHeader('content-type', 'application/json');
    if (path === '/api/health') return void res.end(JSON.stringify({ ok: true, locked, initialised: true, secrets: 1 }));
    if (locked) return void res.writeHead(423).end(JSON.stringify({ error: 'locked' }));
    if (path === '/api/secret') {
      return void res.end(JSON.stringify({ name: 'k', type: 'api_key', value: { value: `from-${name}` } }));
    }
    res.writeHead(404).end('{}');
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server }),
    ),
  );
}

describe('client failover', () => {
  let replica: { url: string; server: Server };
  let locked: { url: string; server: Server };
  const dead = 'http://127.0.0.1:9'; // discard port: nothing listens there

  before(async () => {
    replica = await fakeDaemon('replica');
    locked = await fakeDaemon('locked', true);
  });
  after(() => {
    replica.server.close();
    locked.server.close();
  });

  test('falls back to the next daemon when the primary is unreachable', async () => {
    const api = new SecretdClient(`${dead},${replica.url}`, 'pw');
    assert.deepEqual((await api.get('k')).value, { value: 'from-replica' });
    assert.equal(api.lastBase, replica.url);
  });

  test('falls back when the primary is locked', async () => {
    const api = new SecretdClient(`${locked.url},${replica.url}`, 'pw');
    assert.deepEqual((await api.get('k')).value, { value: 'from-replica' });
  });

  test('reports every daemon tried when none answers', async () => {
    const api = new SecretdClient(`${dead},http://127.0.0.1:7`, 'pw');
    await assert.rejects(api.get('k'), /127\.0\.0\.1:9 or http:\/\/127\.0\.0\.1:7/);
  });

  test('exec runs the command locally with the value fetched from the daemon', async () => {
    const api = new SecretdClient(replica.url, 'pw');
    const r = await api.exec('sh', ['-c', 'printf "%s|%s" "$K" "$PWD"'], [{ name: 'k', as: 'K' }], {
      cwd: '/tmp',
    });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /^from-replica\|.*tmp$/);
  });
});
