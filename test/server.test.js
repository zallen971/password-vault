import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { startServer, fakeCredentials, fakeRecord } from './helpers.js';

const uuid = () => crypto.randomUUID();

describe('accounts and sessions', () => {
  let server;
  before(async () => {
    server = await startServer();
  });
  after(() => server.close());

  test('sign-ups are open only until the first account exists', async () => {
    assert.equal((await server.request('GET', '/api/config')).body.signupsOpen, true);

    const creds = fakeCredentials('first@example.com');
    const created = await server.request('POST', '/api/auth/register', { body: creds });
    assert.equal(created.status, 200);
    assert.ok(created.body.token);
    assert.equal(created.body.account.email, 'first@example.com');
    assert.equal(created.body.account.protectedKey, creds.protectedKey);
    assert.equal(created.body.account.auth, undefined, 'the credential hash must never be returned');

    assert.equal((await server.request('GET', '/api/config')).body.signupsOpen, false);
    const second = await server.request('POST', '/api/auth/register', { body: fakeCredentials('second@example.com') });
    assert.equal(second.status, 403);
    assert.equal(second.body.error, 'signups_closed');
  });

  test('signing in needs the right auth key', async () => {
    const creds = fakeCredentials('first@example.com');
    const wrong = await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.body.error, 'invalid_credentials');

    const unknown = await server.request('POST', '/api/auth/login', { body: { email: 'nobody@example.com', authKey: creds.authKey } });
    assert.equal(unknown.status, 401);
    assert.deepEqual(unknown.body, wrong.body, 'unknown accounts must be indistinguishable from wrong passwords');
  });

  test('prelogin does not reveal which accounts exist', async () => {
    const known = await server.request('POST', '/api/auth/prelogin', { body: { email: 'FIRST@example.com ' } });
    const ghost = await server.request('POST', '/api/auth/prelogin', { body: { email: 'ghost@example.com' } });
    const ghostAgain = await server.request('POST', '/api/auth/prelogin', { body: { email: 'ghost@example.com' } });
    assert.equal(known.status, 200);
    assert.equal(ghost.status, 200);
    assert.deepEqual(Object.keys(known.body).sort(), Object.keys(ghost.body).sort());
    assert.deepEqual(known.body.kdf, ghost.body.kdf);
    assert.equal(Buffer.from(ghost.body.salt, 'base64').length, 16);
    assert.deepEqual(ghost.body, ghostAgain.body, 'the decoy salt must be stable');
    assert.notEqual(ghost.body.salt, known.body.salt);
  });

  test('vault routes require a live session', async () => {
    for (const [method, route] of [['GET', '/api/vault'], ['GET', '/api/vault/revision'], ['POST', '/api/vault/sync'], ['POST', '/api/auth/logout']]) {
      const anonymous = await server.request(method, route, method === 'POST' ? { body: {} } : {});
      assert.equal(anonymous.status, 401, `${method} ${route}`);
      const forged = await server.request(method, route, { token: 'x'.repeat(43), ...(method === 'POST' ? { body: {} } : {}) });
      assert.equal(forged.status, 401, `${method} ${route} with a made-up token`);
    }
  });

  test('rejects malformed registrations', async () => {
    const open = await startServer({ allowSignups: true });
    try {
      const good = fakeCredentials('a@example.com');
      const cases = {
        'no email': { ...good, email: '' },
        'bad email': { ...good, email: 'not-an-email' },
        'weak kdf': { ...good, kdf: { ...good.kdf, iterations: 1000 } },
        'unknown kdf': { ...good, kdf: { name: 'MD5', hash: 'SHA-256', iterations: 600000 } },
        'short salt': { ...good, salt: 'AAAA' },
        'short auth key': { ...good, authKey: 'AAAA' },
        'auth key not base64': { ...good, authKey: '!'.repeat(44) },
        'missing protected key': { ...good, protectedKey: undefined },
      };
      for (const [name, body] of Object.entries(cases)) {
        const response = await open.request('POST', '/api/auth/register', { body });
        assert.equal(response.status, 400, name);
      }
      assert.equal((await open.request('POST', '/api/auth/register', { body: good })).status, 200);
      const duplicate = await open.request('POST', '/api/auth/register', { body: { ...fakeCredentials('A@Example.com') } });
      assert.equal(duplicate.status, 409, 'addresses are case-insensitive');
    } finally {
      await open.close();
    }
  });

  test('only JSON bodies are accepted', async () => {
    const response = await server.request('POST', '/api/auth/prelogin', {
      body: 'email=first@example.com',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(response.status, 415);
    const broken = await server.request('POST', '/api/auth/prelogin', { body: '{"email":', headers: { 'Content-Type': 'application/json' } });
    assert.equal(broken.status, 400);
  });

  test('unknown routes and methods', async () => {
    assert.equal((await server.request('GET', '/api/nope')).status, 404);
    const wrongMethod = await server.request('DELETE', '/api/vault');
    assert.equal(wrongMethod.status, 405);
    assert.equal(wrongMethod.headers.get('allow'), 'GET');
    assert.equal((await server.request('GET', '/api/__proto__')).status, 404);
    assert.equal((await server.request('GET', '/api/constructor')).status, 404);
  });
});

describe('vault sync', () => {
  let server;
  let token;
  const creds = fakeCredentials('sync@example.com');

  before(async () => {
    server = await startServer();
    token = (await server.request('POST', '/api/auth/register', { body: creds })).body.token;
  });
  after(() => server.close());

  const sync = (body, withToken = token) => server.request('POST', '/api/vault/sync', { body, token: withToken });
  const vault = async () => (await server.request('GET', '/api/vault', { token })).body;

  test('starts empty', async () => {
    assert.deepEqual(await vault(), { revision: 0, records: [] });
  });

  test('creates, updates and deletes records with revision checks', async () => {
    const id = uuid();
    const first = fakeRecord();
    const created = await sync({ upserts: [{ id, data: first, baseRev: null }] });
    assert.equal(created.status, 200);
    assert.equal(created.body.revision, 1);
    assert.deepEqual((await vault()).records, [{ id, data: first, rev: 1 }]);

    const second = fakeRecord();
    const updated = await sync({ upserts: [{ id, data: second, baseRev: 1 }] });
    assert.equal(updated.body.revision, 2);

    // A second device still holding revision 1 must not overwrite revision 2.
    const stale = await sync({ upserts: [{ id, data: fakeRecord(), baseRev: 1 }] });
    assert.equal(stale.status, 409);
    assert.deepEqual(stale.body.conflicts, [id]);
    assert.equal((await vault()).records[0].data, second);

    // Creating something that already exists is also a conflict.
    assert.equal((await sync({ upserts: [{ id, data: fakeRecord(), baseRev: null }] })).status, 409);
    // So is deleting a version that has since changed.
    assert.equal((await sync({ deletes: [{ id, baseRev: 1 }] })).status, 409);

    const deleted = await sync({ deletes: [{ id, baseRev: 2 }] });
    assert.equal(deleted.body.revision, 3);
    assert.deepEqual((await vault()).records, []);

    // Updating a record another device deleted is a conflict; deleting it again is fine.
    assert.equal((await sync({ upserts: [{ id, data: fakeRecord(), baseRev: 2 }] })).status, 409);
    assert.equal((await sync({ deletes: [{ id, baseRev: 2 }] })).status, 200);
  });

  test('a batch is all-or-nothing', async () => {
    const existing = uuid();
    await sync({ upserts: [{ id: existing, data: fakeRecord(), baseRev: null }] });
    const before = await vault();

    const fresh = uuid();
    const mixed = await sync({
      upserts: [
        { id: fresh, data: fakeRecord(), baseRev: null },
        { id: existing, data: fakeRecord(), baseRev: 999 },
      ],
    });
    assert.equal(mixed.status, 409);
    assert.deepEqual(await vault(), before, 'nothing from a conflicting batch may be applied');
    await sync({ deletes: [{ id: existing, baseRev: before.records[0].rev }] });
  });

  test('rejects malformed changes', async () => {
    const good = { id: uuid(), data: fakeRecord(), baseRev: null };
    const cases = {
      'id is not a uuid': { upserts: [{ ...good, id: 'abc' }] },
      'prototype key as id': { upserts: [{ ...good, id: '__proto__' }] },
      'data is not base64': { upserts: [{ ...good, data: '<script>alert(1)</script>'.padEnd(64, '!') }] },
      'data too short': { upserts: [{ ...good, data: 'AAAA' }] },
      'negative revision': { upserts: [{ ...good, baseRev: -1 }] },
      'fractional revision': { upserts: [{ ...good, baseRev: 1.5 }] },
      'duplicate ids': { upserts: [good, good] },
      'same id upserted and deleted': { upserts: [good], deletes: [{ id: good.id }] },
      'upserts is not a list': { upserts: 'everything' },
    };
    for (const [name, body] of Object.entries(cases)) {
      assert.equal((await sync(body)).status, 400, name);
    }
    assert.deepEqual((await vault()).records, []);
  });

  test('enforces size limits', async () => {
    const small = await startServer({ limits: { recordChars: 200, records: 3, batchSize: 5, syncBody: 4096 } });
    try {
      const t = (await small.request('POST', '/api/auth/register', { body: fakeCredentials() })).body.token;
      const post = (body) => small.request('POST', '/api/vault/sync', { body, token: t });

      assert.equal((await post({ upserts: [{ id: uuid(), data: fakeRecord(300), baseRev: null }] })).body.error, 'record_too_large');
      const many = Array.from({ length: 6 }, () => ({ id: uuid(), data: fakeRecord(60), baseRev: null }));
      assert.equal((await post({ upserts: many })).body.error, 'batch_too_large');
      assert.equal((await post({ upserts: many.slice(0, 4) })).body.error, 'vault_full');
      assert.equal((await post({ upserts: many.slice(0, 3) })).status, 200);
      assert.equal((await post({ upserts: [{ id: uuid(), data: 'A'.repeat(8000), baseRev: null }] })).status, 413);
    } finally {
      await small.close();
    }
  });

  test('accounts cannot see or touch each other', async () => {
    const shared = await startServer({ allowSignups: true });
    try {
      const alice = (await shared.request('POST', '/api/auth/register', { body: fakeCredentials('alice@example.com') })).body.token;
      const bob = (await shared.request('POST', '/api/auth/register', { body: fakeCredentials('bob@example.com') })).body.token;
      const id = uuid();
      await shared.request('POST', '/api/vault/sync', { token: alice, body: { upserts: [{ id, data: fakeRecord(), baseRev: null }] } });

      assert.deepEqual((await shared.request('GET', '/api/vault', { token: bob })).body.records, []);
      // Bob "deleting" Alice's record id only affects his own (empty) vault.
      await shared.request('POST', '/api/vault/sync', { token: bob, body: { deletes: [{ id }] } });
      assert.equal((await shared.request('GET', '/api/vault', { token: alice })).body.records.length, 1);
    } finally {
      await shared.close();
    }
  });

  test('signing out ends the session', async () => {
    const login = await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } });
    const session = login.body.token;
    assert.equal((await server.request('GET', '/api/vault/revision', { token: session })).status, 200);
    assert.equal((await server.request('POST', '/api/auth/logout', { token: session })).status, 204);
    assert.equal((await server.request('GET', '/api/vault/revision', { token: session })).status, 401);
    assert.equal((await server.request('GET', '/api/vault/revision', { token })).status, 200, 'other sessions are unaffected');
  });
});

describe('brute-force protection', () => {
  test('locks out repeated wrong guesses, then recovers', async () => {
    const server = await startServer({ limits: { loginFailuresPerPair: 3, loginWindowMs: 400 } });
    try {
      const creds = fakeCredentials('target@example.com');
      await server.request('POST', '/api/auth/register', { body: creds });
      const attempt = (authKey) => server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey } });
      const wrong = fakeCredentials().authKey;

      for (let i = 0; i < 3; i += 1) assert.equal((await attempt(wrong)).status, 401);
      const blocked = await attempt(creds.authKey);
      assert.equal(blocked.status, 429, 'even the right key is refused while locked out');
      assert.equal(blocked.body.error, 'too_many_attempts');
      assert.ok(Number(blocked.headers.get('retry-after')) >= 1);

      await new Promise((resolve) => setTimeout(resolve, 450));
      assert.equal((await attempt(creds.authKey)).status, 200);
    } finally {
      await server.close();
    }
  });

  test('a burst of parallel guesses cannot exceed the limit', async () => {
    const server = await startServer({ limits: { loginFailuresPerPair: 5 } });
    try {
      const creds = fakeCredentials('burst@example.com');
      await server.request('POST', '/api/auth/register', { body: creds });
      const responses = await Promise.all(
        Array.from({ length: 20 }, () =>
          server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: fakeCredentials().authKey } }),
        ),
      );
      const checked = responses.filter((r) => r.status === 401).length;
      assert.equal(checked, 5, 'only the allowed number of guesses may reach the password check');
      assert.equal(responses.filter((r) => r.status === 429).length, 15);
    } finally {
      await server.close();
    }
  });

  test('successful sign-ins do not use up the allowance', async () => {
    const server = await startServer({ limits: { loginFailuresPerPair: 3, loginFailuresPerEmail: 3, loginFailuresPerIp: 3 } });
    try {
      const creds = fakeCredentials('steady@example.com');
      await server.request('POST', '/api/auth/register', { body: creds });
      for (let i = 0; i < 8; i += 1) {
        const ok = await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } });
        assert.equal(ok.status, 200);
      }
    } finally {
      await server.close();
    }
  });
});

describe('account changes', () => {
  test('changing the master password replaces credentials and signs out other devices', async () => {
    const server = await startServer();
    try {
      const creds = fakeCredentials('change@example.com');
      const first = (await server.request('POST', '/api/auth/register', { body: creds })).body.token;
      const other = (await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } })).body.token;
      const next = fakeCredentials(creds.email);
      const change = { authKey: creds.authKey, newAuthKey: next.authKey, kdf: next.kdf, salt: next.salt, protectedKey: next.protectedKey };

      const refused = await server.request('POST', '/api/account/password', { token: first, body: { ...change, authKey: next.authKey } });
      assert.equal(refused.status, 401, 'the current password must be proven');

      const changed = await server.request('POST', '/api/account/password', { token: first, body: change });
      assert.equal(changed.status, 200);
      assert.equal(changed.body.account.salt, next.salt);
      assert.equal(changed.body.account.protectedKey, next.protectedKey);

      assert.equal((await server.request('GET', '/api/vault', { token: first })).status, 401);
      assert.equal((await server.request('GET', '/api/vault', { token: other })).status, 401);
      assert.equal((await server.request('GET', '/api/vault', { token: changed.body.token })).status, 200);

      const oldLogin = await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } });
      assert.equal(oldLogin.status, 401);
      const newLogin = await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: next.authKey } });
      assert.equal(newLogin.status, 200);
      const prelogin = await server.request('POST', '/api/auth/prelogin', { body: { email: creds.email } });
      assert.equal(prelogin.body.salt, next.salt);
    } finally {
      await server.close();
    }
  });

  test('deleting an account removes its data and reopens sign-ups', async () => {
    const server = await startServer();
    try {
      const creds = fakeCredentials('gone@example.com');
      const token = (await server.request('POST', '/api/auth/register', { body: creds })).body.token;
      await server.request('POST', '/api/vault/sync', { token, body: { upserts: [{ id: uuid(), data: fakeRecord(), baseRev: null }] } });
      const accountsDir = path.join(server.dataDir, 'accounts');
      assert.equal((await readdir(accountsDir)).length, 1);

      const refused = await server.request('POST', '/api/account/delete', { token, body: { authKey: fakeCredentials().authKey } });
      assert.equal(refused.status, 401);
      assert.equal((await server.request('POST', '/api/account/delete', { token, body: { authKey: creds.authKey } })).status, 204);

      assert.deepEqual(await readdir(accountsDir), []);
      assert.equal((await server.request('GET', '/api/vault', { token })).status, 401);
      assert.equal((await server.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } })).status, 401);
      assert.equal((await server.request('GET', '/api/config')).body.signupsOpen, true);
    } finally {
      await server.close();
    }
  });
});

describe('storage', () => {
  test('data survives a restart; sessions do not', async () => {
    const first = await startServer();
    const creds = fakeCredentials('durable@example.com');
    const token = (await first.request('POST', '/api/auth/register', { body: creds })).body.token;
    const id = uuid();
    const data = fakeRecord();
    await first.request('POST', '/api/vault/sync', { token, body: { upserts: [{ id, data, baseRev: null }] } });
    await first.close({ keepData: true });

    const second = await startServer({ dataDir: first.dataDir });
    try {
      assert.equal((await second.request('GET', '/api/vault', { token })).status, 401);
      assert.equal((await second.request('GET', '/api/config')).body.signupsOpen, false);
      const login = await second.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } });
      assert.equal(login.status, 200);
      const vault = await second.request('GET', '/api/vault', { token: login.body.token });
      assert.deepEqual(vault.body, { revision: 1, records: [{ id, data, rev: 1 }] });
    } finally {
      await second.close();
    }
  });

  test('files are private and hold no plaintext credentials', async () => {
    const server = await startServer();
    try {
      const creds = fakeCredentials('files@example.com');
      await server.request('POST', '/api/auth/register', { body: creds });
      const dir = path.join(server.dataDir, 'accounts');
      const [name] = await readdir(dir);
      const file = path.join(dir, name);
      if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o077, 0, 'account files must not be group/world readable');
      const contents = await readFile(file, 'utf8');
      assert.ok(!contents.includes(creds.authKey), 'the auth key must be stored only as a hash');
      assert.deepEqual((await readdir(dir)).filter((n) => n.endsWith('.tmp')), []);
    } finally {
      await server.close();
    }
  });

  test('keeps a snapshot from before the first change of the day', async () => {
    const first = await startServer();
    const creds = fakeCredentials('snapshot@example.com');
    const token = (await first.request('POST', '/api/auth/register', { body: creds })).body.token;
    const original = { id: uuid(), data: fakeRecord(), baseRev: null };
    await first.request('POST', '/api/vault/sync', { token, body: { upserts: [original] } });
    await first.close({ keepData: true });

    // A fresh process has not taken today's snapshot yet, so its first write does.
    const second = await startServer({ dataDir: first.dataDir });
    try {
      const login = await second.request('POST', '/api/auth/login', { body: { email: creds.email, authKey: creds.authKey } });
      await second.request('POST', '/api/vault/sync', { token: login.body.token, body: { deletes: [{ id: original.id, baseRev: 1 }] } });

      const backups = path.join(second.dataDir, 'backups', login.body.account.id);
      const [snapshot] = await readdir(backups);
      assert.match(snapshot, /^\d{4}-\d{2}-\d{2}\.json$/);
      const saved = JSON.parse(await readFile(path.join(backups, snapshot), 'utf8'));
      assert.equal(saved.records[original.id].data, original.data, 'the snapshot still holds the deleted record');
    } finally {
      await second.close();
    }
  });

  test('an unreadable account file keeps sign-ups closed and is left alone', async () => {
    const first = await startServer();
    await first.request('POST', '/api/auth/register', { body: fakeCredentials('corrupt@example.com') });
    const dir = path.join(first.dataDir, 'accounts');
    const [name] = await readdir(dir);
    await first.close({ keepData: true });

    const { writeFile } = await import('node:fs/promises');
    await writeFile(path.join(dir, name), '{"id": "trunc');
    const originalError = console.error;
    console.error = () => {};
    const second = await startServer({ dataDir: first.dataDir });
    console.error = originalError;
    try {
      assert.equal((await second.request('GET', '/api/config')).body.signupsOpen, false);
      assert.equal(await readFile(path.join(dir, name), 'utf8'), '{"id": "trunc');
    } finally {
      await second.close();
    }
  });
});

describe('web app delivery', () => {
  let server;
  before(async () => {
    server = await startServer();
  });
  after(() => server.close());

  test('serves the app with strict security headers', async () => {
    const response = await fetch(`${server.url}/`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /^text\/html/);
    const csp = response.headers.get('content-security-policy');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'(;|$)/);
    assert.ok(!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'));
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(response.headers.get('cache-control'), 'no-cache');
    assert.equal(response.headers.get('strict-transport-security'), null, 'no HSTS over plain http');
  });

  test('revalidates with ETags', async () => {
    const first = await fetch(`${server.url}/css/app.css`);
    const etag = first.headers.get('etag');
    assert.ok(etag);
    const second = await fetch(`${server.url}/css/app.css`, { headers: { 'If-None-Match': etag } });
    assert.equal(second.status, 304);
  });

  test('does not serve files outside the public directory', async () => {
    const attempts = [
      '/../package.json',
      '/..%2fpackage.json',
      '/%2e%2e/package.json',
      '/..%5cpackage.json',
      '/js/../../server/app.js',
      '/js/..%2f..%2fserver%2fapp.js',
      '/.gitignore',
      '/%00',
      '/js/',
      '/js',
    ];
    for (const attempt of attempts) {
      // Use a raw request so the client does not normalise the path first.
      const { status, body } = await rawGet(server.url, attempt);
      assert.equal(status, 404, attempt);
      assert.ok(!body.includes('"scripts"') && !body.includes('createApp'), attempt);
    }
  });

  test('API responses are never cached', async () => {
    const response = await fetch(`${server.url}/api/config`);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  test('marks forwarded HTTPS as secure only when the proxy is trusted', async () => {
    const plain = await fetch(`${server.url}/api/config`, { headers: { 'X-Forwarded-Proto': 'https' } });
    assert.equal(plain.headers.get('strict-transport-security'), null);

    const proxied = await startServer({ trustProxy: true });
    try {
      const response = await fetch(`${proxied.url}/api/config`, { headers: { 'X-Forwarded-Proto': 'https' } });
      assert.match(response.headers.get('strict-transport-security'), /max-age=\d+/);
    } finally {
      await proxied.close();
    }
  });
});

async function rawGet(baseUrl, rawPath) {
  const { default: http } = await import('node:http');
  const { hostname, port } = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname, port, path: rawPath, method: 'GET' }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}
