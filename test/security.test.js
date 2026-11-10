// Unit tests for sessions, rate limiting, credential hashing and the store.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { RateLimiter, SessionStore, fakeVerify, hashAuthKey, verifyAuthKey } from '../server/security.js';
import { Store, StoreError } from '../server/store.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describe('sessions', () => {
  test('tokens are random, long and only valid as issued', () => {
    const sessions = new SessionStore();
    const a = sessions.create('account-a');
    const b = sessions.create('account-a');
    assert.notEqual(a, b);
    assert.ok(a.length >= 43, 'at least 256 bits of randomness');
    assert.equal(sessions.touch(a).accountId, 'account-a');
    for (const bad of [null, undefined, '', 'short', a.slice(0, -1), `${a}x`, a.toUpperCase(), 'x'.repeat(5000), 42, {}]) {
      assert.equal(sessions.touch(bad), null, String(bad).slice(0, 20));
    }
  });

  test('expire when idle, and stay alive while used', async () => {
    const sessions = new SessionStore({ idleMs: 120, maxMs: 60_000 });
    const token = sessions.create('account');
    for (let i = 0; i < 4; i += 1) {
      await sleep(60);
      assert.ok(sessions.touch(token), 'activity keeps the session alive');
    }
    await sleep(180);
    assert.equal(sessions.touch(token), null);
    assert.equal(sessions.size, 0, 'expired sessions are forgotten');
  });

  test('have a hard maximum lifetime however active they are', async () => {
    const sessions = new SessionStore({ idleMs: 60_000, maxMs: 150 });
    const token = sessions.create('account');
    await sleep(60);
    assert.ok(sessions.touch(token));
    await sleep(130);
    assert.equal(sessions.touch(token), null);
  });

  test('can be revoked one at a time or for a whole account', () => {
    const sessions = new SessionStore();
    const [one, two, other] = [sessions.create('a'), sessions.create('a'), sessions.create('b')];
    sessions.revoke(one);
    assert.equal(sessions.touch(one), null);
    assert.ok(sessions.touch(two));
    sessions.revokeAccount('a');
    assert.equal(sessions.touch(two), null);
    assert.ok(sessions.touch(other), 'other accounts are untouched');
    sessions.revoke('not-a-token'); // must not throw
  });

  test('sweep drops only expired sessions', async () => {
    const sessions = new SessionStore({ idleMs: 80, maxMs: 60_000 });
    sessions.create('old');
    await sleep(120);
    const fresh = sessions.create('new');
    sessions.sweep();
    assert.equal(sessions.size, 1);
    assert.ok(sessions.touch(fresh));
  });
});

describe('rate limiter', () => {
  test('blocks after the limit and recovers when the window passes', async () => {
    const limiter = new RateLimiter({ limit: 3, windowMs: 150 });
    assert.equal(limiter.blockedFor('k'), 0);
    limiter.hit('k');
    limiter.hit('k');
    assert.equal(limiter.blockedFor('k'), 0);
    limiter.hit('k');
    assert.ok(limiter.blockedFor('k') >= 1);
    assert.equal(limiter.blockedFor('someone-else'), 0, 'keys are independent');
    await sleep(190);
    assert.equal(limiter.blockedFor('k'), 0);
  });

  test('forgive takes back one hit; reset clears the key', () => {
    const limiter = new RateLimiter({ limit: 2, windowMs: 10_000 });
    limiter.hit('k');
    limiter.hit('k');
    assert.ok(limiter.blockedFor('k') > 0);
    limiter.forgive('k');
    assert.equal(limiter.blockedFor('k'), 0);
    limiter.forgive('k');
    limiter.forgive('k');
    limiter.forgive('k'); // never goes negative
    limiter.hit('k');
    limiter.hit('k');
    assert.ok(limiter.blockedFor('k') > 0);
    limiter.reset('k');
    assert.equal(limiter.blockedFor('k'), 0);
    limiter.forgive('never-seen'); // must not throw
  });

  test('sweep forgets finished windows', async () => {
    const limiter = new RateLimiter({ limit: 1, windowMs: 60 });
    limiter.hit('a');
    await sleep(90);
    limiter.hit('b');
    limiter.sweep();
    assert.equal(limiter.blockedFor('a'), 0);
    assert.ok(limiter.blockedFor('b') > 0);
  });
});

describe('credential hashing', () => {
  test('verifies only the exact key, and salts every hash', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const first = await hashAuthKey(key);
    const second = await hashAuthKey(key);
    assert.notEqual(first.hash, second.hash, 'the same key must not hash to the same value twice');
    assert.notEqual(first.salt, second.salt);
    assert.ok(!JSON.stringify(first).includes(Buffer.from(key).toString('base64')));
    assert.equal(await verifyAuthKey(key, first), true);
    assert.equal(await verifyAuthKey(key, second), true);

    const wrong = Uint8Array.from(key);
    wrong[31] ^= 1;
    assert.equal(await verifyAuthKey(wrong, first), false);
    assert.equal(await verifyAuthKey(new Uint8Array(32), first), false);
    assert.equal(await fakeVerify(key), false);
  });
});

describe('store', () => {
  async function withStore(run, options) {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'vault-store-'));
    try {
      const store = new Store(dir, options);
      await store.init();
      await run(store, dir);
      await store.flush();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
  const fields = (email) => ({ email, kdf: {}, salt: 's', auth: {}, protectedKey: 'k' });

  test('two sign-ups racing for one address: exactly one wins', async () => {
    await withStore(async (store) => {
      const results = await Promise.allSettled([store.create(fields('same@example.com')), store.create(fields('same@example.com'))]);
      assert.deepEqual(results.map((r) => r.status).sort(), ['fulfilled', 'rejected']);
      const failure = results.find((r) => r.status === 'rejected').reason;
      assert.ok(failure instanceof StoreError && failure.code === 'email_taken');
      assert.equal(store.accountCount, 1);
    });
  });

  test('a failed update changes nothing, in memory or on disk', async () => {
    await withStore(async (store, dir) => {
      const account = await store.create(fields('a@example.com'));
      await store.update(account.id, (draft) => {
        draft.records.one = { data: 'x', rev: 1 };
        draft.revision = 1;
      });
      await assert.rejects(
        store.update(account.id, (draft) => {
          draft.records.two = { data: 'y', rev: 2 };
          draft.revision = 2;
          throw new Error('abort');
        }),
        /abort/,
      );
      assert.deepEqual(Object.keys(store.get(account.id).records), ['one']);
      assert.equal(store.get(account.id).revision, 1);

      const reopened = new Store(dir);
      await reopened.init();
      assert.deepEqual(Object.keys(reopened.get(account.id).records), ['one']);
      // A failure must not block later writes.
      await store.update(account.id, (draft) => {
        draft.revision = 5;
      });
      assert.equal(store.get(account.id).revision, 5);
    });
  });

  test('updates run strictly one after another', async () => {
    await withStore(async (store) => {
      const account = await store.create(fields('a@example.com'));
      const order = [];
      await Promise.all(
        Array.from({ length: 12 }, (_, index) =>
          store.update(account.id, async (draft) => {
            order.push(`start ${index}`);
            await sleep(index % 3);
            draft.revision += 1;
            order.push(`end ${index}`);
          }),
        ),
      );
      assert.equal(store.get(account.id).revision, 12);
      for (let i = 0; i < order.length; i += 2) {
        assert.equal(order[i].replace('start', 'end'), order[i + 1], 'no update may start before the previous one ends');
      }
    });
  });

  test('removing an account deletes its file and its snapshots', async () => {
    await withStore(async (store, dir) => {
      const account = await store.create(fields('gone@example.com'));
      await store.update(account.id, (draft) => {
        draft.revision = 1;
      });
      await store.remove(account.id);
      assert.equal(store.get(account.id), undefined);
      assert.equal(store.findByEmail('gone@example.com'), undefined);
      assert.deepEqual(await readdir(path.join(dir, 'accounts')), []);
      assert.deepEqual(await readdir(path.join(dir, 'backups')), []);
      await assert.rejects(store.update(account.id, () => {}), (error) => error instanceof StoreError && error.code === 'not_found');
      // The address can be used again.
      await store.create(fields('gone@example.com'));
    });
  });

  test('the server secret is created once and reused', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'vault-store-'));
    try {
      const first = new Store(dir);
      await first.init();
      const second = new Store(dir);
      await second.init();
      assert.equal(first.secret.length, 32);
      assert.deepEqual(first.secret, second.secret);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
