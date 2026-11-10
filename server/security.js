// Sessions, rate limiting and credential hashing.

import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1 });
const HASH_BYTES = 32;

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

/**
 * The client never sends the master password. It sends an "auth key" derived
 * from it, and we store only a salted scrypt hash of that key, so a copy of
 * the data directory cannot be replayed to sign in.
 */
export async function hashAuthKey(authKey) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(authKey, salt, HASH_BYTES, SCRYPT);
  return { ...SCRYPT, salt: salt.toString('base64'), hash: hash.toString('base64') };
}

export async function verifyAuthKey(authKey, stored) {
  const expected = Buffer.from(stored.hash, 'base64');
  const actual = await scrypt(authKey, Buffer.from(stored.salt, 'base64'), expected.length, {
    N: stored.N,
    r: stored.r,
    p: stored.p,
  });
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

/** Burns the same time as a real verification, for accounts that do not exist. */
export async function fakeVerify(authKey) {
  await scrypt(authKey, Buffer.alloc(16), HASH_BYTES, SCRYPT);
  return false;
}

export class SessionStore {
  #sessions = new Map(); // sha256(token) -> session
  #idleMs;
  #maxMs;

  constructor({ idleMs = 12 * 60 * 60 * 1000, maxMs = 30 * 24 * 60 * 60 * 1000 } = {}) {
    this.#idleMs = idleMs;
    this.#maxMs = maxMs;
  }

  create(accountId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    this.#sessions.set(sha256(token), { accountId, createdAt: now, lastSeen: now });
    return token;
  }

  /** Returns the live session for a token (and extends it), or null. */
  touch(token) {
    if (typeof token !== 'string' || token.length < 20 || token.length > 200) return null;
    const key = sha256(token);
    const session = this.#sessions.get(key);
    if (!session) return null;
    const now = Date.now();
    if (now - session.lastSeen > this.#idleMs || now - session.createdAt > this.#maxMs) {
      this.#sessions.delete(key);
      return null;
    }
    session.lastSeen = now;
    return session;
  }

  revoke(token) {
    if (typeof token === 'string') this.#sessions.delete(sha256(token));
  }

  revokeAccount(accountId) {
    for (const [key, session] of this.#sessions) {
      if (session.accountId === accountId) this.#sessions.delete(key);
    }
  }

  sweep() {
    const now = Date.now();
    for (const [key, session] of this.#sessions) {
      if (now - session.lastSeen > this.#idleMs || now - session.createdAt > this.#maxMs) {
        this.#sessions.delete(key);
      }
    }
  }

  get size() {
    return this.#sessions.size;
  }
}

/** Fixed-window counter: at most `limit` hits per key in each `windowMs`. */
export class RateLimiter {
  #hits = new Map(); // key -> { count, resetAt }
  #limit;
  #windowMs;

  constructor({ limit, windowMs }) {
    this.#limit = limit;
    this.#windowMs = windowMs;
  }

  #entry(key) {
    const entry = this.#hits.get(key);
    if (entry && entry.resetAt > Date.now()) return entry;
    if (entry) this.#hits.delete(key);
    return null;
  }

  /** Seconds until `key` may try again, or 0 if it is not blocked. */
  blockedFor(key) {
    const entry = this.#entry(key);
    if (!entry || entry.count < this.#limit) return 0;
    return Math.max(1, Math.ceil((entry.resetAt - Date.now()) / 1000));
  }

  hit(key) {
    const entry = this.#entry(key);
    if (entry) entry.count += 1;
    else this.#hits.set(key, { count: 1, resetAt: Date.now() + this.#windowMs });
  }

  /** Undo one hit, e.g. for an attempt that turned out to be legitimate. */
  forgive(key) {
    const entry = this.#entry(key);
    if (entry && entry.count > 0) entry.count -= 1;
  }

  reset(key) {
    this.#hits.delete(key);
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.#hits) {
      if (entry.resetAt <= now) this.#hits.delete(key);
    }
  }
}
