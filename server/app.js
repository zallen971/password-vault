// HTTP application: JSON API plus the static web app.
//
// The server is deliberately "zero knowledge": it authenticates users and
// stores opaque encrypted records. It never receives the master password or
// any key that can decrypt a vault.

import crypto from 'node:crypto';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Store, StoreError } from './store.js';
import { SessionStore, RateLimiter, hashAuthKey, verifyAuthKey, fakeVerify } from './security.js';
import { createStaticHandler } from './static.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const VERSION = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

const DEFAULT_KDF = Object.freeze({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000 });

const DEFAULT_LIMITS = Object.freeze({
  smallBody: 16 * 1024, // bytes, auth and account requests
  syncBody: 24 * 1024 * 1024, // bytes, one sync request
  recordChars: 512 * 1024, // base64 characters in one encrypted record
  batchSize: 2000, // records changed by one sync request
  records: 25_000, // records in one vault
  vaultChars: 96 * 1024 * 1024, // base64 characters in one vault
  loginFailuresPerPair: 10, // per IP + email, per window
  loginFailuresPerEmail: 30,
  loginFailuresPerIp: 50,
  loginWindowMs: 15 * 60 * 1000,
  authRequestsPerIp: 300,
  authWindowMs: 5 * 60 * 1000,
  signupsPerIp: 10,
  signupWindowMs: 60 * 60 * 1000,
});

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  // The only third party the app can ever talk to: the optional, user-initiated
  // breached-password check, which sends a 5-character hash prefix and nothing else.
  "connect-src 'self' https://api.pwnedpasswords.com",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join('; ');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

class HttpError extends Error {
  constructor(status, code, extra) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function decodeBase64(value, minBytes, maxBytes) {
  if (typeof value !== 'string' || value.length % 4 !== 0) return null;
  if (value.length > Math.ceil(maxBytes / 3) * 4 || !BASE64.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length >= minBytes && bytes.length <= maxBytes ? bytes : null;
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) return null;
  return email;
}

function parseKdf(kdf) {
  if (!kdf || kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256') return null;
  if (!Number.isInteger(kdf.iterations) || kdf.iterations < 100_000 || kdf.iterations > 10_000_000) return null;
  return { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations };
}

const isRevision = (value) => Number.isInteger(value) && value >= 0;

/**
 * @param {object} options
 * @param {string} options.dataDir          where accounts are stored
 * @param {boolean|'auto'} [options.allowSignups]  'auto' = only until the first account exists
 * @param {boolean} [options.trustProxy]    honour X-Forwarded-For / X-Forwarded-Proto
 * @param {string} [options.publicDir]
 * @param {object} [options.limits]         overrides for DEFAULT_LIMITS
 * @param {boolean} [options.quiet]
 */
export async function createApp(options) {
  const {
    dataDir,
    allowSignups = 'auto',
    trustProxy = false,
    publicDir = path.join(ROOT, 'public'),
    backupDays = 14,
    quiet = false,
  } = options;
  const limits = { ...DEFAULT_LIMITS, ...options.limits };

  const store = new Store(dataDir, { backupDays });
  await store.init();

  const sessions = new SessionStore();
  const serveStatic = createStaticHandler(publicDir);

  const loginByPair = new RateLimiter({ limit: limits.loginFailuresPerPair, windowMs: limits.loginWindowMs });
  const loginByEmail = new RateLimiter({ limit: limits.loginFailuresPerEmail, windowMs: limits.loginWindowMs });
  const loginByIp = new RateLimiter({ limit: limits.loginFailuresPerIp, windowMs: limits.loginWindowMs });
  const authRequests = new RateLimiter({ limit: limits.authRequestsPerIp, windowMs: limits.authWindowMs });
  const signups = new RateLimiter({ limit: limits.signupsPerIp, windowMs: limits.signupWindowMs });
  const limiters = [loginByPair, loginByEmail, loginByIp, authRequests, signups];

  const sweeper = setInterval(() => {
    sessions.sweep();
    for (const limiter of limiters) limiter.sweep();
  }, 60_000);
  sweeper.unref();

  const log = (...args) => {
    if (!quiet) console.log(...args);
  };

  const signupsOpen = () => (allowSignups === 'auto' ? store.accountCount === 0 : Boolean(allowSignups));

  function clientIp(req) {
    if (trustProxy) {
      const forwarded = req.headers['x-forwarded-for'];
      if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',').pop().trim();
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function isSecure(req) {
    if (req.socket.encrypted) return true;
    if (!trustProxy) return false;
    const proto = req.headers['x-forwarded-proto'];
    return typeof proto === 'string' && proto.split(',')[0].trim() === 'https';
  }

  async function readJson(req, res, limit) {
    const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') throw new HttpError(415, 'unsupported_media_type');
    const tooLarge = () => {
      res.setHeader('Connection', 'close');
      return new HttpError(413, 'payload_too_large');
    };
    if (Number(req.headers['content-length']) > limit) throw tooLarge();
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > limit) throw tooLarge();
      chunks.push(chunk);
    }
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new HttpError(400, 'invalid_json');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new HttpError(400, 'invalid_request');
    return parsed;
  }

  /** Throttles everything that touches credentials, per client address. */
  function throttleAuth(ip) {
    const wait = authRequests.blockedFor(ip);
    if (wait) throw new HttpError(429, 'too_many_requests', { retryAfter: wait });
    authRequests.hit(ip);
  }

  /**
   * Checks an auth key against an account while enforcing the failed-attempt
   * limits. Attempts are counted before the check so that a burst of parallel
   * guesses cannot slip past the limit.
   */
  async function checkCredentials(ip, email, authKey) {
    const guards = [
      [loginByPair, `${ip}|${email}`],
      [loginByEmail, email],
      [loginByIp, ip],
    ];
    const wait = Math.max(...guards.map(([limiter, key]) => limiter.blockedFor(key)));
    if (wait) throw new HttpError(429, 'too_many_attempts', { retryAfter: wait });
    for (const [limiter, key] of guards) limiter.hit(key);

    const account = store.findByEmail(email);
    const ok = account ? await verifyAuthKey(authKey, account.auth) : await fakeVerify(authKey);
    if (!ok) {
      log(`[auth] failed sign-in attempt from ${ip}`);
      throw new HttpError(401, 'invalid_credentials');
    }
    // Correct password: clear this client's strikes for the account, and take
    // back the provisional hit from the two shared counters.
    loginByPair.reset(guards[0][1]);
    loginByEmail.forgive(email);
    loginByIp.forgive(ip);
    return account;
  }

  const accountView = (account) => ({
    id: account.id,
    email: account.email,
    createdAt: account.createdAt,
    kdf: account.kdf,
    salt: account.salt,
    protectedKey: account.protectedKey,
  });

  // ---- Route handlers. Each returns the JSON body, or undefined for 204. ----

  function getConfig() {
    return { name: 'password-vault', version: VERSION, signupsOpen: signupsOpen(), firstRun: store.accountCount === 0 };
  }

  async function prelogin({ ip, body }) {
    throttleAuth(ip);
    const email = normalizeEmail((await body()).email);
    if (!email) throw new HttpError(400, 'invalid_request');
    const account = store.findByEmail(email);
    if (account) return { kdf: account.kdf, salt: account.salt };
    // Unknown addresses get a stable, plausible answer so this endpoint
    // cannot be used to discover which accounts exist.
    const salt = crypto.createHmac('sha256', store.secret).update(`prelogin:${email}`).digest().subarray(0, 16);
    return { kdf: DEFAULT_KDF, salt: salt.toString('base64') };
  }

  async function register({ ip, body }) {
    throttleAuth(ip);
    if (!signupsOpen()) throw new HttpError(403, 'signups_closed');
    const input = await body();
    const email = normalizeEmail(input.email);
    const kdf = parseKdf(input.kdf);
    const salt = decodeBase64(input.salt, 16, 64);
    const authKey = decodeBase64(input.authKey, 32, 32);
    const protectedKey = decodeBase64(input.protectedKey, 32, 512);
    if (!email || !kdf || !salt || !authKey || !protectedKey) throw new HttpError(400, 'invalid_request');

    const wait = signups.blockedFor(ip);
    if (wait) throw new HttpError(429, 'too_many_requests', { retryAfter: wait });
    signups.hit(ip);

    if (store.findByEmail(email)) throw new HttpError(409, 'email_taken');
    const auth = await hashAuthKey(authKey);
    // Re-check: the hash above is slow, and sign-ups may have closed meanwhile.
    if (!signupsOpen()) throw new HttpError(403, 'signups_closed');
    let account;
    try {
      account = await store.create({ email, kdf, salt: input.salt, auth, protectedKey: input.protectedKey });
    } catch (err) {
      if (err instanceof StoreError && err.code === 'email_taken') throw new HttpError(409, 'email_taken');
      throw err;
    }
    log(`[auth] account created (${store.accountCount} total)`);
    return { token: sessions.create(account.id), account: accountView(account) };
  }

  async function login({ ip, body }) {
    throttleAuth(ip);
    const input = await body();
    const email = normalizeEmail(input.email);
    const authKey = decodeBase64(input.authKey, 32, 32);
    if (!email || !authKey) throw new HttpError(400, 'invalid_request');
    const account = await checkCredentials(ip, email, authKey);
    return { token: sessions.create(account.id), account: accountView(account) };
  }

  function logout({ token }) {
    sessions.revoke(token);
  }

  function getVault({ account }) {
    const records = Object.entries(account.records).map(([id, record]) => ({ id, data: record.data, rev: record.rev }));
    return { revision: account.revision, records };
  }

  function getRevision({ account }) {
    return { revision: account.revision };
  }

  async function syncVault({ account, body }) {
    const input = await body();
    const upserts = input.upserts ?? [];
    const deletes = input.deletes ?? [];
    if (!Array.isArray(upserts) || !Array.isArray(deletes)) throw new HttpError(400, 'invalid_request');
    if (upserts.length + deletes.length === 0) return { revision: account.revision };
    if (upserts.length + deletes.length > limits.batchSize) throw new HttpError(413, 'batch_too_large');

    const seen = new Set();
    for (const entry of [...upserts, ...deletes]) {
      if (!entry || typeof entry.id !== 'string' || !UUID.test(entry.id) || seen.has(entry.id)) {
        throw new HttpError(400, 'invalid_request');
      }
      if (entry.baseRev != null && !isRevision(entry.baseRev)) throw new HttpError(400, 'invalid_request');
      seen.add(entry.id);
    }
    for (const { data } of upserts) {
      if (typeof data !== 'string' || data.length < 40 || data.length % 4 !== 0 || !BASE64.test(data)) {
        throw new HttpError(400, 'invalid_request');
      }
      if (data.length > limits.recordChars) throw new HttpError(413, 'record_too_large');
    }

    return store.update(account.id, (draft) => {
      // Optimistic concurrency: every change names the revision it was based
      // on, so edits made on another device are never silently overwritten.
      const conflicts = [];
      for (const { id, baseRev } of upserts) {
        const existing = draft.records[id];
        if (existing ? existing.rev !== baseRev : baseRev != null) conflicts.push(id);
      }
      for (const { id, baseRev } of deletes) {
        const existing = draft.records[id];
        if (existing && baseRev != null && existing.rev !== baseRev) conflicts.push(id);
      }
      if (conflicts.length) throw new HttpError(409, 'conflict', { conflicts, revision: draft.revision });

      const revision = draft.revision + 1;
      for (const { id, data } of upserts) draft.records[id] = { data, rev: revision };
      for (const { id } of deletes) delete draft.records[id];

      const all = Object.values(draft.records);
      if (all.length > limits.records) throw new HttpError(413, 'vault_full');
      if (all.reduce((sum, record) => sum + record.data.length, 0) > limits.vaultChars) {
        throw new HttpError(413, 'vault_full');
      }
      draft.revision = revision;
      draft.updatedAt = new Date().toISOString();
      return { revision };
    });
  }

  async function changePassword({ ip, account, body }) {
    throttleAuth(ip);
    const input = await body();
    const authKey = decodeBase64(input.authKey, 32, 32);
    const newAuthKey = decodeBase64(input.newAuthKey, 32, 32);
    const kdf = parseKdf(input.kdf);
    const salt = decodeBase64(input.salt, 16, 64);
    const protectedKey = decodeBase64(input.protectedKey, 32, 512);
    if (!authKey || !newAuthKey || !kdf || !salt || !protectedKey) throw new HttpError(400, 'invalid_request');

    await checkCredentials(ip, account.email, authKey);
    const auth = await hashAuthKey(newAuthKey);
    await store.update(account.id, (draft) => {
      draft.auth = auth;
      draft.kdf = kdf;
      draft.salt = input.salt;
      draft.protectedKey = input.protectedKey;
    });
    // Sign out every device, then hand this one a fresh session.
    sessions.revokeAccount(account.id);
    log('[auth] master password changed');
    return { token: sessions.create(account.id), account: accountView(store.get(account.id)) };
  }

  async function deleteAccount({ ip, account, body }) {
    throttleAuth(ip);
    const authKey = decodeBase64((await body()).authKey, 32, 32);
    if (!authKey) throw new HttpError(400, 'invalid_request');
    await checkCredentials(ip, account.email, authKey);
    sessions.revokeAccount(account.id);
    await store.remove(account.id);
    log('[auth] account deleted');
  }

  const routes = {
    '/api/config': { GET: { handler: getConfig } },
    '/api/auth/prelogin': { POST: { handler: prelogin } },
    '/api/auth/register': { POST: { handler: register } },
    '/api/auth/login': { POST: { handler: login } },
    '/api/auth/logout': { POST: { handler: logout, auth: true } },
    '/api/vault': { GET: { handler: getVault, auth: true } },
    '/api/vault/revision': { GET: { handler: getRevision, auth: true } },
    '/api/vault/sync': { POST: { handler: syncVault, auth: true, bodyLimit: limits.syncBody } },
    '/api/account/password': { POST: { handler: changePassword, auth: true } },
    '/api/account/delete': { POST: { handler: deleteAccount, auth: true } },
  };

  function sendJson(res, status, body) {
    if (body === undefined) {
      res.statusCode = 204;
      res.end();
      return;
    }
    const payload = Buffer.from(JSON.stringify(body));
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', payload.length);
    res.end(payload);
  }

  async function handleApi(req, res, pathname) {
    res.setHeader('Cache-Control', 'no-store');
    const methods = Object.hasOwn(routes, pathname) ? routes[pathname] : null;
    if (!methods) throw new HttpError(404, 'not_found');
    const route = Object.hasOwn(methods, req.method) ? methods[req.method] : null;
    if (!route) {
      res.setHeader('Allow', Object.keys(methods).join(', '));
      throw new HttpError(405, 'method_not_allowed');
    }

    const ctx = {
      ip: clientIp(req),
      token: null,
      account: null,
      body: () => readJson(req, res, route.bodyLimit ?? limits.smallBody),
    };
    if (route.auth) {
      const header = String(req.headers.authorization || '');
      const token = header.startsWith('Bearer ') ? header.slice(7) : null;
      const session = sessions.touch(token);
      const account = session ? store.get(session.accountId) : null;
      if (!account) throw new HttpError(401, 'unauthorized');
      ctx.token = token;
      ctx.account = account;
    }
    sendJson(res, 200, await route.handler(ctx));
  }

  async function handler(req, res) {
    res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    if (isSecure(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');

    try {
      let pathname;
      try {
        ({ pathname } = new URL(req.url, 'http://localhost'));
      } catch {
        throw new HttpError(400, 'bad_request');
      }
      if (pathname === '/api' || pathname.startsWith('/api/')) {
        await handleApi(req, res, pathname);
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.setHeader('Allow', 'GET, HEAD');
        throw new HttpError(405, 'method_not_allowed');
      }
      if (await serveStatic(req, res, pathname)) return;
      throw new HttpError(404, 'not_found');
    } catch (err) {
      if (res.headersSent || res.destroyed || req.socket?.destroyed) {
        // Nothing useful can be sent: the response is under way or the client hung up.
        res.destroy();
        return;
      }
      if (err instanceof HttpError) {
        if (err.extra?.retryAfter) res.setHeader('Retry-After', String(err.extra.retryAfter));
        sendJson(res, err.status, { error: err.code, ...err.extra });
      } else if (err instanceof StoreError && err.code === 'not_found') {
        sendJson(res, 401, { error: 'unauthorized' });
      } else {
        console.error('[server] unexpected error:', err);
        sendJson(res, 500, { error: 'internal_error' });
      }
    }
  }

  return {
    handler,
    store,
    signupsOpen,
    async close() {
      clearInterval(sweeper);
      await store.flush();
    },
  };
}
