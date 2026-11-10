// Shared helpers for the test suite.

import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { createApp } from '../server/app.js';

/** Starts the real server on a random local port with a throwaway data directory. */
export async function startServer(options = {}) {
  const dataDir = options.dataDir ?? (await mkdtemp(path.join(os.tmpdir(), 'vault-test-')));
  const app = await createApp({ quiet: true, ...options, dataDir });
  const server = http.createServer(app.handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;

  return {
    url,
    app,
    dataDir,
    /** JSON request helper returning { status, body, headers }. */
    async request(method, route, { body, token, headers = {} } = {}) {
      const response = await fetch(url + route, {
        method,
        headers: {
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...headers,
        },
        body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
      });
      const text = await response.text();
      let parsed = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = text;
      }
      return { status: response.status, body: parsed, headers: response.headers };
    },
    async close({ keepData = false } = {}) {
      const closed = new Promise((resolve) => server.close(resolve));
      server.closeAllConnections();
      await closed;
      await app.close();
      if (!keepData) await rm(dataDir, { recursive: true, force: true });
    },
  };
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64');

/** Registration fields with random (but well-formed) key material. */
export function fakeCredentials(email = 'user@example.com') {
  return {
    email,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600000 },
    salt: b64(crypto.getRandomValues(new Uint8Array(16))),
    authKey: b64(crypto.getRandomValues(new Uint8Array(32))),
    protectedKey: b64(crypto.getRandomValues(new Uint8Array(61))),
  };
}

/** A stand-in for an encrypted record: random bytes, base64-encoded. */
export function fakeRecord(size = 96) {
  return b64(crypto.getRandomValues(new Uint8Array(size)));
}
