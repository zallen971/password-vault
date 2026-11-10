#!/usr/bin/env node
// Entry point: reads configuration from the environment and starts the server.

import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { createApp, VERSION } from './app.js';

function flag(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (/^(1|true|yes|on)$/i.test(raw)) return true;
  if (/^(0|false|no|off)$/i.test(raw)) return false;
  throw new Error(`${name} must be "true" or "false" (got "${raw}")`);
}

function config() {
  const port = Number(process.env.PORT ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`PORT is not a valid port: ${process.env.PORT}`);
  const backupDays = Number(process.env.BACKUP_DAYS ?? 14);
  if (!Number.isInteger(backupDays) || backupDays < 0) throw new Error(`BACKUP_DAYS must be a whole number of days: ${process.env.BACKUP_DAYS}`);
  const tlsCert = process.env.TLS_CERT;
  const tlsKey = process.env.TLS_KEY;
  if (Boolean(tlsCert) !== Boolean(tlsKey)) throw new Error('Set both TLS_CERT and TLS_KEY, or neither.');
  const host = process.env.HOST || '127.0.0.1';
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(host);
  // Host names the app answers to. On this computer only, that is "localhost";
  // on the network it is whatever ALLOWED_HOSTS says, or anything if unset.
  const named = (process.env.ALLOWED_HOSTS || '').split(',').map((name) => name.trim().toLowerCase()).filter(Boolean);
  const allowedHosts = named.length ? named : loopback ? ['localhost', '127.0.0.1', '[::1]'] : null;
  return {
    port,
    host,
    allowedHosts,
    dataDir: path.resolve(process.env.DATA_DIR || 'data'),
    allowSignups: flag('ALLOW_SIGNUPS', 'auto'),
    trustProxy: flag('TRUST_PROXY', false),
    backupDays,
    tls: tlsCert ? { cert: readFileSync(tlsCert), key: readFileSync(tlsKey) } : null,
  };
}

async function main() {
  const cfg = config();
  const app = await createApp(cfg);
  const server = cfg.tls ? https.createServer(cfg.tls, app.handler) : http.createServer(app.handler);
  server.headersTimeout = 20_000;
  server.requestTimeout = 120_000;

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(cfg.port, cfg.host, resolve);
  });

  const { port } = server.address();
  const scheme = cfg.tls ? 'https' : 'http';
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(cfg.host);
  const shownHost = loopback || cfg.host === '0.0.0.0' || cfg.host === '::' ? 'localhost' : cfg.host;
  const signups =
    cfg.allowSignups === 'auto'
      ? app.signupsOpen()
        ? 'open until the first account is created'
        : 'closed (set ALLOW_SIGNUPS=true to add another account)'
      : cfg.allowSignups
        ? 'open'
        : 'closed';

  console.log(`\n  Vault ${VERSION} is running\n`);
  console.log(`  Open      ${scheme}://${shownHost}:${port}`);
  console.log(`  Data      ${cfg.dataDir}`);
  console.log(`  Sign-ups  ${signups}\n`);
  if (!loopback && !cfg.tls && !cfg.trustProxy) {
    console.log('  Note: browsers only allow the encryption this app relies on over HTTPS');
    console.log('  (or on http://localhost). To use the vault from other devices, put it');
    console.log('  behind an HTTPS reverse proxy or set TLS_CERT and TLS_KEY. See README.\n');
  }

  let stopping = false;
  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    console.log(`\n  ${signal} received, shutting down…`);
    server.close();
    server.closeIdleConnections?.();
    await app.close();
    process.exit(0);
  };
  process.on('SIGINT', () => stop('SIGINT'));
  process.on('SIGTERM', () => stop('SIGTERM'));
}

main().catch((err) => {
  console.error(`\n  Could not start Vault: ${err.message}\n`);
  process.exit(1);
});
