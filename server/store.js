// File-backed storage for accounts and their encrypted vault records.
//
// Every account lives in one JSON file (data/accounts/<id>.json). The server
// only ever sees ciphertext, so these files are safe to back up as-is.
// Writes are serialized per account and applied atomically (temp file, fsync,
// rename), and a snapshot of each vault is kept before the first change of
// every day so an accidental wipe can be rolled back.

import { promises as fs, constants as FS } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export class StoreError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const today = () => new Date().toISOString().slice(0, 10);

export class Store {
  #dir;
  #accountsDir;
  #backupsDir;
  #backupDays;
  #accounts = new Map(); // id -> account
  #byEmail = new Map(); // email -> id
  #queues = new Map(); // id -> tail of that account's write chain
  #snapshotDay = new Map(); // id -> last day a snapshot was taken
  #unreadable = 0;
  secret = null;

  constructor(dataDir, { backupDays = 14 } = {}) {
    this.#dir = path.resolve(dataDir);
    this.#accountsDir = path.join(this.#dir, 'accounts');
    this.#backupsDir = path.join(this.#dir, 'backups');
    this.#backupDays = backupDays;
  }

  get dir() {
    return this.#dir;
  }

  async init() {
    await fs.mkdir(this.#accountsDir, { recursive: true, mode: 0o700 });
    await fs.mkdir(this.#backupsDir, { recursive: true, mode: 0o700 });
    this.secret = await this.#loadSecret();

    for (const name of await fs.readdir(this.#accountsDir)) {
      const file = path.join(this.#accountsDir, name);
      if (name.endsWith('.tmp')) {
        // Leftover from a write that was interrupted before its rename.
        await fs.rm(file, { force: true });
        continue;
      }
      if (!name.endsWith('.json')) continue;
      try {
        const account = JSON.parse(await fs.readFile(file, 'utf8'));
        if (!account || typeof account.id !== 'string' || typeof account.email !== 'string') {
          throw new Error('missing id or email');
        }
        if (`${account.id}.json` !== name) throw new Error('file name does not match account id');
        account.records ??= {};
        account.revision ??= 0;
        this.#accounts.set(account.id, account);
        this.#byEmail.set(account.email, account.id);
      } catch (err) {
        // Never delete or overwrite something we could not read.
        this.#unreadable += 1;
        console.error(`[store] could not load ${file}: ${err.message}`);
      }
    }
  }

  async #loadSecret() {
    const file = path.join(this.#dir, 'server.json');
    try {
      const parsed = JSON.parse(await fs.readFile(file, 'utf8'));
      const secret = Buffer.from(parsed.secret, 'base64');
      if (secret.length >= 32) return secret;
      throw new Error('invalid secret');
    } catch (err) {
      if (err.code !== 'ENOENT') throw new Error(`could not read ${file}: ${err.message}`);
    }
    const secret = crypto.randomBytes(32);
    await this.#writeAtomic(file, JSON.stringify({ secret: secret.toString('base64') }));
    return secret;
  }

  /** Number of accounts on disk, including any that could not be read. */
  get accountCount() {
    return this.#accounts.size + this.#unreadable;
  }

  get(id) {
    return this.#accounts.get(id);
  }

  findByEmail(email) {
    const id = this.#byEmail.get(email);
    return id ? this.#accounts.get(id) : undefined;
  }

  async create(fields) {
    if (this.#byEmail.has(fields.email)) throw new StoreError('email_taken');
    const account = {
      version: 1,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      revision: 0,
      ...fields,
      records: {},
    };
    // Reserve the address synchronously so concurrent sign-ups cannot both win.
    this.#byEmail.set(account.email, account.id);
    try {
      await this.#writeAtomic(this.#file(account.id), JSON.stringify(account));
    } catch (err) {
      this.#byEmail.delete(account.email);
      throw err;
    }
    this.#accounts.set(account.id, account);
    this.#snapshotDay.set(account.id, today());
    return account;
  }

  /**
   * Apply `fn` to a draft of the account and persist the result. Nothing is
   * saved (and memory is untouched) if `fn` throws. Record objects must be
   * replaced, never mutated in place.
   */
  update(id, fn) {
    return this.#enqueue(id, async () => {
      const current = this.#accounts.get(id);
      if (!current) throw new StoreError('not_found');
      const draft = { ...current, records: { ...current.records } };
      const result = await fn(draft);
      await this.#snapshot(id);
      await this.#writeAtomic(this.#file(id), JSON.stringify(draft));
      this.#accounts.set(id, draft);
      return result;
    });
  }

  remove(id) {
    return this.#enqueue(id, async () => {
      const current = this.#accounts.get(id);
      if (!current) throw new StoreError('not_found');
      await fs.rm(this.#file(id), { force: true });
      await fs.rm(path.join(this.#backupsDir, id), { recursive: true, force: true });
      this.#accounts.delete(id);
      this.#byEmail.delete(current.email);
      this.#snapshotDay.delete(id);
    });
  }

  /** Resolves once every queued write has settled. */
  async flush() {
    await Promise.allSettled([...this.#queues.values()]);
  }

  #enqueue(id, task) {
    const previous = this.#queues.get(id) ?? Promise.resolve();
    const run = previous.then(task, task);
    // Keep the chain alive without letting one failure poison later writes.
    this.#queues.set(id, run.catch(() => {}));
    return run;
  }

  #file(id) {
    return path.join(this.#accountsDir, `${id}.json`);
  }

  async #snapshot(id) {
    if (this.#backupDays <= 0) return;
    const day = today();
    if (this.#snapshotDay.get(id) === day) return;
    const dir = path.join(this.#backupsDir, id);
    try {
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
      try {
        await fs.copyFile(this.#file(id), path.join(dir, `${day}.json`), FS.COPYFILE_EXCL);
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
      }
      const snapshots = (await fs.readdir(dir)).filter((n) => /^\d{4}-\d{2}-\d{2}\.json$/.test(n)).sort();
      for (const stale of snapshots.slice(0, Math.max(0, snapshots.length - this.#backupDays))) {
        await fs.rm(path.join(dir, stale), { force: true });
      }
      this.#snapshotDay.set(id, day);
    } catch (err) {
      // A failed snapshot must not block the user's write.
      console.error(`[store] snapshot failed for ${id}: ${err.message}`);
    }
  }

  async #writeAtomic(file, contents) {
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    let handle;
    try {
      handle = await fs.open(tmp, 'w', 0o600);
      await handle.writeFile(contents, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(tmp, file);
    } catch (err) {
      await handle?.close().catch(() => {});
      await fs.rm(tmp, { force: true }).catch(() => {});
      throw err;
    }
    // Make the rename itself durable. Not supported everywhere (e.g. Windows).
    try {
      const dir = await fs.open(path.dirname(file), 'r');
      try {
        await dir.sync();
      } finally {
        await dir.close();
      }
    } catch {
      /* best effort */
    }
  }
}
