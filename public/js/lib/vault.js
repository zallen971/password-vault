// The unlocked vault: holds the keys and decrypted records in memory, and
// keeps them in step with the server. Nothing here is ever written to disk.

import { ApiError } from './api.js';
import {
  DEFAULT_KDF,
  createAccountKeys,
  decryptJson,
  deriveLoginKeys,
  encryptJson,
  openVaultKey,
  randomBytes,
  rewrapVaultKey,
  toBase64,
} from './crypto.js';
import { MAX_PASSWORD_HISTORY, TRASH_RETENTION_DAYS, contentKey, normalizeFolder, normalizeItem } from './model.js';

export class VaultError extends Error {
  /** @param {'locked'|'conflict'|'wrong_password'|'damaged_key'} code */
  constructor(code) {
    super(code);
    this.name = 'VaultError';
    this.code = code;
  }
}

const SYNC_CHUNK = 400;
const recordContext = (id) => `record:${id}`;
const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });

/**
 * Events: "change" whenever the contents change, and "lock" when the vault is
 * locked (detail.reason is "manual", "idle", "left", "expired" or "deleted").
 */
export class Vault extends EventTarget {
  #api;
  #session = null; // { key, account } while unlocked
  #records = new Map(); // id -> { rev, value }
  #revision = 0;
  #queue = Promise.resolve();

  /** Records that could not be decrypted on the last refresh. */
  unreadable = 0;

  constructor(api) {
    super();
    this.#api = api;
    api.onUnauthorized = () => this.lock('expired');
  }

  get unlocked() {
    return this.#session !== null;
  }

  get email() {
    return this.#session?.account.email ?? null;
  }

  /** @returns {object[]} every item, including those in the trash */
  get items() {
    const items = [];
    for (const { value } of this.#records.values()) if (value.kind === 'item') items.push(value);
    return items;
  }

  get folders() {
    const folders = [];
    for (const { value } of this.#records.values()) if (value.kind === 'folder') folders.push(value);
    return folders.sort(byName);
  }

  item(id) {
    const value = this.#records.get(id)?.value;
    return value?.kind === 'item' ? value : null;
  }

  folder(id) {
    const value = this.#records.get(id)?.value;
    return value?.kind === 'folder' ? value : null;
  }

  /** The revision of a record as this device last saw it (null if it has none). */
  revisionOf(id) {
    return this.#records.get(id)?.rev ?? null;
  }

  // ---- Session ----

  async signUp(email, password) {
    const keys = await createAccountKeys(password);
    const { token, account } = await this.#api.register({
      email,
      kdf: keys.kdf,
      salt: keys.salt,
      authKey: keys.authKey,
      protectedKey: keys.protectedKey,
    });
    this.#start(token, account, keys.vaultKey);
    this.#changed();
  }

  async unlock(email, password) {
    const { kdf, salt } = await this.#api.prelogin(email);
    const { authKey, wrapKey } = await deriveLoginKeys(password, salt, kdf);
    const { token, account } = await this.#api.login(email, authKey);
    let key;
    try {
      key = await openVaultKey(account.protectedKey, wrapKey);
    } catch {
      throw new VaultError('damaged_key');
    }
    this.#start(token, account, key);
    try {
      await this.refresh();
    } catch (err) {
      // Never leave a half-loaded vault open.
      this.#stop(true);
      throw err;
    }
    // Housekeeping must never stand between someone and their passwords: if
    // the server cannot take writes right now, the clean-up waits for next time.
    await this.#purgeOldTrash().catch(() => {});
    if (!this.#session) throw new VaultError('locked');
  }

  #start(token, account, key) {
    this.#api.setToken(token);
    this.#session = { key, account };
    this.#records = new Map();
    this.#revision = 0;
    this.unreadable = 0;
  }

  /** Forgets the keys and every decrypted record. */
  lock(reason = 'manual') {
    if (!this.#session) return;
    // "expired" and "deleted" mean the server has already dropped the session.
    this.#stop(reason !== 'expired' && reason !== 'deleted');
    this.dispatchEvent(new CustomEvent('lock', { detail: { reason } }));
  }

  #stop(signOut) {
    if (signOut) this.#api.logout().catch(() => {});
    this.#api.setToken(null);
    this.#session = null;
    this.#records = new Map();
    this.#revision = 0;
  }

  /** True if `password` is the current master password. Checked locally. */
  async verifyPassword(password) {
    const { account } = this.#require();
    const { wrapKey } = await deriveLoginKeys(password, account.salt, account.kdf);
    try {
      await openVaultKey(account.protectedKey, wrapKey);
      return true;
    } catch {
      return false;
    }
  }

  async changeMasterPassword(currentPassword, newPassword) {
    const session = this.#require();
    const { account } = session;
    const current = await deriveLoginKeys(currentPassword, account.salt, account.kdf);
    try {
      await openVaultKey(account.protectedKey, current.wrapKey);
    } catch {
      throw new VaultError('wrong_password');
    }
    const salt = toBase64(randomBytes(16));
    const kdf = { ...DEFAULT_KDF };
    const next = await deriveLoginKeys(newPassword, salt, kdf);
    const protectedKey = await rewrapVaultKey(account.protectedKey, current.wrapKey, next.wrapKey);
    const result = await this.#api.changePassword({
      authKey: current.authKey,
      newAuthKey: next.authKey,
      kdf,
      salt,
      protectedKey,
    });
    if (session !== this.#session) throw new VaultError('locked');
    this.#api.setToken(result.token);
    session.account = result.account;
  }

  /** Permanently deletes the account and everything in it. */
  async deleteAccount(password) {
    const { account } = this.#require();
    const { authKey, wrapKey } = await deriveLoginKeys(password, account.salt, account.kdf);
    try {
      await openVaultKey(account.protectedKey, wrapKey);
    } catch {
      throw new VaultError('wrong_password');
    }
    await this.#api.deleteAccount(authKey);
    this.lock('deleted');
  }

  // ---- Reading ----

  /** Fetches the vault and decrypts whatever changed since last time. */
  refresh() {
    return this.#serialize(() => this.#pull());
  }

  /** Cheap poll: only downloads the vault if another device changed it. */
  checkForChanges() {
    return this.#serialize(async () => {
      const session = this.#require();
      const { revision } = await this.#api.getRevision();
      if (session === this.#session && revision !== this.#revision) await this.#pull();
    });
  }

  async #pull() {
    const session = this.#require();
    const { revision, records } = await this.#api.getVault();
    const next = new Map();
    let unreadable = 0;
    await Promise.all(
      records.map(async ({ id, data, rev }) => {
        const cached = this.#records.get(id);
        if (cached && cached.rev === rev) {
          next.set(id, cached);
          return;
        }
        try {
          const value = await decryptJson(session.key, data, recordContext(id));
          const normalized = value?.kind === 'folder' ? normalizeFolder({ ...value, id }) : normalizeItem({ ...value, id });
          next.set(id, { rev, value: normalized });
        } catch {
          unreadable += 1;
        }
      }),
    );
    if (session !== this.#session) throw new VaultError('locked');
    this.#records = next;
    this.#revision = revision;
    this.unreadable = unreadable;
    this.#changed();
  }

  // ---- Writing ----
  //
  // Every write goes through #commit, which runs changes one at a time and
  // works out each change when its turn comes, from the newest local copy.
  // Small changes (star, trash, move) are therefore applied on top of
  // whatever has synced in meanwhile instead of overwriting it. A full edit
  // is different: it replaces the item, so it names the revision it was based
  // on and the server refuses it if that is no longer the latest.

  /**
   * Creates or updates an item and returns the saved version.
   * `basedOn` is the revision the edit started from (see revisionOf); if the
   * item has moved on since then, on this device or another, the save is
   * refused with a "conflict" error instead of overwriting the newer version.
   * Left out, it means the revision this device holds right now.
   */
  async saveItem(input, { basedOn = this.revisionOf(input.id) } = {}) {
    let item;
    await this.#commit(() => {
      const existing = this.item(input.id);
      const now = new Date().toISOString();
      item = normalizeItem({ ...input, createdAt: existing?.createdAt ?? input.createdAt, updatedAt: now });
      if (existing) {
        // Keep a trail of replaced passwords so a mistaken change can be undone.
        item.passwordHistory = existing.passwordHistory;
        const previous = existing.login?.password;
        if (previous && previous !== item.login?.password) {
          item.passwordHistory = [{ password: previous, changedAt: now }, ...existing.passwordHistory].slice(0, MAX_PASSWORD_HISTORY);
        }
      }
      return { upserts: [item], basedOn: new Map([[item.id, basedOn]]) };
    });
    return item;
  }

  setFavorite(id, favorite) {
    return this.#modify([id], (item) => ({ ...item, favorite }));
  }

  /** Moves items to the trash, where they stay for 30 days. */
  trashItems(ids) {
    const deletedAt = new Date().toISOString();
    return this.#modify(ids, (item) => ({ ...item, deletedAt }));
  }

  restoreItems(ids) {
    return this.#modify(ids, (item) => ({ ...item, deletedAt: null }));
  }

  deleteItems(ids) {
    return this.#commit(() => ({ deletes: ids.filter((id) => this.item(id)) }));
  }

  emptyTrash() {
    return this.#commit(() => ({ deletes: this.items.filter((item) => item.deletedAt).map((item) => item.id) }));
  }

  async saveFolder(input) {
    let folder;
    await this.#commit(() => {
      folder = normalizeFolder({ ...this.folder(input.id), ...input, updatedAt: new Date().toISOString() });
      if (!folder.name) throw new Error('A folder needs a name');
      return { upserts: [folder] };
    });
    return folder;
  }

  /** Deletes a folder. Its items are kept and simply become unfiled. */
  deleteFolder(id) {
    return this.#commit(() => ({
      upserts: this.items.filter((item) => item.folderId === id).map((item) => ({ ...item, folderId: null })),
      deletes: this.folder(id) ? [id] : [],
    }));
  }

  /**
   * Saves imported item drafts, creating any folders they mention.
   * `folders` lists further folder names to create even if nothing is in them.
   * With `skipDuplicates`, a draft identical to an item already in the vault is
   * left out; identical drafts within the import itself are all kept.
   * @returns {Promise<{added: number, skipped: number, folders: number}>}
   */
  async importItems(drafts, { skipDuplicates = true, folders: folderNames = [] } = {}) {
    this.#require();
    const folderIds = new Map(this.folders.map((folder) => [folder.name, folder.id]));
    const existing = skipDuplicates ? new Set(this.items.filter((item) => !item.deletedAt).map(contentKey)) : null;
    const folders = [];
    const items = [];
    let skipped = 0;

    const folderFor = (name) => {
      if (!folderIds.has(name)) {
        const folder = normalizeFolder({ name });
        folders.push(folder);
        folderIds.set(name, folder.id);
      }
      return folderIds.get(name);
    };

    for (const { folderName, ...draft } of drafts) {
      const item = normalizeItem({ ...draft, id: undefined, folderId: null, deletedAt: null });
      if (existing?.has(contentKey(item))) {
        skipped += 1;
        continue;
      }
      const name = String(folderName ?? '').trim();
      if (name) item.folderId = folderFor(name);
      items.push(item);
    }
    for (const name of folderNames) {
      if (String(name ?? '').trim()) folderFor(String(name).trim());
    }

    await this.#commit(() => ({ upserts: [...folders, ...items] }));
    return { added: items.length, skipped, folders: folders.length };
  }

  /** Applies a small change to each item, starting from its newest local copy. */
  #modify(ids, change) {
    return this.#commit(() => ({
      upserts: ids
        .map((id) => this.item(id))
        .filter(Boolean)
        .map(change),
    }));
  }

  async #purgeOldTrash() {
    const cutoff = Date.now() - TRASH_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    await this.#commit(() => ({
      deletes: this.items.filter((item) => item.deletedAt && new Date(item.deletedAt).getTime() < cutoff).map((item) => item.id),
    }));
  }

  /**
   * Encrypts and uploads a set of changes. `plan` is called when it is this
   * operation's turn and returns `{ upserts, deletes, basedOn }`. Each change
   * is sent with the revision it builds on (the local one, unless `basedOn`
   * names an earlier one), and the server rejects a request if any of those
   * is out of date. Changes go in one all-or-nothing request, except very
   * large sets (imports, emptying a big trash), which are sent in several.
   */
  #commit(plan) {
    return this.#serialize(async () => {
      const session = this.#require();
      const { upserts = [], deletes = [], basedOn } = plan();
      const baseRev = (id) => (basedOn?.has(id) ? basedOn.get(id) : this.revisionOf(id));
      const steps = [...upserts.map((value) => ({ value })), ...deletes.map((id) => ({ id }))];
      let behind = false;

      for (let start = 0; start < steps.length; start += SYNC_CHUNK) {
        const slice = steps.slice(start, start + SYNC_CHUNK);
        const changes = { upserts: [], deletes: [] };
        for (const { value, id } of slice) {
          if (value) {
            changes.upserts.push({ id: value.id, baseRev: baseRev(value.id), data: await encryptJson(session.key, value, recordContext(value.id)) });
          } else {
            changes.deletes.push({ id, baseRev: baseRev(id) });
          }
        }

        let result;
        try {
          result = await this.#api.sync(changes);
        } catch (err) {
          if (err instanceof ApiError && err.code === 'conflict') {
            // Another device got there first. Show its version; the caller decides what next.
            await this.#pull().catch(() => {});
            throw new VaultError('conflict');
          }
          throw err;
        }
        if (session !== this.#session) throw new VaultError('locked');

        // A gap in revisions means other devices made changes we have not seen yet.
        if (result.revision !== this.#revision + 1) behind = true;
        for (const { value, id } of slice) {
          if (value) this.#records.set(value.id, { rev: result.revision, value });
          else this.#records.delete(id);
        }
        this.#revision = result.revision;
        this.#changed();
      }
      if (behind) await this.#pull().catch(() => {});
    });
  }

  #require() {
    if (!this.#session) throw new VaultError('locked');
    return this.#session;
  }

  /** Runs vault operations one at a time so they cannot interleave. */
  #serialize(task) {
    const run = this.#queue.then(task, task);
    this.#queue = run.catch(() => {});
    return run;
  }

  #changed() {
    this.dispatchEvent(new Event('change'));
  }
}
