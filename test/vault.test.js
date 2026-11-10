// End-to-end tests of the client libraries against the real server: the same
// Api and Vault classes the browser uses, talking to an actual instance.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { startServer } from './helpers.js';
import { Api, ApiError } from '../public/js/lib/api.js';
import { Vault, VaultError } from '../public/js/lib/vault.js';
import { blankItem } from '../public/js/lib/model.js';
import { parseImport } from '../public/js/lib/importers.js';
import { toBitwardenJson } from '../public/js/lib/exporters.js';

const EMAIL = 'ada@example.com';
const PASSWORD = 'correct horse battery staple';

const device = (server) => new Vault(new Api(server.url));

function login(name, fields = {}) {
  const item = blankItem('login');
  item.name = name;
  item.login = { username: 'ada', password: 'S3cret!-for-tests', totp: '', uris: ['https://example.com'], ...fields };
  return item;
}

describe('vault', () => {
  let server;
  let vault;

  before(async () => {
    server = await startServer();
    vault = device(server);
    await vault.signUp(EMAIL, PASSWORD);
  });
  after(() => server.close());

  test('a new vault is unlocked and empty', () => {
    assert.equal(vault.unlocked, true);
    assert.equal(vault.email, EMAIL);
    assert.deepEqual(vault.items, []);
    assert.deepEqual(vault.folders, []);
  });

  test('items survive locking and unlocking', async () => {
    const saved = await vault.saveItem({ ...login('GitHub'), notes: 'ünïcödé ✓', favorite: true });
    const events = [];
    vault.addEventListener('lock', (event) => events.push(event.detail.reason), { once: true });
    vault.lock();
    assert.equal(vault.unlocked, false);
    assert.deepEqual(vault.items, [], 'nothing decrypted may remain after locking');
    assert.deepEqual(events, ['manual']);
    await assert.rejects(vault.saveItem(login('Nope')), (err) => err instanceof VaultError && err.code === 'locked');

    await vault.unlock(EMAIL, PASSWORD);
    assert.deepEqual(vault.item(saved.id), saved);
  });

  test('the wrong master password is rejected', async () => {
    const other = device(server);
    await assert.rejects(other.unlock(EMAIL, 'correct horse battery stapler'), (err) => err instanceof ApiError && err.code === 'invalid_credentials');
    await assert.rejects(other.unlock('nobody@example.com', PASSWORD), (err) => err instanceof ApiError && err.code === 'invalid_credentials');
    assert.equal(other.unlocked, false);
    assert.equal(await vault.verifyPassword(PASSWORD), true);
    assert.equal(await vault.verifyPassword('something else'), false);
  });

  test('the server only ever stores ciphertext', async () => {
    const secret = login('Very Recognizable Name', {
      username: 'needle-username',
      password: 'needle-password-9431',
      uris: ['https://needle-site.test/login'],
    });
    secret.notes = 'needle-notes';
    secret.fields = [{ name: 'needle-field', value: 'needle-value', type: 'hidden' }];
    await vault.saveItem(secret);
    await vault.saveFolder({ name: 'needle-folder' });

    const dir = path.join(server.dataDir, 'accounts');
    const [file] = await readdir(dir);
    const stored = await readFile(path.join(dir, file), 'utf8');
    for (const needle of ['Recognizable', 'needle', 'S3cret', 'https://', 'login', 'folder', PASSWORD]) {
      assert.ok(!stored.includes(needle), `"${needle}" is readable on the server`);
    }
    assert.ok(stored.includes(EMAIL), 'only the account address is stored in the clear');
  });

  test('editing keeps a history of replaced passwords', async () => {
    const original = await vault.saveItem(login('Bank', { password: 'first' }));
    assert.deepEqual(original.passwordHistory, []);

    const second = await vault.saveItem({ ...original, login: { ...original.login, password: 'second' } });
    assert.equal(second.passwordHistory.length, 1);
    assert.equal(second.passwordHistory[0].password, 'first');
    assert.equal(second.createdAt, original.createdAt);

    const renamed = await vault.saveItem({ ...second, name: 'My Bank' });
    assert.equal(renamed.passwordHistory.length, 1, 'unrelated edits do not add history');

    const third = await vault.saveItem({ ...renamed, login: { ...renamed.login, password: 'third' }, passwordHistory: [] });
    assert.deepEqual(third.passwordHistory.map((entry) => entry.password), ['second', 'first'], 'history cannot be dropped by an edit');
  });

  test('trash, restore and permanent deletion', async () => {
    const item = await vault.saveItem(login('Disposable'));
    await vault.trashItems([item.id]);
    assert.ok(vault.item(item.id).deletedAt);
    await vault.restoreItems([item.id]);
    assert.equal(vault.item(item.id).deletedAt, null);

    await vault.trashItems([item.id]);
    const keeper = await vault.saveItem(login('Keeper'));
    await vault.emptyTrash();
    assert.equal(vault.item(item.id), null);
    assert.ok(vault.item(keeper.id), 'emptying the trash leaves other items alone');

    const fresh = device(server);
    await fresh.unlock(EMAIL, PASSWORD);
    assert.equal(fresh.item(item.id), null);
    fresh.lock();
  });

  test('items left in the trash for 30 days are purged on unlock', async () => {
    const old = await vault.saveItem({ ...login('Ancient'), deletedAt: new Date(Date.now() - 31 * 86400_000).toISOString() });
    const recent = await vault.saveItem({ ...login('Recent'), deletedAt: new Date(Date.now() - 29 * 86400_000).toISOString() });
    const fresh = device(server);
    await fresh.unlock(EMAIL, PASSWORD);
    assert.equal(fresh.item(old.id), null);
    assert.ok(fresh.item(recent.id));
    fresh.lock();
    await vault.refresh();
  });

  test('folders: create, rename, and delete without losing items', async () => {
    const folder = await vault.saveFolder({ name: 'Work' });
    const item = await vault.saveItem({ ...login('Intranet'), folderId: folder.id });
    const renamed = await vault.saveFolder({ id: folder.id, name: 'Office' });
    assert.equal(renamed.id, folder.id);
    assert.equal(vault.folder(folder.id).name, 'Office');
    await assert.rejects(vault.saveFolder({ name: '   ' }));

    await vault.deleteFolder(folder.id);
    assert.equal(vault.folder(folder.id), null);
    assert.equal(vault.item(item.id).folderId, null, 'items move out of a deleted folder');
  });

  test('favorites', async () => {
    const item = await vault.saveItem(login('Starred'));
    await vault.setFavorite(item.id, true);
    assert.equal(vault.item(item.id).favorite, true);
    assert.equal(vault.item(item.id).updatedAt, item.updatedAt);
  });
});

describe('several devices', () => {
  let server;
  let laptop;
  let phone;

  before(async () => {
    server = await startServer();
    laptop = device(server);
    await laptop.signUp(EMAIL, PASSWORD);
    phone = device(server);
    await phone.unlock(EMAIL, PASSWORD);
  });
  after(() => server.close());

  test('changes made on one device reach the other', async () => {
    const item = await laptop.saveItem(login('Shared'));
    assert.equal(phone.item(item.id), null);

    let notified = 0;
    phone.addEventListener('change', () => (notified += 1));
    await phone.checkForChanges();
    assert.deepEqual(phone.item(item.id), item);
    assert.ok(notified >= 1);

    notified = 0;
    await phone.checkForChanges();
    assert.equal(notified, 0, 'nothing is re-downloaded when nothing changed');

    await laptop.deleteItems([item.id]);
    await phone.checkForChanges();
    assert.equal(phone.item(item.id), null);
  });

  test('conflicting edits are detected instead of overwriting each other', async () => {
    const item = await laptop.saveItem(login('Contested', { password: 'original' }));
    await phone.checkForChanges();

    await laptop.saveItem({ ...item, login: { ...item.login, password: 'from-laptop' } });
    const stale = phone.item(item.id);
    await assert.rejects(
      phone.saveItem({ ...stale, login: { ...stale.login, password: 'from-phone' } }),
      (err) => err instanceof VaultError && err.code === 'conflict',
    );
    // The phone now shows the laptop's version and can redo its edit on top of it.
    assert.equal(phone.item(item.id).login.password, 'from-laptop');
    const latest = phone.item(item.id);
    const merged = await phone.saveItem({ ...latest, login: { ...latest.login, password: 'from-phone' } });
    assert.deepEqual(merged.passwordHistory.map((entry) => entry.password), ['from-laptop', 'original']);

    await laptop.checkForChanges();
    assert.equal(laptop.item(item.id).login.password, 'from-phone');
  });

  test('a device that is behind catches up when it saves something else', async () => {
    const fromLaptop = await laptop.saveItem(login('Laptop item'));
    const fromPhone = await phone.saveItem(login('Phone item'));
    assert.ok(phone.item(fromLaptop.id), 'saving reveals what the other device added');
    await laptop.checkForChanges();
    assert.ok(laptop.item(fromPhone.id));
  });

  test('deleting an item that changed elsewhere is refused', async () => {
    const item = await laptop.saveItem(login('Restored elsewhere'));
    await phone.checkForChanges();
    await laptop.trashItems([item.id]);
    await assert.rejects(phone.deleteItems([item.id]), (err) => err.code === 'conflict');
    assert.ok(phone.item(item.id).deletedAt, 'the phone now sees the newer version');
  });

  test('changing the master password keeps the data and locks out the old password', async () => {
    const item = await laptop.saveItem(login('Survivor'));
    await assert.rejects(laptop.changeMasterPassword('not my password', 'whatever-new-password'), (err) => err.code === 'wrong_password');

    const NEW_PASSWORD = 'a brand new master password';
    await laptop.changeMasterPassword(PASSWORD, NEW_PASSWORD);
    assert.equal(laptop.unlocked, true, 'the device that made the change stays signed in');
    await laptop.saveItem(login('Saved after the change'));
    assert.equal(await laptop.verifyPassword(NEW_PASSWORD), true);
    assert.equal(await laptop.verifyPassword(PASSWORD), false);

    // Every other device is signed out the next time it talks to the server.
    const reasons = [];
    phone.addEventListener('lock', (event) => reasons.push(event.detail.reason));
    await assert.rejects(phone.checkForChanges());
    assert.equal(phone.unlocked, false);
    assert.deepEqual(reasons, ['expired']);

    await assert.rejects(phone.unlock(EMAIL, PASSWORD), (err) => err.code === 'invalid_credentials');
    await phone.unlock(EMAIL, NEW_PASSWORD);
    assert.deepEqual(phone.item(item.id), item);
    await phone.changeMasterPassword(NEW_PASSWORD, PASSWORD);
    await assert.rejects(laptop.checkForChanges());
    await laptop.unlock(EMAIL, PASSWORD);
  });
});

describe('importing', () => {
  let server;
  let vault;

  before(async () => {
    server = await startServer();
    vault = device(server);
    await vault.signUp(EMAIL, PASSWORD);
  });
  after(() => server.close());

  const bitwarden = JSON.stringify({
    encrypted: false,
    folders: [{ id: 'f1', name: 'Work' }],
    items: [
      { type: 1, name: 'Mail', folderId: 'f1', login: { username: 'ada', password: 'pw-1', uris: [{ uri: 'https://mail.example' }] } },
      { type: 1, name: 'Shop', folderId: null, login: { username: 'ada', password: 'pw-2', uris: [] } },
      { type: 2, name: 'Door code', notes: '4321' },
    ],
  });

  test('imports items and creates their folders', async () => {
    const result = await vault.importItems(parseImport(bitwarden).items);
    assert.deepEqual(result, { added: 3, skipped: 0, folders: 1 });
    assert.deepEqual(vault.folders.map((folder) => folder.name), ['Work']);
    const mail = vault.items.find((item) => item.name === 'Mail');
    assert.equal(mail.folderId, vault.folders[0].id);
    assert.equal(mail.login.password, 'pw-1');
  });

  test('importing the same file again adds nothing', async () => {
    const again = await vault.importItems(parseImport(bitwarden).items);
    assert.deepEqual(again, { added: 0, skipped: 3, folders: 0 });
    assert.equal(vault.items.length, 3);

    const forced = await vault.importItems(parseImport(bitwarden).items, { skipDuplicates: false });
    assert.equal(forced.added, 3);
    assert.equal(vault.folders.length, 1, 'existing folders are reused, not duplicated');
    assert.equal(vault.items.length, 6);
  });

  test('a large import arrives complete', async () => {
    const items = Array.from({ length: 1234 }, (_, index) => ({
      type: 'login',
      name: `Site ${index}`,
      folderName: `Group ${index % 7}`,
      login: { username: `user${index}`, password: `password-${index}`, uris: [`https://site${index}.example`] },
    }));
    const result = await vault.importItems(items);
    assert.equal(result.added, 1234);
    assert.equal(result.folders, 7);

    const other = device(server);
    await other.unlock(EMAIL, PASSWORD);
    assert.equal(other.items.length, 6 + 1234);
    assert.equal(other.items.find((item) => item.name === 'Site 1233').login.password, 'password-1233');
    other.lock();
  });

  test('an export from one vault imports into another without loss', async () => {
    const exported = JSON.stringify(toBitwardenJson(vault.items, vault.folders));
    const second = await startServer();
    try {
      const copy = device(second);
      await copy.signUp('copy@example.com', 'another long master password');
      // The source vault holds deliberate duplicates, so keep them all here too.
      await copy.importItems(parseImport(exported).items, { skipDuplicates: false });
      assert.equal(copy.items.length, vault.items.length);
      assert.deepEqual(copy.folders.map((f) => f.name), vault.folders.map((f) => f.name));
      const strip = ({ id, folderId, ...rest }) => rest;
      const sort = (list) => list.map(strip).sort((a, b) => a.name.localeCompare(b.name) || a.login?.password.localeCompare(b.login?.password));
      assert.deepEqual(sort(copy.items), sort(vault.items));
    } finally {
      await second.close();
    }
  });
});

describe('account removal and hostile servers', () => {
  test('deleting the account locks the vault and frees the address', async () => {
    const server = await startServer();
    try {
      const vault = device(server);
      await vault.signUp(EMAIL, PASSWORD);
      await vault.saveItem(login('Doomed'));
      await assert.rejects(vault.deleteAccount('wrong password'), (err) => err.code === 'wrong_password');
      assert.equal(vault.unlocked, true);

      const reasons = [];
      vault.addEventListener('lock', (event) => reasons.push(event.detail.reason));
      await vault.deleteAccount(PASSWORD);
      assert.equal(vault.unlocked, false);
      assert.deepEqual(reasons, ['deleted']);
      await assert.rejects(device(server).unlock(EMAIL, PASSWORD), (err) => err.code === 'invalid_credentials');
      await device(server).signUp(EMAIL, PASSWORD);
    } finally {
      await server.close();
    }
  });

  test('refuses a server that asks for weakened key derivation', async () => {
    const server = await startServer();
    try {
      const api = new Api(server.url);
      api.prelogin = async () => ({ kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 1 }, salt: 'AAAAAAAAAAAAAAAAAAAAAA==' });
      let sentCredentials = false;
      api.login = async () => {
        sentCredentials = true;
        throw new Error('should not be reached');
      };
      await assert.rejects(new Vault(api).unlock(EMAIL, PASSWORD), /Unsupported/);
      assert.equal(sentCredentials, false, 'no auth key may be derived or sent with weak settings');
    } finally {
      await server.close();
    }
  });

  test('records the server has tampered with are reported, not trusted', async () => {
    const server = await startServer();
    try {
      const vault = device(server);
      await vault.signUp(EMAIL, PASSWORD);
      const a = await vault.saveItem(login('A', { password: 'password-of-a' }));
      const b = await vault.saveItem(login('B', { password: 'password-of-b' }));
      vault.lock();
      await server.app.close();

      // Swap the two ciphertexts on disk, as a malicious host might.
      const dir = path.join(server.dataDir, 'accounts');
      const [file] = await readdir(dir);
      const { writeFile } = await import('node:fs/promises');
      const account = JSON.parse(await readFile(path.join(dir, file), 'utf8'));
      [account.records[a.id].data, account.records[b.id].data] = [account.records[b.id].data, account.records[a.id].data];
      await writeFile(path.join(dir, file), JSON.stringify(account));

      const restarted = await startServer({ dataDir: server.dataDir });
      try {
        const victim = device(restarted);
        await victim.unlock(EMAIL, PASSWORD);
        assert.equal(victim.items.length, 0, 'swapped records must not decrypt under the wrong id');
        assert.equal(victim.unreadable, 2);
      } finally {
        await restarted.close({ keepData: true });
      }
    } finally {
      await server.close();
    }
  });
});
