// Exports. The plain formats match Bitwarden's own, so a vault can always be
// taken elsewhere: nothing here locks your data in.

import { toCsv } from './csv.js';
import { encryptWithPassword, decryptWithPassword } from './crypto.js';
import { BACKUP_FORMAT } from './importers.js';

const TYPE_CODES = { login: 1, note: 2, card: 3, identity: 4 };
const FIELD_CODES = { text: 0, hidden: 1, boolean: 2 };
const orNull = (value) => (value === '' || value == null ? null : value);

function toBitwardenItem(item) {
  const out = {
    id: item.id,
    organizationId: null,
    folderId: item.folderId,
    type: TYPE_CODES[item.type],
    reprompt: 0,
    name: item.name,
    notes: orNull(item.notes),
    favorite: item.favorite,
    fields: item.fields.map((field) => ({
      name: field.name,
      value: field.value,
      type: FIELD_CODES[field.type] ?? 0,
      linkedId: null,
    })),
    passwordHistory: item.passwordHistory.length
      ? item.passwordHistory.map((entry) => ({ lastUsedDate: entry.changedAt, password: entry.password }))
      : null,
    revisionDate: item.updatedAt,
    creationDate: item.createdAt,
    deletedDate: null,
    collectionIds: null,
  };
  if (item.type === 'login') {
    out.login = {
      uris: item.login.uris.map((uri) => ({ match: null, uri })),
      username: orNull(item.login.username),
      password: orNull(item.login.password),
      totp: orNull(item.login.totp),
    };
  } else if (item.type === 'note') {
    out.secureNote = { type: 0 };
  } else if (item.type === 'card') {
    const { cardholder, ...card } = item.card;
    out.card = Object.fromEntries(Object.entries({ cardholderName: cardholder, ...card }).map(([k, v]) => [k, orNull(v)]));
  } else if (item.type === 'identity') {
    out.identity = Object.fromEntries(Object.entries(item.identity).map(([k, v]) => [k, orNull(v)]));
  }
  return out;
}

/** Items in the trash are never exported. */
const exportable = (items) => items.filter((item) => !item.deletedAt);

/** Bitwarden's unencrypted JSON export format. */
export function toBitwardenJson(items, folders) {
  return {
    encrypted: false,
    folders: folders.map((folder) => ({ id: folder.id, name: folder.name })),
    items: exportable(items).map(toBitwardenItem),
  };
}

/** Bitwarden's CSV export format. Like Bitwarden's, it only covers logins and notes. */
export function toBitwardenCsv(items, folders) {
  const folderNames = new Map(folders.map((folder) => [folder.id, folder.name]));
  const rows = [
    ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'],
  ];
  for (const item of exportable(items)) {
    if (item.type !== 'login' && item.type !== 'note') continue;
    const login = item.login ?? { uris: [], username: '', password: '', totp: '' };
    rows.push([
      folderNames.get(item.folderId) ?? '',
      item.favorite ? '1' : '',
      item.type,
      item.name,
      item.notes,
      item.fields.map((field) => `${field.name}: ${field.value}`).join('\n'),
      '0',
      login.uris.join(','),
      login.username,
      login.password,
      login.totp,
    ]);
  }
  return toCsv(rows);
}

/** A password-protected backup: the JSON export, encrypted with AES-256-GCM. */
export async function toEncryptedBackup(items, folders, password, kdf) {
  const payload = JSON.stringify(toBitwardenJson(items, folders));
  const sealed = await encryptWithPassword(password, payload, kdf);
  return { format: BACKUP_FORMAT, version: 1, createdAt: new Date().toISOString(), ...sealed };
}

/** Returns the JSON text inside a backup. Throws if the password is wrong. */
export function openEncryptedBackup(envelope, password) {
  return decryptWithPassword(password, envelope);
}
