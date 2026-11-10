// Reads exports from Bitwarden and other password managers.
//
// Every importer returns the same thing: a list of item drafts (each with a
// `folderName` instead of a folder id) that the vault then encrypts and saves.

import { parseCsvRecords } from './csv.js';
import { hostOf } from './model.js';

export const BACKUP_FORMAT = 'password-vault-backup';

export class ImportError extends Error {}

const text = (value) => (typeof value === 'string' ? value : value == null ? '' : String(value));
const truthy = (value) => /^(1|true|yes|y|on)$/i.test(text(value).trim());

/**
 * @param {string} content  the file's text
 * @returns {{format: string, label: string, encrypted?: true, envelope?: object,
 *            items: object[], warnings: string[]}}
 */
export function parseImport(content) {
  const source = text(content).replace(/^﻿/, '').trim();
  if (!source) throw new ImportError('That file is empty.');

  if (source.startsWith('{') || source.startsWith('[')) {
    let data;
    try {
      data = JSON.parse(source);
    } catch {
      throw new ImportError('That file is not valid JSON. It may be damaged or incomplete.');
    }
    if (data?.format === BACKUP_FORMAT) {
      if (!data.kdf || !data.salt || !data.data) throw new ImportError('That backup file is incomplete.');
      return { format: 'backup', label: 'Encrypted Vault backup', encrypted: true, envelope: data, items: [], warnings: [] };
    }
    if (data?.encrypted === true) {
      throw new ImportError(
        'That Bitwarden export is encrypted, so it can only be opened by Bitwarden. ' +
          'Export again and choose the file format ".json" (not ".json (Encrypted)").',
      );
    }
    if (Array.isArray(data?.items)) return fromBitwardenJson(data);
    throw new ImportError('That JSON file is not a Bitwarden export or a Vault backup.');
  }

  return fromCsv(source);
}

// ---- Bitwarden JSON ----

const BITWARDEN_FIELD_TYPES = { 0: 'text', 1: 'hidden', 2: 'boolean' };

function fromBitwardenJson(data) {
  const names = new Map();
  for (const group of [...(data.folders ?? []), ...(data.collections ?? [])]) {
    if (group?.id) names.set(group.id, text(group.name).trim());
  }

  const items = [];
  let unsupported = 0;
  let passkeys = 0;

  for (const raw of data.items) {
    if (!raw || typeof raw !== 'object') {
      unsupported += 1;
      continue;
    }
    const base = {
      name: text(raw.name),
      notes: text(raw.notes),
      favorite: Boolean(raw.favorite),
      folderName: names.get(raw.folderId) ?? names.get(raw.collectionIds?.[0]) ?? '',
      fields: (Array.isArray(raw.fields) ? raw.fields : [])
        .filter((field) => field && field.type !== 3) // "linked" fields only point at other fields
        .map((field) => ({
          name: text(field.name),
          value: text(field.value),
          type: BITWARDEN_FIELD_TYPES[field.type] ?? 'text',
        })),
      passwordHistory: (Array.isArray(raw.passwordHistory) ? raw.passwordHistory : []).map((entry) => ({
        password: text(entry?.password),
        changedAt: entry?.lastUsedDate,
      })),
      createdAt: raw.creationDate,
      updatedAt: raw.revisionDate,
    };

    if (raw.type === 1) {
      const login = raw.login ?? {};
      passkeys += Array.isArray(login.fido2Credentials) ? login.fido2Credentials.length : 0;
      items.push({
        ...base,
        type: 'login',
        login: {
          username: text(login.username),
          password: text(login.password),
          totp: text(login.totp),
          uris: (Array.isArray(login.uris) ? login.uris : []).map((entry) => text(entry?.uri)),
        },
      });
    } else if (raw.type === 2) {
      items.push({ ...base, type: 'note' });
    } else if (raw.type === 3) {
      const card = raw.card ?? {};
      items.push({
        ...base,
        type: 'card',
        card: {
          cardholder: text(card.cardholderName),
          brand: text(card.brand),
          number: text(card.number),
          expMonth: text(card.expMonth),
          expYear: text(card.expYear),
          code: text(card.code),
        },
      });
    } else if (raw.type === 4) {
      items.push({ ...base, type: 'identity', identity: { ...(raw.identity ?? {}) } });
    } else if (raw.type === 5 && raw.sshKey) {
      // SSH keys have no dedicated type here; keep them as a note with hidden fields.
      items.push({
        ...base,
        type: 'note',
        fields: [
          ...base.fields,
          { name: 'Private key', value: text(raw.sshKey.privateKey), type: 'hidden' },
          { name: 'Public key', value: text(raw.sshKey.publicKey), type: 'text' },
          { name: 'Fingerprint', value: text(raw.sshKey.keyFingerprint), type: 'text' },
        ],
      });
    } else {
      unsupported += 1;
    }
  }

  const warnings = [];
  if (passkeys) {
    warnings.push(
      `${passkeys} passkey${passkeys === 1 ? '' : 's'} cannot be moved between password managers and will be left behind.`,
    );
  }
  if (unsupported) warnings.push(`${unsupported} item${unsupported === 1 ? ' is' : 's are'} of a type that is not supported and will be skipped.`);
  return { format: 'bitwarden-json', label: 'Bitwarden (JSON)', items, warnings };
}

// ---- CSV ----

// Column names used by Bitwarden, Chrome, Edge, Firefox, Safari, 1Password,
// LastPass, Dashlane, KeePass and NordPass, most specific first.
const COLUMNS = {
  name: ['name', 'title', 'account', 'item name', 'entry'],
  url: ['login_uri', 'url', 'uri', 'website', 'web site', 'login url', 'web address', 'site'],
  username: ['login_username', 'username', 'user name', 'user', 'login', 'login name', 'email', 'e-mail'],
  password: ['login_password', 'password', 'pass', 'pwd'],
  notes: ['notes', 'note', 'extra', 'comments', 'comment'],
  totp: ['login_totp', 'totp', 'otpauth', 'otpsecret', 'otp secret', 'otp', 'two factor secret'],
  folder: ['folder', 'grouping', 'group', 'category'],
  favorite: ['favorite', 'favourite', 'fav'],
};

function fromCsv(source) {
  const { headers, records } = parseCsvRecords(source);
  const column = Object.fromEntries(
    Object.entries(COLUMNS).map(([key, aliases]) => [key, aliases.find((alias) => headers.includes(alias)) ?? null]),
  );
  if (!column.password && !column.username && !column.url && !column.notes) {
    throw new ImportError(
      'Could not find any recognizable columns. The first row must name the columns, ' +
        'for example: name, url, username, password, notes.',
    );
  }
  const isBitwarden = headers.includes('login_uri') || headers.includes('login_password');
  const get = (record, key) => (column[key] ? text(record[column[key]]) : '');

  const items = [];
  for (const record of records) {
    const url = get(record, 'url').trim();
    const username = get(record, 'username');
    const password = get(record, 'password');
    const notes = get(record, 'notes');
    const totp = get(record, 'totp').trim();
    let name = get(record, 'name').trim();
    if (!name && !url && !username && !password && !notes) continue;

    // Bitwarden marks notes with type "note"; LastPass with the placeholder URL "http://sn".
    const isNote =
      (isBitwarden && text(record.type).trim().toLowerCase() === 'note') ||
      url === 'http://sn' ||
      (!url && !username && !password && !totp);

    const item = {
      type: isNote ? 'note' : 'login',
      name,
      notes,
      favorite: truthy(get(record, 'favorite')),
      folderName: get(record, 'folder').trim(),
      fields: isBitwarden ? bitwardenCsvFields(record.fields) : [],
    };
    if (!isNote) {
      // Bitwarden writes several addresses for one login as a comma-separated list.
      const uris = isBitwarden ? url.split(',').map((part) => part.trim()) : [url];
      item.login = { username, password, totp, uris: uris.filter(Boolean) };
      if (!name && item.login.uris[0]) name = hostOf(item.login.uris[0]);
    }
    item.name = name || (isNote ? 'Imported note' : 'Imported login');
    items.push(item);
  }

  if (!items.length) throw new ImportError('That file does not contain any items.');
  return { format: isBitwarden ? 'bitwarden-csv' : 'csv', label: isBitwarden ? 'Bitwarden (CSV)' : 'CSV', items, warnings: [] };
}

/** Bitwarden's CSV packs custom fields into one cell as "name: value" lines. */
function bitwardenCsvFields(cell) {
  return text(cell)
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => {
      const split = line.indexOf(': ');
      return split === -1
        ? { name: line.trim(), value: '', type: 'text' }
        : { name: line.slice(0, split).trim(), value: line.slice(split + 2), type: 'text' };
    });
}
