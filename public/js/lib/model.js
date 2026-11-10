// The shape of everything stored in a vault, plus small pure helpers.
// Records are plain JSON objects; they are encrypted as a whole before they
// leave the device, so none of these fields are visible to the server.

export const ITEM_TYPES = Object.freeze(['login', 'note', 'card', 'identity']);

export const TYPE_INFO = Object.freeze({
  login: { label: 'Login', plural: 'Logins', icon: 'globe' },
  note: { label: 'Secure note', plural: 'Secure notes', icon: 'note' },
  card: { label: 'Card', plural: 'Cards', icon: 'card' },
  identity: { label: 'Identity', plural: 'Identities', icon: 'user' },
});

export const CARD_BRANDS = Object.freeze([
  'Visa', 'Mastercard', 'American Express', 'Discover', 'Diners Club', 'JCB', 'Maestro', 'UnionPay', 'RuPay', 'Other',
]);

/** `secret` fields are masked until revealed; `half` fields share a row in forms. */
export const CARD_FIELDS = Object.freeze([
  { key: 'cardholder', label: 'Cardholder name' },
  { key: 'number', label: 'Card number', secret: true, mono: true, inputMode: 'numeric' },
  { key: 'brand', label: 'Brand', options: CARD_BRANDS, half: true },
  { key: 'code', label: 'Security code', secret: true, mono: true, inputMode: 'numeric', half: true },
  { key: 'expMonth', label: 'Expiry month', placeholder: 'MM', inputMode: 'numeric', half: true },
  { key: 'expYear', label: 'Expiry year', placeholder: 'YYYY', inputMode: 'numeric', half: true },
]);

export const IDENTITY_FIELDS = Object.freeze([
  { key: 'title', label: 'Title', half: true },
  { key: 'firstName', label: 'First name', half: true },
  { key: 'middleName', label: 'Middle name', half: true },
  { key: 'lastName', label: 'Last name', half: true },
  { key: 'username', label: 'Username', half: true },
  { key: 'company', label: 'Company', half: true },
  { key: 'email', label: 'Email', half: true, inputMode: 'email' },
  { key: 'phone', label: 'Phone', half: true, inputMode: 'tel' },
  { key: 'ssn', label: 'Social Security / national ID number', secret: true, mono: true },
  { key: 'passportNumber', label: 'Passport number', secret: true, mono: true, half: true },
  { key: 'licenseNumber', label: 'Licence number', secret: true, mono: true, half: true },
  { key: 'address1', label: 'Address line 1' },
  { key: 'address2', label: 'Address line 2' },
  { key: 'address3', label: 'Address line 3' },
  { key: 'city', label: 'City / town', half: true },
  { key: 'state', label: 'State / province', half: true },
  { key: 'postalCode', label: 'ZIP / postal code', half: true },
  { key: 'country', label: 'Country', half: true },
]);

export const FIELD_TYPES = Object.freeze(['text', 'hidden', 'boolean']);
export const MAX_PASSWORD_HISTORY = 10;
export const TRASH_RETENTION_DAYS = 30;

const text = (value) => (typeof value === 'string' ? value : value == null ? '' : String(value));

function isoDate(value) {
  if (!value) return null;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

const pickText = (source, fields) => Object.fromEntries(fields.map(({ key }) => [key, text(source?.[key]).trim()]));

/** Returns a complete, well-formed item no matter how sparse or odd the input is. */
export function normalizeItem(input = {}) {
  const type = ITEM_TYPES.includes(input.type) ? input.type : 'login';
  const now = new Date().toISOString();
  const item = {
    id: text(input.id) || crypto.randomUUID(),
    kind: 'item',
    type,
    name: text(input.name).trim(),
    folderId: input.folderId ? text(input.folderId) : null,
    favorite: Boolean(input.favorite),
    notes: text(input.notes),
    fields: (Array.isArray(input.fields) ? input.fields : [])
      .map((field) => {
        const kind = FIELD_TYPES.includes(field?.type) ? field.type : 'text';
        const value = kind === 'boolean' ? String(field?.value === true || field?.value === 'true') : text(field?.value);
        return { name: text(field?.name).trim(), value, type: kind };
      })
      .filter((field) => field.name || field.value),
    passwordHistory: (Array.isArray(input.passwordHistory) ? input.passwordHistory : [])
      .filter((entry) => entry && text(entry.password))
      .map((entry) => ({ password: text(entry.password), changedAt: isoDate(entry.changedAt) || now }))
      .slice(0, MAX_PASSWORD_HISTORY),
    createdAt: isoDate(input.createdAt) || now,
    updatedAt: isoDate(input.updatedAt) || now,
    deletedAt: isoDate(input.deletedAt),
  };
  if (type === 'login') {
    const login = input.login ?? {};
    item.login = {
      username: text(login.username),
      password: text(login.password),
      totp: text(login.totp).trim(),
      uris: (Array.isArray(login.uris) ? login.uris : []).map((uri) => text(uri).trim()).filter(Boolean),
    };
  } else if (type === 'card') {
    item.card = pickText(input.card, CARD_FIELDS);
  } else if (type === 'identity') {
    item.identity = pickText(input.identity, IDENTITY_FIELDS);
  }
  return item;
}

export function normalizeFolder(input = {}) {
  const now = new Date().toISOString();
  return {
    id: text(input.id) || crypto.randomUUID(),
    kind: 'folder',
    name: text(input.name).trim(),
    createdAt: isoDate(input.createdAt) || now,
    updatedAt: isoDate(input.updatedAt) || now,
  };
}

/** A blank item of the given type, ready for the editor. */
export function blankItem(type, folderId = null) {
  const item = normalizeItem({ type, folderId });
  if (type === 'login') item.login.uris = [''];
  return item;
}

/**
 * Turns whatever the user typed into a web address that is safe to open.
 * Only http(s) is ever returned: "javascript:" and friends must never launch.
 */
export function launchUrl(uri) {
  const value = text(uri).trim();
  if (!value || /\s/.test(value)) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value) && !/^[^/:]+:\d+(\/|$)/.test(value) ? value : `https://${value}`;
  try {
    const url = new URL(candidate);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (!url.hostname.includes('.') && url.hostname !== 'localhost') return null;
    return url.href;
  } catch {
    return null;
  }
}

/** "https://www.example.com/login" -> "example.com". Falls back to the raw text. */
export function hostOf(uri) {
  const url = launchUrl(uri);
  if (!url) return text(uri).trim();
  return new URL(url).hostname.replace(/^www\./, '');
}

export function fullName(identity) {
  return [identity?.title, identity?.firstName, identity?.middleName, identity?.lastName].filter(Boolean).join(' ');
}

/** The secondary line shown under an item's name. Never reveals a secret. */
export function itemSubtitle(item) {
  if (item.type === 'login') return item.login.username || (item.login.uris[0] ? hostOf(item.login.uris[0]) : '');
  if (item.type === 'card') {
    const digits = item.card.number.replace(/\D/g, '');
    return [item.card.brand, digits ? `•••• ${digits.slice(-4)}` : ''].filter(Boolean).join(' ');
  }
  if (item.type === 'identity') return fullName(item.identity) || item.identity.email || item.identity.company;
  return '';
}

export function displayName(item) {
  if (item.name) return item.name;
  if (item.type === 'login' && item.login.uris[0]) return hostOf(item.login.uris[0]);
  return 'Untitled';
}

/** Guesses the card network from the first digits of the number. */
export function detectCardBrand(number) {
  const digits = text(number).replace(/\D/g, '');
  if (/^4/.test(digits)) return 'Visa';
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(digits)) return 'Mastercard';
  if (/^3[47]/.test(digits)) return 'American Express';
  if (/^(6011|65|64[4-9])/.test(digits)) return 'Discover';
  if (/^(30[0-5]|36|38)/.test(digits)) return 'Diners Club';
  if (/^35(2[89]|[3-8])/.test(digits)) return 'JCB';
  if (/^62/.test(digits)) return 'UnionPay';
  if (/^(50|5[6-9]|6[37])/.test(digits)) return 'Maestro';
  return '';
}

export function formatCardNumber(number) {
  const digits = text(number).replace(/\s+/g, '');
  if (!/^\d+$/.test(digits)) return text(number);
  if (/^3[47]/.test(digits)) return digits.replace(/^(\d{4})(\d{0,6})(\d{0,5}).*/, '$1 $2 $3').trim();
  return digits.replace(/(\d{4})(?=\d)/g, '$1 ');
}

/** Lower-cased text an item can be found by. Secrets are deliberately excluded. */
export function searchText(item, folderName = '') {
  const parts = [item.name, item.notes, folderName];
  for (const field of item.fields) {
    parts.push(field.name);
    if (field.type === 'text') parts.push(field.value);
  }
  if (item.type === 'login') parts.push(item.login.username, ...item.login.uris);
  if (item.type === 'card') parts.push(item.card.cardholder, item.card.brand, item.card.number.replace(/\D/g, '').slice(-4));
  if (item.type === 'identity') {
    const id = item.identity;
    parts.push(fullName(id), id.username, id.company, id.email, id.phone, id.city, id.country);
  }
  return parts.filter(Boolean).join('\n').toLowerCase();
}

/** A stable fingerprint of an item's content, used to skip duplicates on import. */
export function contentKey(item) {
  const core = { type: item.type, name: item.name, notes: item.notes, fields: item.fields };
  if (item.type === 'login') core.login = item.login;
  if (item.type === 'card') core.card = item.card;
  if (item.type === 'identity') core.identity = item.identity;
  return JSON.stringify(core);
}
