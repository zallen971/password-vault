// All cryptography happens here, in the browser, using the Web Crypto API.
//
//   master password ──PBKDF2-SHA256 (600k)──▶ master key
//   master key ──HKDF──▶ auth key   (sent to the server to sign in)
//   master key ──HKDF──▶ wrap key   (never leaves this device)
//   wrap key   ──AES-256-GCM──▶ protects the random vault key
//   vault key  ──AES-256-GCM──▶ encrypts every record
//
// The server stores only ciphertext and a hash of the auth key, so it cannot
// read a vault, and neither can anyone who copies its data directory.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const DEFAULT_KDF = Object.freeze({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000 });

// Settings outside this range are refused. The floor matters: it stops a
// tampered server (or backup file) from talking this device into deriving
// keys so cheaply that the password could be brute-forced.
export const MIN_KDF_ITERATIONS = 100_000;
export const MAX_KDF_ITERATIONS = 10_000_000;

const HKDF_SALT = encoder.encode('password-vault/v1');
const BLOB_VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_AAD = 'vault-key';

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Stretches a password into 32 bytes of key material. Deliberately slow. */
export async function deriveMasterKey(password, salt, kdf = DEFAULT_KDF) {
  const supported =
    kdf?.name === 'PBKDF2' &&
    kdf.hash === 'SHA-256' &&
    Number.isInteger(kdf.iterations) &&
    kdf.iterations >= MIN_KDF_ITERATIONS &&
    kdf.iterations <= MAX_KDF_ITERATIONS;
  if (!supported) throw new Error('Unsupported key derivation settings');
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password.normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: kdf.iterations },
    material,
    256,
  );
  return new Uint8Array(bits);
}

async function expand(masterKey, purpose) {
  const base = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: encoder.encode(purpose) },
    base,
    256,
  );
  return new Uint8Array(bits);
}

const importAesKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

/**
 * Turns a master password into the two keys a session needs. The auth key is
 * safe to send to the server; it cannot be turned back into the wrap key.
 * @returns {Promise<{authKey: string, wrapKey: CryptoKey}>}
 */
export async function deriveLoginKeys(password, saltBase64, kdf) {
  const masterKey = await deriveMasterKey(password, fromBase64(saltBase64), kdf);
  try {
    const [auth, wrap] = await Promise.all([expand(masterKey, 'auth'), expand(masterKey, 'wrap')]);
    const keys = { authKey: toBase64(auth), wrapKey: await importAesKey(wrap) };
    auth.fill(0);
    wrap.fill(0);
    return keys;
  } finally {
    masterKey.fill(0);
  }
}

/** Everything needed to register a new account, generated locally. */
export async function createAccountKeys(password, kdf = DEFAULT_KDF) {
  const salt = toBase64(randomBytes(16));
  const { authKey, wrapKey } = await deriveLoginKeys(password, salt, kdf);
  const rawVaultKey = randomBytes(32);
  try {
    return {
      kdf: { ...kdf },
      salt,
      authKey,
      wrapKey,
      protectedKey: await encryptBytes(wrapKey, rawVaultKey, KEY_AAD),
      vaultKey: await importAesKey(rawVaultKey),
    };
  } finally {
    rawVaultKey.fill(0);
  }
}

/** Unlocks the vault key. Throws if the wrap key (i.e. the password) is wrong. */
export async function openVaultKey(protectedKey, wrapKey) {
  const raw = await decryptBytes(wrapKey, protectedKey, KEY_AAD);
  try {
    return await importAesKey(raw);
  } finally {
    raw.fill(0);
  }
}

/** Re-protects the same vault key under a new password; records stay untouched. */
export async function rewrapVaultKey(protectedKey, oldWrapKey, newWrapKey) {
  const raw = await decryptBytes(oldWrapKey, protectedKey, KEY_AAD);
  try {
    return await encryptBytes(newWrapKey, raw, KEY_AAD);
  } finally {
    raw.fill(0);
  }
}

/**
 * AES-256-GCM with a fresh random nonce. `context` is authenticated but not
 * stored: decryption fails unless the same context is supplied, which stops
 * ciphertexts from being swapped between records.
 * Output: base64( version | nonce | ciphertext + tag ).
 */
export async function encryptBytes(key, plaintext, context) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(context) }, key, plaintext),
  );
  const blob = new Uint8Array(1 + IV_BYTES + ciphertext.length);
  blob[0] = BLOB_VERSION;
  blob.set(iv, 1);
  blob.set(ciphertext, 1 + IV_BYTES);
  return toBase64(blob);
}

export async function decryptBytes(key, blobBase64, context) {
  const blob = fromBase64(blobBase64);
  if (blob.length < 1 + IV_BYTES + TAG_BYTES || blob[0] !== BLOB_VERSION) {
    throw new Error('Unrecognized or damaged ciphertext');
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.subarray(1, 1 + IV_BYTES), additionalData: encoder.encode(context) },
    key,
    blob.subarray(1 + IV_BYTES),
  );
  return new Uint8Array(plaintext);
}

export async function encryptJson(key, value, context) {
  return encryptBytes(key, encoder.encode(JSON.stringify(value)), context);
}

export async function decryptJson(key, blobBase64, context) {
  return JSON.parse(decoder.decode(await decryptBytes(key, blobBase64, context)));
}

// ---- Password-protected files (encrypted backups) ----

const FILE_AAD = 'vault-backup';

/** Encrypts text under a password of its own, independent of any account. */
export async function encryptWithPassword(password, text, kdf = DEFAULT_KDF) {
  const salt = randomBytes(16);
  const masterKey = await deriveMasterKey(password, salt, kdf);
  try {
    const key = await importAesKey(await expand(masterKey, 'backup'));
    return { kdf: { ...kdf }, salt: toBase64(salt), data: await encryptBytes(key, encoder.encode(text), FILE_AAD) };
  } finally {
    masterKey.fill(0);
  }
}

/** Throws if the password is wrong or the file was tampered with. */
export async function decryptWithPassword(password, { kdf, salt, data }) {
  const masterKey = await deriveMasterKey(password, fromBase64(salt), kdf);
  try {
    const key = await importAesKey(await expand(masterKey, 'backup'));
    return decoder.decode(await decryptBytes(key, data, FILE_AAD));
  } finally {
    masterKey.fill(0);
  }
}

/** SHA-1 as upper-case hex. Used only for the breached-password range lookup. */
export async function sha1Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', encoder.encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
