// Time-based one-time passwords (RFC 6238), the codes an authenticator app shows.

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export function decodeBase32(text) {
  const clean = String(text).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean) throw new Error('Empty secret');
  const bytes = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of clean) {
    const value = BASE32.indexOf(char);
    if (value === -1) throw new Error('Secret is not valid base32');
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[index] = (buffer >>> bits) & 0xff;
      index += 1;
    }
  }
  if (!bytes.length) throw new Error('Secret is too short');
  return bytes;
}

/**
 * Accepts either a bare base32 secret or an otpauth://totp/ URI.
 * @returns {{secret: Uint8Array, algorithm: string, digits: number, period: number} | null}
 */
export function parseTotp(input) {
  const text = String(input ?? '').trim();
  if (!text) return null;
  try {
    if (/^otpauth:\/\//i.test(text)) {
      const url = new URL(text);
      if (url.host.toLowerCase() !== 'totp') return null;
      const algorithm = ALGORITHMS[(url.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-', '')];
      const digits = Number(url.searchParams.get('digits') || 6);
      const period = Number(url.searchParams.get('period') || 30);
      if (!algorithm || !Number.isInteger(digits) || digits < 6 || digits > 10) return null;
      if (!Number.isInteger(period) || period < 1 || period > 3600) return null;
      return { secret: decodeBase32(url.searchParams.get('secret') || ''), algorithm, digits, period };
    }
    return { secret: decodeBase32(text), algorithm: 'SHA-1', digits: 6, period: 30 };
  } catch {
    return null;
  }
}

/** @returns {Promise<{code: string, remaining: number, period: number}>} */
export async function generateTotp(config, now = Date.now()) {
  const seconds = Math.floor(now / 1000);
  const counter = Math.floor(seconds / config.period);
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));

  const key = await crypto.subtle.importKey('raw', config.secret, { name: 'HMAC', hash: config.algorithm }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  const code = String(binary % 10 ** config.digits).padStart(config.digits, '0');
  return { code, remaining: config.period - (seconds % config.period), period: config.period };
}
