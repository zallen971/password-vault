// Optional check against Have I Been Pwned's "Pwned Passwords" list.
//
// Uses k-anonymity: each password is hashed locally and only the first five
// characters of the hash are sent. The service replies with every hash that
// shares that prefix and the match is made on this device, so neither the
// password nor its full hash ever leaves the browser.

import { sha1Hex } from './crypto.js';

const RANGE_URL = 'https://api.pwnedpasswords.com/range/';
const PARALLEL = 4;

/**
 * @param {string[]} passwords
 * @param {{fetch?: typeof fetch, onProgress?: (done: number, total: number) => void}} [options]
 * @returns {Promise<Map<string, number>>} password -> times seen in breaches (0 = never)
 */
export async function findBreachedPasswords(passwords, options = {}) {
  const request = options.fetch ?? fetch;
  const unique = [...new Set(passwords.filter(Boolean))];
  const results = new Map(unique.map((password) => [password, 0]));

  const groups = new Map(); // hash prefix -> [{ password, suffix }]
  for (const password of unique) {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    if (!groups.has(prefix)) groups.set(prefix, []);
    groups.get(prefix).push({ password, suffix: hash.slice(5) });
  }

  const pending = [...groups];
  const total = pending.length;
  let done = 0;
  const worker = async () => {
    while (pending.length) {
      const [prefix, entries] = pending.pop();
      const response = await request(RANGE_URL + prefix, { credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (!response.ok) throw new Error(`Breach lookup failed (${response.status})`);
      const counts = new Map();
      for (const line of (await response.text()).split('\n')) {
        const [suffix, count] = line.trim().split(':');
        if (suffix) counts.set(suffix.toUpperCase(), Number.parseInt(count, 10) || 0);
      }
      for (const { password, suffix } of entries) results.set(password, counts.get(suffix) ?? 0);
      done += 1;
      options.onProgress?.(done, total);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL, total) }, worker));
  return results;
}
