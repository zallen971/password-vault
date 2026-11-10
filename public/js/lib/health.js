// Vault health: finds logins whose passwords are weak, reused or sent over
// plain http. Runs entirely on decrypted data in memory.

import { estimateStrength } from './strength.js';

/**
 * @param {object[]} items
 * @returns {{logins: number, weak: {item: object, strength: object}[],
 *            reused: {items: object[]}[], insecure: object[]}}
 */
export function analyzeVault(items) {
  const logins = items.filter((item) => item.type === 'login' && !item.deletedAt && item.login.password);

  const weak = [];
  const byPassword = new Map();
  for (const item of logins) {
    const strength = estimateStrength(item.login.password);
    if (strength.score <= 1) weak.push({ item, strength });
    if (!byPassword.has(item.login.password)) byPassword.set(item.login.password, []);
    byPassword.get(item.login.password).push(item);
  }
  weak.sort((a, b) => a.strength.bits - b.strength.bits);

  const reused = [...byPassword.values()]
    .filter((group) => group.length > 1)
    .sort((a, b) => b.length - a.length)
    .map((group) => ({ items: group }));

  const insecure = logins.filter((item) => item.login.uris.some((uri) => /^http:\/\//i.test(uri.trim())));

  return { logins: logins.length, weak, reused, insecure };
}
