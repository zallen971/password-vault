// Password and passphrase generation using the browser's secure random source.

import { WORDS } from './wordlist.js';

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*-_';
const AMBIGUOUS = /[Il1O0]/g;

export const PASSWORD_LENGTH = Object.freeze({ min: 5, max: 128 });
export const PASSPHRASE_WORDS = Object.freeze({ min: 3, max: 12 });

export const DEFAULT_PASSWORD_OPTIONS = Object.freeze({
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  avoidAmbiguous: false,
});

export const DEFAULT_PASSPHRASE_OPTIONS = Object.freeze({
  words: 5,
  separator: '-',
  capitalize: false,
  includeNumber: false,
});

/** Uniform random integer in [0, max), without modulo bias. */
export function randomInt(max) {
  if (!Number.isInteger(max) || max < 1 || max > 0x100000000) throw new RangeError('max out of range');
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);
  let value;
  do {
    crypto.getRandomValues(buffer);
    [value] = buffer;
  } while (value >= limit);
  return value % max;
}

const pick = (alphabet) => alphabet[randomInt(alphabet.length)];
const clamp = (value, { min, max }, fallback) => {
  const number = Number.parseInt(value, 10);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : fallback;
};

function shuffle(items) {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

function passwordAlphabets(options) {
  const sets = [];
  if (options.lowercase) sets.push(LOWER);
  if (options.uppercase) sets.push(UPPER);
  if (options.numbers) sets.push(DIGITS);
  if (options.symbols) sets.push(SYMBOLS);
  if (!sets.length) sets.push(LOWER);
  return options.avoidAmbiguous ? sets.map((set) => set.replace(AMBIGUOUS, '')) : sets;
}

export function normalizePasswordOptions(options = {}) {
  const merged = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  merged.length = clamp(merged.length, PASSWORD_LENGTH, DEFAULT_PASSWORD_OPTIONS.length);
  for (const key of ['uppercase', 'lowercase', 'numbers', 'symbols', 'avoidAmbiguous']) merged[key] = Boolean(merged[key]);
  if (!merged.uppercase && !merged.lowercase && !merged.numbers && !merged.symbols) merged.lowercase = true;
  return merged;
}

export function normalizePassphraseOptions(options = {}) {
  const merged = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  merged.words = clamp(merged.words, PASSPHRASE_WORDS, DEFAULT_PASSPHRASE_OPTIONS.words);
  merged.separator = String(merged.separator ?? '').slice(0, 3);
  merged.capitalize = Boolean(merged.capitalize);
  merged.includeNumber = Boolean(merged.includeNumber);
  return merged;
}

/** A random password containing at least one character from every enabled set. */
export function generatePassword(options) {
  const opts = normalizePasswordOptions(options);
  const sets = passwordAlphabets(opts);
  const all = sets.join('');
  const chars = sets.slice(0, opts.length).map(pick);
  while (chars.length < opts.length) chars.push(pick(all));
  return shuffle(chars).join('');
}

/** Random words from the EFF list, e.g. "plaza-unbolted-crisply-moisture-refined". */
export function generatePassphrase(options) {
  const opts = normalizePassphraseOptions(options);
  const words = Array.from({ length: opts.words }, () => {
    const word = pick(WORDS);
    return opts.capitalize ? word[0].toUpperCase() + word.slice(1) : word;
  });
  if (opts.includeNumber) words[randomInt(words.length)] += String(randomInt(10));
  return words.join(opts.separator);
}

/** Entropy in bits of a generated password (ignoring the tiny cost of forcing one character per set). */
export function passwordEntropy(options) {
  const opts = normalizePasswordOptions(options);
  return opts.length * Math.log2(passwordAlphabets(opts).join('').length);
}

export function passphraseEntropy(options) {
  const opts = normalizePassphraseOptions(options);
  const numberBits = opts.includeNumber ? Math.log2(10 * opts.words) : 0;
  return opts.words * Math.log2(WORDS.length) + numberBits;
}
