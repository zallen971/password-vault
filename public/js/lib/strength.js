// A small, dependency-free password strength estimator.
//
// It is a heuristic, not a guarantee. The password is split into runs of
// letters, digits and symbols. Runs that look like something a person would
// choose (words, years, sequences, repeats, "l33t" spellings, well-known
// passwords) are costed as such; everything else is costed as random
// characters. The total is an estimate of entropy in bits.

import { WORDS } from './wordlist.js';

export const STRENGTH_LABELS = Object.freeze(['Very weak', 'Weak', 'Fair', 'Good', 'Strong']);

const COMMON = new Set(
  `123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123 football
  monkey letmein shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx
  7777777 121212 000000 qazwsx 123qwe killer trustno jordan jennifer zxcvbnm asdfgh hunter buster soccer harley
  batman andrew tigger sunshine iloveyou charlie robert thomas hockey ranger daniel starwars 112233 george
  computer michelle jessica pepper zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 aaaaaa ginger
  princess joshua cheese amanda summer love ashley nicole chelsea biteme matthew access yankees 987654321 dallas
  austin thunder taylor matrix welcome admin login password1 hello whatever secret changeme default guest root
  test temp administrator qwerty123 1q2w3e4r 1q2w3e q1w2e3r4 zaq12wsx qwe123 asdfghjkl asdf lovely flower hottie
  loveme donald internet google apple samsung pokemon naruto minecraft liverpool arsenal barcelona winter spring
  autumn monday friday sunday january february march april june july august september october november december
  money family purple orange banana cookie chocolate butterfly angel baby babygirl friend friends forever
  nothing superstar eagles cowboys steelers lakers tiger basketball golfer bailey buddy maxwell lucky merlin
  diamond silver golden phoenix mercedes ferrari porsche corvette yamaha honda toyota nissan jaguar scooter
  snoopy mickey bubbles peanut simpsons spiderman ironman avengers pirate ninja wizard hacker security system
  server network windows linux ubuntu oracle cisco router wifi wireless office company business manager service
  support user username example sample demo vault bitwarden lastpass keepass passphrase letmeinnow iloveu
  qazwsxedc azerty zxcvb poiuyt mnbvcxz abcd abcdef abcdefg abcdefgh abcd1234 aa123456 pass123 pass1234
  passw admin123 root123 test123 welcome1 welcome123 hello123 love123 master123 jesus christ heaven blessed
  faith grace hope peace happy smile dream magic secret1 mypassword mypass newpassword newpass oldpassword
  1qaz2wsx3edc 1qazxsw2 zaq1xsw2 qweasdzxc 1q2w3e4r5t q1w2e3r4t5 asdfzxcv poiuytrewq a1b2c3d4 a1b2c3 1a2b3c4d
  birthday sydney tokyo london paris`
    .split(/\s+/)
    .filter(Boolean),
);

// Very common short words, which are too short for the statistical test below.
const SHORT_WORDS = `the and for you not are but all can her was one our out day get has him his how man new now
  old see two way who boy did its let put say she too use dad mom dog cat sun red big top hot sex god job car bad
  fun win joy sky sea ice war law art age air arm bed box bus cup cut eye far fat fly gun hat key kid lab leg lip
  low map mix net oil pay pen pet pie pig pin pop ran rat raw run sad sit six ten tie toy van wet yes yet zoo
  love baby blue cool fire girl game home king life lion live mine moon nice open pink play rock rose star time
  wolf word work year your john mike dave anna emma jack luke mary paul adam alex ryan sara kate
  my is it to in on of at be we he me no so up do go if or as an by us am oh ok hi`.split(/\s+/);

let dictionary = null;
let letterPairs = null;

/** Words a letter run can match exactly: the 7,776-word passphrase list plus common short words. */
function isDictionaryWord(lower) {
  dictionary ??= new Set([...WORDS, ...SHORT_WORDS]);
  return dictionary.has(lower);
}

/**
 * How much more likely each letter pair is in English than in random text
 * (log2 ratio), learned from the bundled word list. Random letters average
 * about -2.2 per pair; real words and names about +1.
 */
function pairScores() {
  if (letterPairs) return letterPairs;
  const counts = new Float64Array(26 * 26).fill(0.5);
  const totals = new Float64Array(26).fill(13);
  for (const word of WORDS) {
    for (let i = 1; i < word.length; i += 1) {
      const a = word.charCodeAt(i - 1) - 97;
      const b = word.charCodeAt(i) - 97;
      if (a < 0 || a > 25 || b < 0 || b > 25) continue;
      counts[a * 26 + b] += 1;
      totals[a] += 1;
    }
  }
  letterPairs = new Float64Array(26 * 26);
  for (let a = 0; a < 26; a += 1) {
    for (let b = 0; b < 26; b += 1) letterPairs[a * 26 + b] = Math.log2((counts[a * 26 + b] / totals[a]) * 26);
  }
  return letterPairs;
}

const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qwertzuiop', 'azertyuiop'];
const LEET = { '@': 'a', 4: 'a', 8: 'b', 3: 'e', 6: 'g', 1: 'l', '!': 'i', 0: 'o', $: 's', 5: 's', 7: 't', '+': 't' };
const LETTER_BITS = Math.log2(26);
const DIGIT_BITS = Math.log2(10);
const SYMBOL_BITS = Math.log2(33);
const RUNS = /\p{Lu}?\p{Ll}+|\p{Lu}+|\p{L}+|\p{Nd}+|[^\p{L}\p{Nd}]+/gu;
const WORD_MIN = 3; // shortest letter run judged by how word-like it sounds
const LEET_WORD_MIN = 6; // de-l33ted words must be longer to count, to avoid false alarms

const distinct = (text) => new Set(text).size;
const reverse = (text) => [...text].reverse().join('');
const isLetters = (run) => /^\p{L}/u.test(run);
const isDigits = (run) => /^\p{Nd}/u.test(run);

/** "abcd", "4321", "qwer": neighbours in the alphabet or along a keyboard row. */
function isSequence(text) {
  let up = true;
  let down = true;
  for (let i = 1; i < text.length; i += 1) {
    const step = text.charCodeAt(i) - text.charCodeAt(i - 1);
    if (step !== 1) up = false;
    if (step !== -1) down = false;
  }
  if (up || down) return true;
  return text.length >= 4 && KEYBOARD_ROWS.some((row) => row.includes(text) || row.includes(reverse(text)));
}

/**
 * Does this run of lower-case letters read like a word or name rather than
 * random letters? Judged by how plausible its letter pairs are in English.
 * The bar is higher for short runs, where chance resemblance is common, and
 * is set so that roughly 1 random run in 20 is mistaken for a word.
 * Other scripts cannot be judged this way, so they are assumed to be words.
 */
function looksLikeWords(lower) {
  if (/[^a-z]/.test(lower)) return true;
  if (lower.length < 2) return false;
  const scores = pairScores();
  let total = 0;
  for (let i = 1; i < lower.length; i += 1) {
    total += scores[(lower.charCodeAt(i - 1) - 97) * 26 + lower.charCodeAt(i) - 97];
  }
  const pairs = lower.length - 1;
  return total / pairs >= Math.max(0.05, -2.17 + 5.1 / Math.sqrt(pairs));
}

const DICTIONARY_BITS = Math.log2(WORDS.length);
const COMMON_BITS = 4;
const wordBits = (length) => Math.min(length * LETTER_BITS, 1.5 * length + 5);
const knownWordBits = (word) => (COMMON.has(word) ? COMMON_BITS : Math.min(wordBits(word.length), DICTIONARY_BITS));

/**
 * If a run of letters is entirely made of known words stuck together
 * ("passwordpassword", "correcthorsebatterystaple"), returns the cheapest way
 * to spell it in bits; otherwise null.
 */
function wordChainBits(lower) {
  const n = lower.length;
  if (n < 4 || n > 64) return null;
  const best = new Array(n + 1).fill(Infinity);
  const words = new Array(n + 1).fill(0);
  best[0] = 0;
  for (let end = 2; end <= n; end += 1) {
    for (let start = Math.max(0, end - 12); start <= end - 2; start += 1) {
      if (best[start] === Infinity) continue;
      const word = lower.slice(start, end);
      if (!COMMON.has(word) && !isDictionaryWord(word)) continue;
      const bits = best[start] + knownWordBits(word);
      if (bits < best[end]) {
        best[end] = bits;
        words[end] = words[start] + 1;
      }
    }
  }
  return best[n] !== Infinity && words[n] >= 2 ? best[n] : null;
}

/** @returns {{bits: number, word: boolean}} cost of a letter run, and whether it reads as words */
function letterRun(run, randomBits) {
  const lower = run.toLowerCase();
  const n = [...lower].length;
  const caseBit = run !== lower ? 1 : 0;
  const word = (bits) => ({ bits: bits + caseBit, word: true });
  if (COMMON.has(lower)) return word(COMMON_BITS);
  if (n >= 3 && distinct(lower) === 1) return word(LETTER_BITS + Math.log2(n)); // "aaaa"
  if (n >= 6 && distinct(lower) === 2) return word(2 * LETTER_BITS + Math.log2(n)); // "ababab"
  if (n >= 4 && isSequence(lower)) return word(LETTER_BITS + Math.log2(n) + 1); // "abcd", "qwer"
  if (isDictionaryWord(lower)) return word(knownWordBits(lower));
  const chain = /[^a-z]/.test(lower) ? null : wordChainBits(lower);
  const wordy = n >= WORD_MIN && looksLikeWords(lower) ? wordBits(n) : Infinity;
  if (chain !== null || wordy !== Infinity) return word(Math.min(chain ?? Infinity, wordy));
  return { bits: n * randomBits, word: false };
}

function digitRunBits(run, randomBits, besideWord) {
  const n = run.length;
  if (n >= 2 && distinct(run) === 1) return DIGIT_BITS + Math.log2(n); // "00", "7777"
  if (n >= 3 && isSequence(run)) return DIGIT_BITS + Math.log2(n) + 1; // "1234"
  if (/^(19|20)\d\d$/.test(run)) return 6.6; // a year
  // Three or more digits, or any digits tacked onto a word, are "a number".
  if (n >= 3 || besideWord) return n * DIGIT_BITS;
  return n * randomBits;
}

function poolSize(text) {
  let pool = 0;
  if (/\p{Ll}/u.test(text)) pool += 26;
  if (/\p{Lu}/u.test(text)) pool += 26;
  if (/\p{Nd}/u.test(text)) pool += 10;
  if (/[^\p{L}\p{Nd}]/u.test(text) || /\p{Lo}/u.test(text)) pool += 33;
  return pool || 1;
}

function entropyOf(text) {
  const runs = text.match(RUNS) ?? [];
  const randomBits = Math.log2(poolSize(text));
  const parts = runs.map((run) => {
    if (isLetters(run)) return { run, kind: 'letters', ...letterRun(run, randomBits) };
    return { run, kind: isDigits(run) ? 'digits' : 'symbols', word: false };
  });
  const isWord = (part) => Boolean(part?.word);
  const isAlnum = (part) => part !== undefined && part.kind !== 'symbols';
  const isJoiner = (part) => part?.kind === 'symbols' && [...part.run].length === 1;

  const separators = new Set();
  let bits = 0;
  parts.forEach((part, index) => {
    const before = parts[index - 1];
    const after = parts[index + 1];
    if (part.kind === 'letters') {
      bits += part.bits;
    } else if (part.kind === 'digits') {
      // "word99" and "word 99": the number belongs to the neighbouring word.
      const besideWord = isWord(before) || isWord(after) || (isJoiner(before) && isWord(parts[index - 2])) || (isJoiner(after) && isWord(parts[index + 2]));
      bits += digitRunBits(part.run, randomBits, besideWord);
    } else if (isJoiner(part) && isAlnum(before) && isAlnum(after) && (isWord(before) || isWord(after))) {
      // A separator between words: choosing it costs something once, repeating it almost nothing.
      bits += separators.has(part.run) ? 1 : SYMBOL_BITS;
      separators.add(part.run);
    } else {
      bits += [...part.run].length * randomBits;
    }
  });
  return bits;
}

/** Undo l33t-speak that sits inside a word: "tr0ub4dor" -> "troubador". */
function unleet(text) {
  const swapped = [];
  const plain = text.replace(/([A-Za-z])([@4836!0$57+1])(?=[A-Za-z])/g, (match, before, char, offset) => {
    swapped.push(offset + 1);
    return before + LEET[char];
  });
  return { plain, swapped };
}

/** True if undoing the substitutions revealed a long, word-like run. */
function revealsWord(plain, swapped) {
  for (const match of plain.matchAll(RUNS)) {
    const run = match[0];
    const end = match.index + run.length;
    if (
      isLetters(run) &&
      run.length >= LEET_WORD_MIN &&
      looksLikeWords(run.toLowerCase()) &&
      swapped.some((position) => position >= match.index && position < end)
    ) {
      return true;
    }
  }
  return false;
}

/** If the password is a well-known one plus decoration, how many extra characters it has. */
function commonDecoration(text) {
  const lower = text.toLowerCase();
  const trim = (value) => value.replace(/^[^a-z]+|[^a-z]+$/g, '');
  const candidates = new Set([lower, trim(lower)]);
  for (const value of [...candidates]) {
    const full = value.replace(/[@4836!0$57+1]/g, (char) => LEET[char]);
    candidates.add(full);
    candidates.add(full.replace(/l/g, 'i'));
    candidates.add(trim(unleet(value).plain));
  }
  let best = null;
  for (const candidate of candidates) {
    if (candidate && COMMON.has(candidate)) {
      const extra = Math.max(0, lower.length - candidate.length);
      best = best === null ? extra : Math.min(best, extra);
    }
  }
  return best;
}

const scoreOf = (bits) => (bits < 28 ? 0 : bits < 40 ? 1 : bits < 58 ? 2 : bits < 75 ? 3 : 4);

/**
 * @param {string} password
 * @returns {{score: 0|1|2|3|4, bits: number, label: string}}
 */
export function estimateStrength(password) {
  const text = String(password ?? '');
  if (!text) return { score: 0, bits: 0, label: STRENGTH_LABELS[0] };

  let bits = entropyOf(text);
  const { plain, swapped } = unleet(text);
  if (swapped.length && revealsWord(plain, swapped)) bits = Math.min(bits, entropyOf(plain) + swapped.length);

  const decoration = commonDecoration(text);
  if (decoration !== null) bits = Math.min(bits, 6 + 2.5 * decoration);

  // The same thing typed several times over: "abc123abc123". (Skipped for very
  // long input, where the search would be slow and the answer is not in doubt.)
  const repeated = text.length <= 256 ? /^(.+?)\1+$/su.exec(text) : null;
  if (repeated) bits = Math.min(bits, estimateStrength(repeated[1]).bits + Math.log2(text.length / repeated[1].length) + 1);

  bits = Math.max(1, Math.round(bits));
  const score = scoreOf(bits);
  return { score, bits, label: STRENGTH_LABELS[score] };
}

/** Maps a known entropy (e.g. from the generator) onto the same 0-4 scale. */
export function scoreForBits(bits) {
  const score = scoreOf(bits);
  return { score, bits: Math.round(bits), label: STRENGTH_LABELS[score] };
}
