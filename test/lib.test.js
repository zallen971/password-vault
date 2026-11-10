// Unit tests for the browser-side libraries. They are plain ES modules built
// on Web Crypto, so the same code runs unmodified under Node.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import * as vaultCrypto from '../public/js/lib/crypto.js';
import { parseTotp, generateTotp, decodeBase32 } from '../public/js/lib/totp.js';
import {
  generatePassword,
  generatePassphrase,
  passwordEntropy,
  passphraseEntropy,
  randomInt,
  normalizePasswordOptions,
} from '../public/js/lib/generator.js';
import { WORDS } from '../public/js/lib/wordlist.js';
import { estimateStrength } from '../public/js/lib/strength.js';
import { parseCsv, parseCsvRecords, toCsv } from '../public/js/lib/csv.js';
import { parseImport, ImportError } from '../public/js/lib/importers.js';
import { toBitwardenJson, toBitwardenCsv, toEncryptedBackup, openEncryptedBackup } from '../public/js/lib/exporters.js';
import {
  normalizeItem,
  normalizeFolder,
  launchUrl,
  hostOf,
  itemSubtitle,
  searchText,
  contentKey,
  detectCardBrand,
  formatCardNumber,
} from '../public/js/lib/model.js';
import { findBreachedPasswords } from '../public/js/lib/breach.js';
import { analyzeVault } from '../public/js/lib/health.js';

const FAST_KDF = { name: 'PBKDF2', hash: 'SHA-256', iterations: 100_000 };
const ascii = (text) => new TextEncoder().encode(text);

describe('crypto', () => {
  test('PBKDF2 matches a known test vector', async () => {
    // PBKDF2-HMAC-SHA256("password", "salt", 100000 iterations, 32 bytes)
    const key = await vaultCrypto.deriveMasterKey('password', ascii('salt'), FAST_KDF);
    assert.equal(Buffer.from(key).toString('hex'), '0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5');
  });

  test('refuses weak or unknown key-derivation settings', async () => {
    const salt = ascii('0123456789abcdef');
    for (const kdf of [
      { ...FAST_KDF, iterations: 1 },
      { ...FAST_KDF, iterations: 99_999 },
      { ...FAST_KDF, iterations: 50_000_000 },
      { ...FAST_KDF, iterations: '600000' },
      { ...FAST_KDF, hash: 'SHA-1' },
      { ...FAST_KDF, name: 'none' },
      null,
    ]) {
      await assert.rejects(vaultCrypto.deriveMasterKey('pw', salt, kdf), /Unsupported/);
    }
  });

  test('login keys are deterministic, distinct per purpose, and password-dependent', async () => {
    const salt = vaultCrypto.toBase64(vaultCrypto.randomBytes(16));
    const a = await vaultCrypto.deriveLoginKeys('correct horse', salt, FAST_KDF);
    const b = await vaultCrypto.deriveLoginKeys('correct horse', salt, FAST_KDF);
    const c = await vaultCrypto.deriveLoginKeys('correct horsf', salt, FAST_KDF);
    assert.equal(a.authKey, b.authKey);
    assert.notEqual(a.authKey, c.authKey);
    assert.equal(vaultCrypto.fromBase64(a.authKey).length, 32);
    assert.equal(a.wrapKey.extractable, false, 'keys must not be exportable from the browser');

    // The auth key (which the server sees) must not be usable as the wrap key.
    const sealed = await vaultCrypto.encryptBytes(a.wrapKey, ascii('secret'), 'ctx');
    const impostor = await crypto.subtle.importKey('raw', vaultCrypto.fromBase64(a.authKey), 'AES-GCM', false, ['decrypt']);
    await assert.rejects(vaultCrypto.decryptBytes(impostor, sealed, 'ctx'));
  });

  test('unicode passwords are normalized before use', async () => {
    const salt = vaultCrypto.toBase64(vaultCrypto.randomBytes(16));
    const composed = await vaultCrypto.deriveLoginKeys('café', salt, FAST_KDF);
    const decomposed = await vaultCrypto.deriveLoginKeys('café', salt, FAST_KDF);
    assert.equal(composed.authKey, decomposed.authKey);
  });

  test('account keys: the vault key opens only with the right password', async () => {
    const account = await vaultCrypto.createAccountKeys('a long master password', FAST_KDF);
    assert.equal(account.vaultKey.extractable, false);
    const record = await vaultCrypto.encryptJson(account.vaultKey, { name: 'Bank', password: 'hunter2' }, 'record:1');

    const right = await vaultCrypto.deriveLoginKeys('a long master password', account.salt, account.kdf);
    assert.equal(right.authKey, account.authKey);
    const key = await vaultCrypto.openVaultKey(account.protectedKey, right.wrapKey);
    assert.deepEqual(await vaultCrypto.decryptJson(key, record, 'record:1'), { name: 'Bank', password: 'hunter2' });

    const wrong = await vaultCrypto.deriveLoginKeys('a long master passwore', account.salt, account.kdf);
    await assert.rejects(vaultCrypto.openVaultKey(account.protectedKey, wrong.wrapKey));
  });

  test('re-wrapping keeps the same vault key under a new password', async () => {
    const account = await vaultCrypto.createAccountKeys('old password', FAST_KDF);
    const record = await vaultCrypto.encryptJson(account.vaultKey, { n: 1 }, 'record:x');
    const oldKeys = await vaultCrypto.deriveLoginKeys('old password', account.salt, FAST_KDF);
    const newSalt = vaultCrypto.toBase64(vaultCrypto.randomBytes(16));
    const newKeys = await vaultCrypto.deriveLoginKeys('new password', newSalt, FAST_KDF);

    const rewrapped = await vaultCrypto.rewrapVaultKey(account.protectedKey, oldKeys.wrapKey, newKeys.wrapKey);
    assert.notEqual(rewrapped, account.protectedKey);
    const key = await vaultCrypto.openVaultKey(rewrapped, newKeys.wrapKey);
    assert.deepEqual(await vaultCrypto.decryptJson(key, record, 'record:x'), { n: 1 });
    await assert.rejects(vaultCrypto.openVaultKey(rewrapped, oldKeys.wrapKey));
  });

  test('encryption is randomised and tamper-evident', async () => {
    const { vaultKey } = await vaultCrypto.createAccountKeys('pw pw pw pw', FAST_KDF);
    const value = { password: 'p@ss', notes: 'ünïcödé ✓ 日本語', nested: [1, 2, { a: null }] };
    const one = await vaultCrypto.encryptJson(vaultKey, value, 'record:a');
    const two = await vaultCrypto.encryptJson(vaultKey, value, 'record:a');
    assert.notEqual(one, two, 'every encryption must use a fresh nonce');
    assert.deepEqual(await vaultCrypto.decryptJson(vaultKey, one, 'record:a'), value);
    assert.ok(!Buffer.from(one, 'base64').toString('latin1').includes('p@ss'));

    // Bound to its record: the server cannot swap one record's data into another.
    await assert.rejects(vaultCrypto.decryptJson(vaultKey, one, 'record:b'));

    const bytes = vaultCrypto.fromBase64(one);
    for (const index of [0, 5, 20, bytes.length - 1]) {
      const copy = bytes.slice();
      copy[index] ^= 0x01;
      await assert.rejects(vaultCrypto.decryptJson(vaultKey, vaultCrypto.toBase64(copy), 'record:a'), `flipping byte ${index}`);
    }
    await assert.rejects(vaultCrypto.decryptJson(vaultKey, vaultCrypto.toBase64(bytes.slice(0, 20)), 'record:a'));
    await assert.rejects(vaultCrypto.decryptJson(vaultKey, '', 'record:a'));
  });

  test('base64 round-trips binary data of any size', () => {
    for (const size of [0, 1, 2, 3, 255, 32768, 70000]) {
      const bytes = new Uint8Array(size).map((_, i) => (i * 31 + 7) & 0xff);
      const encoded = vaultCrypto.toBase64(bytes);
      assert.equal(encoded, Buffer.from(bytes).toString('base64'));
      assert.deepEqual(vaultCrypto.fromBase64(encoded), bytes);
    }
  });

  test('password-protected files', async () => {
    const sealed = await vaultCrypto.encryptWithPassword('file password', '{"items":[]}', FAST_KDF);
    assert.equal(await vaultCrypto.decryptWithPassword('file password', sealed), '{"items":[]}');
    await assert.rejects(vaultCrypto.decryptWithPassword('wrong password', sealed));
    await assert.rejects(vaultCrypto.decryptWithPassword('file password', { ...sealed, kdf: { ...FAST_KDF, iterations: 10 } }), /Unsupported/);
  });

  test('sha1Hex', async () => {
    assert.equal(await vaultCrypto.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  });
});

describe('totp', () => {
  // RFC 6238, Appendix B.
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  const secrets = {
    'SHA-1': ascii('12345678901234567890'),
    'SHA-256': ascii('12345678901234567890123456789012'),
    'SHA-512': ascii('1234567890123456789012345678901234567890123456789012345678901234'),
  };

  test('matches the RFC 6238 test vectors', async () => {
    for (const [time, sha1, sha256, sha512] of vectors) {
      for (const [algorithm, expected] of [['SHA-1', sha1], ['SHA-256', sha256], ['SHA-512', sha512]]) {
        const { code } = await generateTotp({ secret: secrets[algorithm], algorithm, digits: 8, period: 30 }, time * 1000);
        assert.equal(code, expected, `${algorithm} at ${time}`);
      }
    }
  });

  test('reports the time left in the current period', async () => {
    const config = { secret: secrets['SHA-1'], algorithm: 'SHA-1', digits: 6, period: 30 };
    assert.equal((await generateTotp(config, 0)).remaining, 30);
    assert.equal((await generateTotp(config, 29_999)).remaining, 1);
    assert.equal((await generateTotp(config, 45_000)).remaining, 15);
    assert.equal((await generateTotp(config, 59_000)).code, '287082');
  });

  test('decodes base32 secrets however they are typed', () => {
    const expected = ascii('12345678901234567890');
    assert.deepEqual(decodeBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), expected);
    assert.deepEqual(decodeBase32('gezd gnbv gy3t qojq gezd gnbv gy3t qojq'), expected);
    assert.deepEqual(decodeBase32('GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ'), expected);
    assert.deepEqual(decodeBase32('MZXW6==='), ascii('foo'));
    assert.deepEqual(decodeBase32('MZXW6YQ='), ascii('foob'));
    assert.deepEqual(decodeBase32('MZXW6YTBOI======'), ascii('foobar'));
    assert.throws(() => decodeBase32('not base32!'));
    assert.throws(() => decodeBase32(''));
  });

  test('parses secrets and otpauth:// URIs', () => {
    assert.deepEqual(parseTotp('JBSWY3DPEHPK3PXP'), { secret: decodeBase32('JBSWY3DPEHPK3PXP'), algorithm: 'SHA-1', digits: 6, period: 30 });
    const uri = parseTotp('otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60');
    assert.deepEqual(uri, { secret: decodeBase32('JBSWY3DPEHPK3PXP'), algorithm: 'SHA-256', digits: 8, period: 60 });
    assert.equal(parseTotp(''), null);
    assert.equal(parseTotp('   '), null);
    assert.equal(parseTotp('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1'), null);
    assert.equal(parseTotp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99'), null);
    assert.equal(parseTotp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0'), null);
    assert.equal(parseTotp('otpauth://totp/x'), null);
    assert.equal(parseTotp('not-base32-1890!'), null);
  });
});

describe('generator', () => {
  const classes = { lowercase: /[a-z]/, uppercase: /[A-Z]/, numbers: /[0-9]/, symbols: /[!@#$%^&*\-_]/ };

  test('respects length and always includes every enabled character class', () => {
    for (let round = 0; round < 300; round += 1) {
      const password = generatePassword({ length: 8 });
      assert.equal(password.length, 8);
      for (const [name, pattern] of Object.entries(classes)) assert.match(password, pattern, `${name} missing from ${password}`);
      assert.match(password, /^[A-Za-z0-9!@#$%^&*\-_]+$/);
    }
  });

  test('leaves out disabled classes', () => {
    for (let round = 0; round < 100; round += 1) {
      assert.match(generatePassword({ length: 24, symbols: false }), /^[A-Za-z0-9]{24}$/);
      assert.match(generatePassword({ length: 16, uppercase: false, lowercase: false, symbols: false }), /^[0-9]{16}$/);
      assert.match(generatePassword({ length: 30, avoidAmbiguous: true }), /^[^Il1O0]{30}$/);
    }
  });

  test('copes with odd options', () => {
    assert.match(generatePassword({ length: 12, uppercase: false, lowercase: false, numbers: false, symbols: false }), /^[a-z]{12}$/);
    assert.equal(generatePassword({ length: 1 }).length, 5);
    assert.equal(generatePassword({ length: 100000 }).length, 128);
    assert.equal(generatePassword({ length: 'abc' }).length, 20);
    assert.equal(normalizePasswordOptions({ length: '32' }).length, 32);
  });

  test('uses the whole alphabet without obvious bias', () => {
    const counts = new Map();
    const sample = Array.from({ length: 400 }, () => generatePassword({ length: 64 })).join('');
    for (const char of sample) counts.set(char, (counts.get(char) ?? 0) + 1);
    assert.equal(counts.size, 72, 'every character of the 72-character alphabet should appear');
    const expected = sample.length / 72;
    for (const [char, count] of counts) {
      assert.ok(count > expected * 0.7 && count < expected * 1.3, `"${char}" appeared ${count} times, expected about ${expected}`);
    }
  });

  test('randomInt is in range and rejects bad bounds', () => {
    const seen = new Set();
    for (let i = 0; i < 2000; i += 1) {
      const value = randomInt(7);
      assert.ok(Number.isInteger(value) && value >= 0 && value < 7);
      seen.add(value);
    }
    assert.equal(seen.size, 7);
    assert.equal(randomInt(1), 0);
    assert.throws(() => randomInt(0), RangeError);
    assert.throws(() => randomInt(1.5), RangeError);
  });

  test('passphrases use words from the EFF list', () => {
    assert.equal(WORDS.length, 7776);
    assert.equal(new Set(WORDS).size, 7776);
    const dictionary = new Set(WORDS);
    for (let round = 0; round < 50; round += 1) {
      const words = generatePassphrase({ words: 6, separator: ' ' }).split(' ');
      assert.equal(words.length, 6);
      for (const word of words) assert.ok(dictionary.has(word), word);
    }
    const fancy = generatePassphrase({ words: 4, separator: '.', capitalize: true, includeNumber: true });
    assert.equal(fancy.split('.').length, 4);
    assert.match(fancy, /\d/);
    for (const word of fancy.split('.')) assert.match(word, /^[A-Z]/);
    assert.equal(generatePassphrase({ words: 1 }).split('-').length, 3);
    assert.equal(generatePassphrase({ words: 99 }).split('-').length, 12);
  });

  test('entropy figures', () => {
    assert.equal(Math.round(passwordEntropy({ length: 20 })), Math.round(20 * Math.log2(72)));
    assert.equal(Math.round(passwordEntropy({ length: 10, uppercase: false, lowercase: false, symbols: false })), 33);
    assert.equal(Math.round(passphraseEntropy({ words: 5 })), 65);
    assert.ok(passphraseEntropy({ words: 5, includeNumber: true }) > passphraseEntropy({ words: 5 }));
  });
});

describe('strength', () => {
  const score = (password) => estimateStrength(password).score;

  test('flags common and predictable passwords as very weak', () => {
    for (const password of [
      '', 'password', 'Password1', 'Password123!', 'P@ssw0rd!', 'qwerty', 'qwertyuiop', '123456', '12345678', 'letmein',
      'iloveyou', 'abc123', 'aaaaaaaaaaaa', 'abcdefgh', '11111111', 'Summer2024!', 'hunter2', 'admin123', 'welcome1',
      'MyP@ssw0rd2024!', '493817', 'Zx9!', 'passwordpassword', 'adminadminadmin', 'abc123abc123', 'iloveyoupassword',
      'qwertyqwerty', 'hellohello12', '1qaz2wsx3edc', 'a1b2c3d4',
    ]) {
      assert.equal(score(password), 0, JSON.stringify(password));
    }
  });

  test('rates human-style passwords as weak or fair, never strong', () => {
    for (const password of [
      'Tr0ub4dor&3', 'iloveyouverymuch', 'MyDogIsCute', 'Fluffy-the-cat', 'Liverpool1892FC', 'correcthorsebatterystaple',
      'M0nk3yBus1ness', 'dr4g0nSl4yer99', 'John1985', 'Tr0ub4dor&3Tr0ub4dor&3', 'my dog is cute 99', 'happy birthday 2020',
      'winter is coming 99', 'purple monkey dishwasher', 'i love my dog rex',
    ]) {
      assert.ok(score(password) <= 2, `${password} scored ${score(password)}`);
    }
  });

  // The estimator is statistical, so these check rates over many samples
  // rather than demanding a particular score for every single password.
  const rate = (make, minimum, samples = 400) => {
    let hits = 0;
    for (let i = 0; i < samples; i += 1) if (score(make()) >= minimum) hits += 1;
    return hits / samples;
  };

  test('recognizes generated passwords as strong', () => {
    assert.ok(rate(() => generatePassword({ length: 20 }), 4) >= 0.99);
    assert.ok(rate(() => generatePassword({ length: 16 }), 4) >= 0.97);
    assert.ok(rate(() => generatePassword({ length: 12 }), 3) >= 0.95);
    assert.ok(rate(() => generatePassword({ length: 20, symbols: false }), 4) >= 0.98);
    assert.ok(rate(() => generatePassword({ length: 24, uppercase: false, numbers: false, symbols: false }), 4) >= 0.98);
    assert.equal(rate(() => generatePassword({ length: 20 }), 3), 1);
  });

  test('rates generated passphrases in line with their real entropy', () => {
    assert.ok(rate(() => generatePassphrase({ words: 6 }), 4) >= 0.95, 'six words (77 bits) are strong');
    assert.ok(rate(() => generatePassphrase({ words: 5 }), 3) >= 0.98, 'five words (65 bits) are good');
    assert.ok(rate(() => generatePassphrase({ words: 3 }), 3) <= 0.05, 'three words (39 bits) are not');
    assert.ok([2, 3].includes(score('correct horse battery staple')), 'four common words are fair to good');
  });

  test('short random passwords are not over-rated', () => {
    assert.ok(rate(() => generatePassword({ length: 8 }), 3) <= 0.01);
    assert.ok(rate(() => generatePassword({ length: 6 }), 2) <= 0.01);
    assert.equal(score(generatePassword({ length: 20, uppercase: false, lowercase: false, symbols: false })), 3, '20 random digits = 66 bits');
  });

  test('longer random passwords are stronger', () => {
    for (let round = 0; round < 100; round += 1) {
      const password = generatePassword({ length: 32 });
      const bits = [8, 16, 32].map((length) => estimateStrength(password.slice(0, length)).bits);
      assert.ok(bits[0] < bits[1] && bits[1] < bits[2], `${password}: ${bits}`);
    }
  });

  test('handles unusual input', () => {
    assert.equal(score(null), 0);
    assert.equal(score(undefined), 0);
    assert.ok(estimateStrength('пароль-длинный-и-сложный-42').bits > 0);
    assert.ok(estimateStrength('😀😃😄😁😆😅😂🤣').bits > 0);
    assert.ok(estimateStrength('a'.repeat(10_000)).score <= 1);
    assert.equal(typeof estimateStrength('x').label, 'string');
  });
});

describe('csv', () => {
  test('parses quoting, embedded separators and newlines', () => {
    const text = 'name,notes,password\r\n"Smith, John","line one\nline two","he said ""hi"""\r\nplain,,x\n';
    assert.deepEqual(parseCsv(text), [
      ['name', 'notes', 'password'],
      ['Smith, John', 'line one\nline two', 'he said "hi"'],
      ['plain', '', 'x'],
    ]);
  });

  test('handles BOMs, blank lines, bare CRs and a missing final newline', () => {
    assert.deepEqual(parseCsv('﻿a,b\n\n1,2\r\r\n3,4'), [['a', 'b'], ['1', '2'], ['3', '4']]);
    assert.deepEqual(parseCsv(''), []);
    assert.deepEqual(parseCsv('a,b,'), [['a', 'b', '']]);
    assert.deepEqual(parseCsv('"",x'), [['', 'x']]);
    assert.deepEqual(parseCsv('a,"unterminated'), [['a', 'unterminated']]);
  });

  test('records are keyed by lower-cased header', () => {
    const { headers, records } = parseCsvRecords('Title, URL ,Password\nMail,https://mail.example,pw\nshort');
    assert.deepEqual(headers, ['title', 'url', 'password']);
    assert.deepEqual(records, [
      { title: 'Mail', url: 'https://mail.example', password: 'pw' },
      { title: 'short', url: '', password: '' },
    ]);
  });

  test('round-trips awkward values exactly', () => {
    const rows = [
      ['name', 'value'],
      ['formula-looking', '=1+1'],
      ['starts with dash', '-Rk9!x'],
      ['at sign', '@home'],
      ['quotes', 'a "quoted" word'],
      ['multi\nline', 'comma, here'],
      ['spaces', '  padded  '],
      ['unicode', 'ключ 🔑'],
      ['empty', ''],
    ];
    assert.deepEqual(parseCsv(toCsv(rows)), rows);
  });
});

describe('model', () => {
  test('normalizeItem fills in a complete item from sparse input', () => {
    const item = normalizeItem({ type: 'login', name: '  GitHub ', login: { username: 'octo', uris: [' github.com ', '', null] } });
    assert.match(item.id, /^[0-9a-f-]{36}$/);
    assert.equal(item.kind, 'item');
    assert.equal(item.name, 'GitHub');
    assert.deepEqual(item.login, { username: 'octo', password: '', totp: '', uris: ['github.com'] });
    assert.deepEqual(item.fields, []);
    assert.equal(item.deletedAt, null);
    assert.equal(item.card, undefined);
  });

  test('normalizeItem tolerates hostile or broken input', () => {
    const item = normalizeItem({
      type: 'nonsense',
      name: 42,
      notes: null,
      favorite: 'yes',
      fields: [null, { name: 'ok', value: 7, type: 'weird' }, { type: 'boolean', name: 'flag', value: 'true' }, {}],
      passwordHistory: [{ password: '' }, { password: 'old', changedAt: 'not a date' }, null],
      createdAt: 'garbage',
      login: 'not an object',
    });
    assert.equal(item.type, 'login');
    assert.equal(item.name, '42');
    assert.equal(item.notes, '');
    assert.equal(item.favorite, true);
    assert.deepEqual(item.fields, [
      { name: 'ok', value: '7', type: 'text' },
      { name: 'flag', value: 'true', type: 'boolean' },
    ]);
    assert.equal(item.passwordHistory.length, 1);
    assert.ok(!Number.isNaN(Date.parse(item.createdAt)));
    assert.deepEqual(item.login, { username: '', password: '', totp: '', uris: [] });
  });

  test('normalizing is stable', () => {
    for (const type of ['login', 'note', 'card', 'identity']) {
      const once = normalizeItem({ type, name: 'x', card: { number: '4111 1111 1111 1111' }, identity: { firstName: 'Ada' } });
      assert.deepEqual(normalizeItem(once), once);
    }
    const folder = normalizeFolder({ name: ' Work ' });
    assert.equal(folder.name, 'Work');
    assert.deepEqual(normalizeFolder(folder), folder);
  });

  test('only web addresses can ever be opened', () => {
    assert.equal(launchUrl('example.com'), 'https://example.com/');
    assert.equal(launchUrl('https://www.example.com/login?x=1'), 'https://www.example.com/login?x=1');
    assert.equal(launchUrl('http://192.168.1.1/admin'), 'http://192.168.1.1/admin');
    assert.equal(launchUrl('example.com:8443/path'), 'https://example.com:8443/path');
    assert.equal(launchUrl('localhost:3000'), 'https://localhost:3000/');
    for (const dangerous of [
      'javascript:alert(1)', 'JavaScript:alert(1)', ' javascript:alert(1)', 'java\tscript:alert(1)', 'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)', 'file:///etc/passwd', 'blob:https://example.com/x', 'ftp://example.com', 'androidapp://com.example',
      'mailto:a@example.com', 'chrome://settings', 'about:blank', '', '   ', 'two words', 'justaword', null, undefined,
    ]) {
      assert.equal(launchUrl(dangerous), null, String(dangerous));
    }
  });

  test('display helpers', () => {
    assert.equal(hostOf('https://www.github.com/login'), 'github.com');
    assert.equal(hostOf('androidapp://com.example'), 'androidapp://com.example');
    assert.equal(itemSubtitle(normalizeItem({ type: 'login', login: { username: 'me@x.com', uris: ['x.com'] } })), 'me@x.com');
    assert.equal(itemSubtitle(normalizeItem({ type: 'login', login: { uris: ['https://www.x.com/a'] } })), 'x.com');
    assert.equal(itemSubtitle(normalizeItem({ type: 'card', card: { brand: 'Visa', number: '4111 1111 1111 1234' } })), 'Visa •••• 1234');
    assert.equal(itemSubtitle(normalizeItem({ type: 'identity', identity: { firstName: 'Ada', lastName: 'Lovelace' } })), 'Ada Lovelace');
    assert.equal(itemSubtitle(normalizeItem({ type: 'note', notes: 'very secret text' })), '', 'note contents must not leak into the list');
    assert.equal(detectCardBrand('4111111111111111'), 'Visa');
    assert.equal(detectCardBrand('5555 5555 5555 4444'), 'Mastercard');
    assert.equal(detectCardBrand('2221 0000 0000 0009'), 'Mastercard');
    assert.equal(detectCardBrand('378282246310005'), 'American Express');
    assert.equal(detectCardBrand('6011111111111117'), 'Discover');
    assert.equal(detectCardBrand(''), '');
    assert.equal(formatCardNumber('4111111111111111'), '4111 1111 1111 1111');
    assert.equal(formatCardNumber('378282246310005'), '3782 822463 10005');
    assert.equal(formatCardNumber('not-a-number'), 'not-a-number');
  });

  test('search text never contains secrets', () => {
    const item = normalizeItem({
      type: 'login',
      name: 'Bank',
      notes: 'call the branch',
      login: { username: 'alice', password: 'S3cretPassw0rd', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://bank.example'] },
      fields: [{ name: 'PIN', value: '9911', type: 'hidden' }, { name: 'Branch', value: 'Main St', type: 'text' }],
    });
    const haystack = searchText(item, 'Finance');
    for (const visible of ['bank', 'alice', 'bank.example', 'finance', 'branch', 'main st', 'pin', 'call the branch']) {
      assert.ok(haystack.includes(visible), visible);
    }
    for (const secret of ['s3cretpassw0rd', 'jbswy3dpehpk3pxp', '9911']) assert.ok(!haystack.includes(secret), secret);
  });

  test('contentKey ignores identity and bookkeeping but not content', () => {
    const a = normalizeItem({ type: 'login', name: 'X', login: { username: 'u', password: 'p' } });
    const b = normalizeItem({ ...a, id: undefined, folderId: 'f', favorite: true, updatedAt: '2020-01-01T00:00:00Z' });
    const c = normalizeItem({ ...a, login: { ...a.login, password: 'different' } });
    assert.equal(contentKey(a), contentKey(b));
    assert.notEqual(contentKey(a), contentKey(c));
  });
});

describe('import and export', () => {
  const bitwardenExport = {
    encrypted: false,
    folders: [{ id: 'f1', name: 'Work' }, { id: 'f2', name: 'Personal' }],
    items: [
      {
        id: 'i1', organizationId: null, folderId: 'f1', type: 1, reprompt: 0, name: 'GitHub', notes: 'main account', favorite: true,
        fields: [
          { name: 'Recovery', value: 'abcd-efgh', type: 1, linkedId: null },
          { name: 'Enabled', value: 'true', type: 2, linkedId: null },
          { name: 'Linked', value: null, type: 3, linkedId: 100 },
        ],
        login: {
          uris: [{ match: null, uri: 'https://github.com/login' }, { match: 0, uri: 'https://github.com' }],
          username: 'octocat', password: 'correct horse', totp: 'JBSWY3DPEHPK3PXP',
          fido2Credentials: [{ credentialId: 'x' }],
        },
        passwordHistory: [{ lastUsedDate: '2023-05-01T10:00:00.000Z', password: 'older' }],
        revisionDate: '2024-01-02T03:04:05.000Z', creationDate: '2022-01-01T00:00:00.000Z', deletedDate: null, collectionIds: null,
      },
      { id: 'i2', folderId: null, type: 2, name: 'Wi-Fi', notes: 'SSID: home\nKey: 12345', favorite: false, secureNote: { type: 0 } },
      {
        id: 'i3', folderId: 'f2', type: 3, name: 'Visa', notes: null, favorite: false,
        card: { cardholderName: 'A Person', brand: 'Visa', number: '4111111111111111', expMonth: '4', expYear: '2030', code: '123' },
      },
      {
        id: 'i4', folderId: 'f2', type: 4, name: 'Me', favorite: false,
        identity: { title: 'Dr', firstName: 'Ada', middleName: null, lastName: 'Lovelace', address1: '1 Main St', city: 'London', country: 'UK', email: 'ada@example.com', ssn: '000-00-0000' },
      },
      { id: 'i5', type: 5, name: 'Deploy key', sshKey: { privateKey: 'PRIVATE', publicKey: 'ssh-ed25519 AAAA', keyFingerprint: 'SHA256:abc' } },
      { id: 'i6', type: 99, name: 'From the future' },
      null,
    ],
  };

  test('reads a Bitwarden JSON export', () => {
    const result = parseImport(JSON.stringify(bitwardenExport));
    assert.equal(result.format, 'bitwarden-json');
    assert.equal(result.items.length, 5);

    const [login, note, card, identity, ssh] = result.items.map((draft) => ({ ...normalizeItem(draft), folderName: draft.folderName }));
    assert.equal(login.type, 'login');
    assert.equal(login.name, 'GitHub');
    assert.equal(login.folderName, 'Work');
    assert.equal(login.favorite, true);
    assert.deepEqual(login.login, { username: 'octocat', password: 'correct horse', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://github.com/login', 'https://github.com'] });
    assert.deepEqual(login.fields, [
      { name: 'Recovery', value: 'abcd-efgh', type: 'hidden' },
      { name: 'Enabled', value: 'true', type: 'boolean' },
    ]);
    assert.deepEqual(login.passwordHistory, [{ password: 'older', changedAt: '2023-05-01T10:00:00.000Z' }]);
    assert.equal(login.createdAt, '2022-01-01T00:00:00.000Z');
    assert.equal(login.updatedAt, '2024-01-02T03:04:05.000Z');

    assert.equal(note.type, 'note');
    assert.equal(note.notes, 'SSID: home\nKey: 12345');
    assert.equal(note.folderName, '');

    assert.deepEqual(card.card, { cardholder: 'A Person', number: '4111111111111111', brand: 'Visa', code: '123', expMonth: '4', expYear: '2030' });
    assert.equal(card.folderName, 'Personal');

    assert.equal(identity.identity.firstName, 'Ada');
    assert.equal(identity.identity.middleName, '');
    assert.equal(identity.identity.ssn, '000-00-0000');

    assert.equal(ssh.type, 'note');
    assert.deepEqual(ssh.fields[0], { name: 'Private key', value: 'PRIVATE', type: 'hidden' });

    assert.equal(result.warnings.length, 2);
    assert.match(result.warnings[0], /1 passkey/);
    assert.match(result.warnings[1], /2 items are/);
  });

  test('explains why encrypted Bitwarden exports cannot be read', () => {
    assert.throws(() => parseImport('{"encrypted":true,"passwordProtected":true,"data":"2.abc"}'), (err) => err instanceof ImportError && /encrypted/.test(err.message));
    assert.throws(() => parseImport('{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.x","items":[]}'), ImportError);
  });

  test('rejects files it does not understand', () => {
    assert.throws(() => parseImport(''), ImportError);
    assert.throws(() => parseImport('   \n '), ImportError);
    assert.throws(() => parseImport('{"hello": "world"}'), ImportError);
    assert.throws(() => parseImport('{"items": '), ImportError);
    assert.throws(() => parseImport('[1,2,3]'), ImportError);
    assert.throws(() => parseImport('color,size\nred,large'), ImportError);
    assert.throws(() => parseImport('name,url,username,password'), ImportError);
  });

  test('reads a Bitwarden CSV export', () => {
    const csv = [
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
      'Work,1,login,GitHub,"two\nlines","Recovery: abcd\nSeat: 12A",0,"https://github.com/login,https://github.com",octocat,"p,w""x",JBSWY3DPEHPK3PXP',
      ',,note,Wi-Fi,"SSID: home",,0,,,,',
      ',,login,,,,0,https://example.org/path,solo,pw,',
    ].join('\n');
    const result = parseImport(csv);
    assert.equal(result.format, 'bitwarden-csv');
    const [login, note, unnamed] = result.items;
    assert.equal(login.folderName, 'Work');
    assert.equal(login.favorite, true);
    assert.equal(login.notes, 'two\nlines');
    assert.deepEqual(login.login, { username: 'octocat', password: 'p,w"x', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://github.com/login', 'https://github.com'] });
    assert.deepEqual(login.fields, [{ name: 'Recovery', value: 'abcd', type: 'text' }, { name: 'Seat', value: '12A', type: 'text' }]);
    assert.equal(note.type, 'note');
    assert.equal(note.login, undefined);
    assert.equal(unnamed.name, 'example.org');
  });

  test('reads CSV exports from browsers and other managers', () => {
    const chrome = parseImport('name,url,username,password,note\nExample,https://example.com/,alice,pw1,hello\n');
    assert.equal(chrome.format, 'csv');
    assert.deepEqual(chrome.items[0].login, { username: 'alice', password: 'pw1', totp: '', uris: ['https://example.com/'] });
    assert.equal(chrome.items[0].notes, 'hello');

    const firefox = parseImport('"url","username","password","httpRealm","formActionOrigin","guid","timeCreated"\n"https://accounts.example.com","bob","pw2",,"https://accounts.example.com","{abc}","1700000000000"');
    assert.equal(firefox.items[0].name, 'accounts.example.com');
    assert.equal(firefox.items[0].login.password, 'pw2');

    const lastpass = parseImport('url,username,password,totp,extra,name,grouping,fav\nhttps://shop.example,carol,pw3,,Some notes,Shop,Shopping,1\nhttp://sn,,,,"Alarm code 1234",Alarm,Home,0');
    assert.equal(lastpass.items[0].name, 'Shop');
    assert.equal(lastpass.items[0].folderName, 'Shopping');
    assert.equal(lastpass.items[0].favorite, true);
    assert.equal(lastpass.items[0].notes, 'Some notes');
    assert.equal(lastpass.items[1].type, 'note');
    assert.equal(lastpass.items[1].notes, 'Alarm code 1234');

    const onePassword = parseImport('Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nBank,https://bank.example,dave,pw4,otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP,true,false,,memo');
    assert.equal(onePassword.items[0].login.totp, 'otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP');
    assert.equal(onePassword.items[0].favorite, true);

    const keepass = parseImport('"Group","Title","Username","Password","URL","Notes"\n"Root/Internet","Forum","erin","pw5","https://forum.example",""');
    assert.equal(keepass.items[0].folderName, 'Root/Internet');
    assert.equal(keepass.items[0].login.username, 'erin');

    const safari = parseImport('Title,URL,Username,Password,Notes,OTPAuth\nexample.com (frank),https://example.com/,frank,pw6,,');
    assert.equal(safari.items[0].login.username, 'frank');
  });

  const sampleVault = () => {
    const folder = normalizeFolder({ name: 'Work' });
    const items = [
      normalizeItem({
        type: 'login', name: 'GitHub', folderId: folder.id, favorite: true, notes: 'line1\nline2',
        login: { username: 'octocat', password: '-Rk9!"x,=', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://github.com/login', 'https://github.com'] },
        fields: [{ name: 'Recovery', value: 'abcd', type: 'hidden' }, { name: 'Enabled', value: true, type: 'boolean' }, { name: 'Note', value: 'plain', type: 'text' }],
        passwordHistory: [{ password: 'previous', changedAt: '2024-03-01T00:00:00.000Z' }],
        createdAt: '2023-01-01T00:00:00.000Z', updatedAt: '2024-06-01T00:00:00.000Z',
      }),
      normalizeItem({ type: 'note', name: 'Wi-Fi', notes: 'SSID: home' }),
      normalizeItem({ type: 'card', name: 'Visa', card: { cardholder: 'A Person', brand: 'Visa', number: '4111111111111111', expMonth: '4', expYear: '2030', code: '123' } }),
      normalizeItem({ type: 'identity', name: 'Me', identity: { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.com', address1: '1 Main St', passportNumber: 'X123' } }),
      normalizeItem({ type: 'login', name: 'In the trash', deletedAt: '2024-06-01T00:00:00.000Z', login: { password: 'gone' } }),
    ];
    return { folder, items };
  };

  test('JSON export is in Bitwarden format and re-imports without loss', () => {
    const { folder, items } = sampleVault();
    const exported = toBitwardenJson(items, [folder]);
    assert.equal(exported.encrypted, false);
    assert.deepEqual(exported.folders, [{ id: folder.id, name: 'Work' }]);
    assert.equal(exported.items.length, 4, 'trashed items are not exported');
    assert.deepEqual(exported.items.map((item) => item.type), [1, 2, 3, 4]);
    assert.deepEqual(exported.items[0].login.uris[0], { match: null, uri: 'https://github.com/login' });
    assert.deepEqual(exported.items[1].secureNote, { type: 0 });
    assert.equal(exported.items[2].card.cardholderName, 'A Person');

    const reimported = parseImport(JSON.stringify(exported));
    assert.deepEqual(reimported.warnings, []);
    const live = items.filter((item) => !item.deletedAt);
    reimported.items.forEach((draft, index) => {
      const original = live[index];
      const roundTripped = normalizeItem({ ...draft, id: original.id, folderId: original.folderId });
      assert.deepEqual(roundTripped, original, original.name);
      assert.equal(draft.folderName, original.folderId ? 'Work' : '');
    });
  });

  test('CSV export re-imports logins and notes without loss', () => {
    const { folder, items } = sampleVault();
    const csv = toBitwardenCsv(items, [folder]);
    const { items: drafts, format } = parseImport(csv);
    assert.equal(format, 'bitwarden-csv');
    assert.equal(drafts.length, 2, 'CSV carries logins and notes only');
    assert.equal(drafts[0].folderName, 'Work');
    assert.equal(drafts[0].favorite, true);
    assert.equal(drafts[0].notes, 'line1\nline2');
    assert.deepEqual(drafts[0].login, items[0].login, 'passwords with quotes, commas and leading symbols must survive');
    assert.deepEqual(drafts[0].fields.map((f) => [f.name, f.value]), [['Recovery', 'abcd'], ['Enabled', 'true'], ['Note', 'plain']]);
    assert.equal(drafts[1].type, 'note');
    assert.equal(drafts[1].notes, 'SSID: home');
  });

  test('encrypted backups need their password and hide their contents', async () => {
    const { folder, items } = sampleVault();
    const backup = await toEncryptedBackup(items, [folder], 'backup password', FAST_KDF);
    const serialized = JSON.stringify(backup);
    for (const secret of ['GitHub', 'octocat', '-Rk9!', '4111111111111111', 'Lovelace', 'Work']) {
      assert.ok(!serialized.includes(secret), `${secret} is visible in the backup file`);
    }

    const detected = parseImport(serialized);
    assert.equal(detected.format, 'backup');
    assert.equal(detected.encrypted, true);
    await assert.rejects(openEncryptedBackup(detected.envelope, 'not the password'));

    const opened = parseImport(await openEncryptedBackup(detected.envelope, 'backup password'));
    assert.equal(opened.items.length, 4);
    assert.equal(opened.items[0].login.password, '-Rk9!"x,=');
    assert.throws(() => parseImport(JSON.stringify({ format: 'password-vault-backup', version: 1 })), ImportError);
  });
});

describe('breach check', () => {
  // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
  const fakeFetch = (log) => async (url) => {
    log.push(url);
    const prefix = url.split('/').pop();
    const body = prefix === '5BAA6' ? '0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\r\n' : 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2\r\n';
    return { ok: true, status: 200, text: async () => body };
  };

  test('only sends five-character hash prefixes and matches locally', async () => {
    const requests = [];
    const progress = [];
    const result = await findBreachedPasswords(['password', 'a-unique-passphrase-nobody-has', 'password', ''], {
      fetch: fakeFetch(requests),
      onProgress: (done, total) => progress.push([done, total]),
    });
    assert.equal(result.get('password'), 3730471);
    assert.equal(result.get('a-unique-passphrase-nobody-has'), 0);
    assert.equal(result.size, 2);
    assert.equal(requests.length, 2);
    for (const url of requests) assert.match(url, /^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/);
    assert.deepEqual(progress.at(-1), [2, 2]);
  });

  test('fails loudly when the service is unavailable', async () => {
    const broken = async () => ({ ok: false, status: 503, text: async () => '' });
    await assert.rejects(findBreachedPasswords(['password'], { fetch: broken }), /503/);
    assert.equal((await findBreachedPasswords([], { fetch: broken })).size, 0);
  });
});

describe('vault health', () => {
  test('finds weak, reused and insecure logins', () => {
    const login = (name, password, uris = [], extra = {}) => normalizeItem({ type: 'login', name, login: { password, uris }, ...extra });
    const strong = 'q7!Zp2@Lm9#Xr4$Vt6&K';
    const report = analyzeVault([
      login('Strong', strong, ['https://a.example']),
      login('Weak', 'password1'),
      login('Twin A', 'shared-Pass-9431-xyz!'),
      login('Twin B', 'shared-Pass-9431-xyz!'),
      login('Old router', strong.split('').reverse().join(''), ['http://192.168.0.1']),
      login('No password', ''),
      login('Trashed twin', 'shared-Pass-9431-xyz!', [], { deletedAt: new Date().toISOString() }),
      normalizeItem({ type: 'note', name: 'Note', notes: 'password1' }),
    ]);
    assert.equal(report.logins, 5);
    assert.deepEqual(report.weak.map(({ item }) => item.name), ['Weak']);
    assert.equal(report.reused.length, 1);
    assert.deepEqual(report.reused[0].items.map((item) => item.name), ['Twin A', 'Twin B']);
    assert.deepEqual(report.insecure.map((item) => item.name), ['Old router']);
  });
});
