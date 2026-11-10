// Browser tests: drive the real app in Chromium against a real server.
//
//   npm run test:e2e
//
// Needs Playwright (`npm install --no-save playwright && npx playwright install chromium`).
// It is not a dependency of the app itself, which has none.

import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createApp } from '../../server/app.js';
import { generateTotp, parseTotp } from '../../public/js/lib/totp.js';
import { parseImport } from '../../public/js/lib/importers.js';
import { openEncryptedBackup } from '../../public/js/lib/exporters.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const outputDir = path.join(here, 'output');
const fixture = path.join(here, '..', 'fixtures', 'bitwarden-export.json');

let chromium;
let devices;
try {
  ({ chromium, devices } = createRequire(import.meta.url)('playwright'));
} catch {
  console.error('Playwright is not installed. Run:\n  npm install --no-save playwright && npx playwright install chromium');
  process.exit(1);
}

const STEP_TIMEOUT_MS = 8000; // long enough for key derivation, short enough to fail fast
const EMAIL = 'ada@example.com';
const MASTER = 'orbit-lantern-quartz-meadow-7';
const NEW_MASTER = 'velvet-harbor-cactus-signal-42';

// ---- Harness ----

async function startServer(options = {}) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'vault-e2e-'));
  const app = await createApp({ dataDir, quiet: true, ...options });
  const server = http.createServer(app.handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    // "localhost" rather than 127.0.0.1 so the page is a secure context in every browser.
    url: `http://localhost:${server.address().port}/`,
    dataDir,
    async close() {
      const closed = new Promise((resolve) => server.close(resolve));
      server.closeAllConnections();
      await closed;
      await app.close();
      await rm(dataDir, { recursive: true, force: true });
    },
  };
}

const results = [];
const problems = []; // console errors, uncaught exceptions and CSP violations
let currentPage = null;

async function step(name, run) {
  const started = Date.now();
  try {
    await run();
    results.push({ name, ok: true });
    console.log(`  ✔ ${name} (${Date.now() - started}ms)`);
  } catch (error) {
    results.push({ name, ok: false });
    console.log(`  ✖ ${name}\n      ${String(error.stack ?? error).split('\n').slice(0, 6).join('\n      ')}`);
    if (currentPage) {
      const file = path.join(outputDir, `${name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}.png`);
      await currentPage.screenshot({ path: file }).catch(() => {});
      console.log(`      screenshot: ${file}`);
    }
  }
}

function watch(page, label) {
  page.on('console', (message) => {
    if (message.type() === 'error') problems.push(`${label}: console error: ${message.text()}`);
  });
  page.on('pageerror', (error) => problems.push(`${label}: uncaught ${error.message}`));
}

async function newPage(context, label) {
  const page = await context.newPage();
  page.setDefaultTimeout(STEP_TIMEOUT_MS);
  watch(page, label);
  return page;
}

async function signUp(page, url, email = EMAIL, password = MASTER) {
  await page.goto(url);
  await page.getByRole('heading', { name: 'Create your vault' }).waitFor();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Master password', { exact: true }).fill(password);
  await page.getByLabel('Confirm master password').fill(password);
  await page.getByRole('button', { name: 'Create vault' }).click();
  await page.locator('.shell').waitFor();
}

async function unlock(page, password = MASTER, email = EMAIL) {
  await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Master password').fill(password);
  await page.getByRole('button', { name: 'Unlock' }).click();
}

const row = (page, name) => page.locator('.list .row', { hasText: name });
/** Waits for a confirmation message, then dismisses it so it cannot be mistaken for a later one. */
async function sawToast(page, text) {
  const message = page.locator('.toast', { hasText: text }).last();
  await message.waitFor();
  await page.evaluate(() => document.querySelectorAll('.toast').forEach((el) => el.remove()));
}
const field = (page, label) => page.locator('.detail .field', { has: page.locator('.field-name', { hasText: label }) });
const clipboard = (page) => page.evaluate(() => navigator.clipboard.readText());
const navItem = (page, name) => page.locator('.sidebar-nav .nav-item', { hasText: name });

async function addLogin(page, { name, username, password, website }) {
  await page.getByRole('button', { name: 'New', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Login' }).click();
  await page.getByLabel('Name', { exact: true }).fill(name);
  if (username) await page.getByLabel('Username or email').fill(username);
  if (password) await page.getByLabel('Password', { exact: true }).fill(password);
  if (website) await page.getByLabel('Website 1').fill(website);
  await page.getByRole('button', { name: 'Save' }).click();
  await sawToast(page, 'Item added');
  await page.locator('.detail-title', { hasText: name }).waitFor();
}

// ---- Tests ----

async function main() {
  await mkdir(outputDir, { recursive: true });
  const browser = await chromium.launch();
  const server = await startServer();
  const context = await browser.newContext({
    viewport: { width: 1360, height: 860 },
    permissions: ['clipboard-read', 'clipboard-write'],
    acceptDownloads: true,
  });
  const page = await newPage(context, 'main');
  currentPage = page;
  let generated = '';

  console.log('\nFirst run');

  await step('refuses weak or mismatched master passwords', async () => {
    await page.goto(server.url);
    await page.getByRole('heading', { name: 'Create your vault' }).waitFor();
    await page.getByLabel('Email').fill(EMAIL);
    const password = page.getByLabel('Master password', { exact: true });
    const confirm = page.getByLabel('Confirm master password');
    const submit = page.getByRole('button', { name: 'Create vault' });
    const error = page.locator('.auth-error');

    await password.fill('short');
    await confirm.fill('short');
    await submit.click();
    await assert.doesNotReject(error.filter({ hasText: 'at least 12 characters' }).waitFor());

    await password.fill('passwordpassword');
    await confirm.fill('passwordpassword');
    await submit.click();
    await error.filter({ hasText: 'too easy to guess' }).waitFor();

    await password.fill(MASTER);
    await confirm.fill(`${MASTER}x`);
    await submit.click();
    await error.filter({ hasText: 'do not match' }).waitFor();

    // Acceptable but weak: allowed only after an explicit confirmation.
    await password.fill('winter is coming 99');
    await confirm.fill('winter is coming 99');
    await submit.click();
    const warning = page.getByRole('dialog', { name: 'Use a weak master password?' });
    await warning.getByRole('button', { name: 'Choose another' }).click();
    assert.equal(await page.locator('.shell').count(), 0);
  });

  await step('creates a vault and shows the empty state', async () => {
    await signUp(page, server.url);
    await page.getByRole('heading', { name: 'Your vault is ready' }).waitFor();
    assert.equal(await page.locator('.account-email').textContent(), EMAIL);
  });

  console.log('\nItems');

  await step('adds a login with a generated password', async () => {
    await page.getByRole('button', { name: 'Add a login' }).click();
    await page.getByLabel('Name', { exact: true }).fill('GitHub');
    await page.getByLabel('Username or email').fill('octocat');
    await page.getByRole('button', { name: 'Generate a password' }).click();
    const dialog = page.getByRole('dialog', { name: 'Generator' });
    await dialog.waitFor();
    generated = (await dialog.locator('.gen-value').textContent()).trim();
    assert.equal(generated.length, 20);
    await dialog.getByRole('button', { name: 'Generate another' }).click();
    const second = (await dialog.locator('.gen-value').textContent()).trim();
    assert.notEqual(second, generated, 'regenerating gives a new password');
    generated = second;
    await dialog.getByRole('button', { name: 'Use password' }).click();
    assert.equal(await page.getByLabel('Password', { exact: true }).inputValue(), generated);

    await page.getByLabel('Website 1').fill('https://github.com/login');
    await page.getByLabel('Notes').fill('Line one\nLine two');
    await page.getByRole('button', { name: 'Add field' }).click();
    await page.getByRole('menuitem', { name: 'Hidden (masked)' }).click();
    await page.getByLabel('Field name').fill('Recovery code');
    await page.getByPlaceholder('Hidden value').fill('abcd-1234');
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Item added');

    await page.locator('.detail-title', { hasText: 'GitHub' }).waitFor();
    assert.equal(await row(page, 'GitHub').getAttribute('aria-selected'), 'true');
    assert.match(await row(page, 'GitHub').textContent(), /octocat/);
  });

  await step('hides secrets until revealed, and copies them', async () => {
    const password = field(page, 'Password');
    assert.ok(!(await password.textContent()).includes(generated), 'the password must start hidden');
    assert.ok(!(await page.locator('.detail').textContent()).includes('abcd-1234'), 'hidden fields must start hidden');

    await password.getByRole('button', { name: 'Show password' }).click();
    assert.ok((await password.locator('.field-value').textContent()).includes(generated));
    await password.getByRole('button', { name: 'Hide password' }).click();
    assert.ok(!(await password.textContent()).includes(generated));

    await password.getByRole('button', { name: 'Copy password' }).click();
    await sawToast(page, 'Password copied');
    assert.equal(await clipboard(page), generated);

    await field(page, 'Username').click(); // clicking a row copies it too
    await sawToast(page, 'Username copied');
    assert.equal(await clipboard(page), 'octocat');

    await field(page, 'Recovery code').getByRole('button', { name: 'Copy recovery code' }).click();
    assert.equal(await clipboard(page), 'abcd-1234');
    assert.equal(await field(page, 'Notes').locator('.field-value').textContent(), 'Line one\nLine two');
  });

  await step('shows live verification codes for an authenticator key', async () => {
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Authenticator key').fill('not a key!!');
    await page.locator('.field-error', { hasText: 'does not look like a valid key' }).waitFor();
    await page.getByLabel('Authenticator key').fill('JBSWY3DPEHPK3PXP');
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');

    const shown = field(page, 'Verification code').locator('.totp-code');
    await assert.doesNotReject(page.waitForFunction(() => /^\d{3} \d{3}$/.test(document.querySelector('.totp-code')?.textContent ?? '')));
    const config = parseTotp('JBSWY3DPEHPK3PXP');
    const now = Date.now();
    const valid = await Promise.all([now - 30_000, now, now + 30_000].map(async (time) => (await generateTotp(config, time)).code));
    const code = (await shown.textContent()).replace(/\s/g, '');
    assert.ok(valid.includes(code), `code ${code} should be one of ${valid}`);

    await field(page, 'Verification code').getByRole('button', { name: 'Copy verification code' }).click();
    assert.ok(valid.includes(await clipboard(page)));
  });

  await step('keeps a history when a password is replaced', async () => {
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Password', { exact: true }).fill('a-brand-new-Passw0rd!');
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');
    const history = page.locator('.history');
    await history.locator('summary').click();
    await history.getByRole('button', { name: /^Copy replaced/ }).click();
    assert.equal(await clipboard(page), generated);
  });

  await step('asks before discarding unsaved edits', async () => {
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Renamed by mistake');
    await page.locator('.editor-head').getByRole('button', { name: 'Cancel' }).click();
    const confirm = page.getByRole('dialog', { name: 'Discard changes?' });
    await confirm.getByRole('button', { name: 'Keep editing' }).click();
    assert.equal(await page.getByLabel('Name', { exact: true }).inputValue(), 'Renamed by mistake');
    await page.locator('.editor-head').getByRole('button', { name: 'Cancel' }).click();
    await confirm.getByRole('button', { name: 'Discard' }).click();
    await page.locator('.detail-title', { hasText: 'GitHub' }).waitFor();
  });

  await step('requires a name, or borrows one from the website', async () => {
    await page.getByRole('button', { name: 'New', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Secure note' }).click();
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.field-error', { hasText: 'Give this item a name' }).waitFor();
    await page.locator('.editor-head').getByRole('button', { name: 'Cancel' }).click();

    await page.getByRole('button', { name: 'New', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Login' }).click();
    await page.getByLabel('Website 1').fill('https://www.example.org/account');
    await page.getByLabel('Password', { exact: true }).fill('password1');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.detail-title', { hasText: 'example.org' }).waitFor();
    await page.locator('.detail .badge', { hasText: 'Weak' }).waitFor();
  });

  await step('adds a card, an identity and a note', async () => {
    await page.getByRole('button', { name: 'New', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Card' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Everyday Visa');
    await page.getByLabel('Cardholder name').fill('Ada Lovelace');
    await page.getByLabel('Card number').fill('4242 4242 4242 4242');
    assert.equal(await page.getByLabel('Brand').inputValue(), 'Visa', 'the brand is detected from the number');
    await page.getByLabel('Expiry month').fill('8');
    await page.getByLabel('Expiry year').fill('2031');
    await page.getByLabel('Security code').fill('123');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.detail-title', { hasText: 'Everyday Visa' }).waitFor();
    assert.match(await field(page, 'Card number').locator('.field-value').textContent(), /4242$/);
    assert.ok(!(await field(page, 'Card number').textContent()).includes('4242 4242 4242 4242'));
    assert.equal(await field(page, 'Expires').locator('.field-value').textContent(), '08 / 2031');
    await field(page, 'Card number').getByRole('button', { name: 'Copy card number' }).click();
    assert.equal(await clipboard(page), '4242424242424242');
    assert.match(await row(page, 'Everyday Visa').textContent(), /Visa •••• 4242/);

    await page.getByRole('button', { name: 'New', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Identity' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Me');
    await page.getByLabel('First name').fill('Ada');
    await page.getByLabel('Last name').fill('Lovelace');
    await page.getByLabel('Address line 1').fill('12 St James Square');
    await page.getByLabel('City / town').fill('London');
    await page.getByLabel('Passport number').fill('X1234567');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.detail-title', { hasText: 'Me' }).waitFor();
    assert.equal(await field(page, 'Name').locator('.field-value').textContent(), 'Ada Lovelace');
    assert.ok(!(await page.locator('.detail').textContent()).includes('X1234567'));

    await page.getByRole('button', { name: 'New', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Secure note' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Door code');
    await page.getByLabel('Notes').fill('4321 then #');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.detail-title', { hasText: 'Door code' }).waitFor();
    assert.ok(!(await row(page, 'Door code').textContent()).includes('4321'), 'note text must not show in the list');
  });

  await step('treats hostile text as text, never as markup', async () => {
    const payload = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>';
    await page.getByRole('button', { name: 'New', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Login' }).click();
    await page.getByLabel('Name', { exact: true }).fill(payload);
    await page.getByLabel('Username or email').fill(payload);
    await page.getByLabel('Website 1').fill('javascript:window.__xss=3');
    await page.getByLabel('Notes').fill(payload);
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Item added');
    assert.equal(await page.locator('.detail-title').textContent(), payload);
    assert.equal(await page.locator('.detail img, .list img, .detail script').count(), 0);
    assert.equal(await page.locator('.detail a[href^="javascript"]').count(), 0, 'unsafe addresses are never links');
    assert.equal(await field(page, 'Website').getByRole('button', { name: 'Open website' }).count(), 0);
    await page.fill('input[type=search]', '<img');
    await row(page, '<img').waitFor();
    await page.fill('input[type=search]', '');
    assert.equal(await page.evaluate(() => window.__xss), undefined);

    await page.getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'Move to trash' }).click();
    await sawToast(page, 'Moved to trash');
  });

  console.log('\nOrganizing');

  await step('searches, and focuses search with "/"', async () => {
    await page.locator('.list-title').click();
    await page.keyboard.press('/');
    await page.keyboard.type('octo');
    await assert.doesNotReject(page.locator('.list .row').first().waitFor());
    assert.equal(await page.locator('.list .row').count(), 1);
    assert.match(await page.locator('.list-meta').textContent(), /1 result/);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('input[type=search]').inputValue(), '');
    await page.fill('input[type=search]', 'nothing-matches-this');
    await page.getByRole('heading', { name: 'No matches' }).waitFor();
    await page.locator('.empty').getByRole('button', { name: 'Clear search' }).click();
    assert.ok((await page.locator('.list .row').count()) >= 5);

    await page.fill('input[type=search]', 'a-brand-new-Passw0rd');
    await page.getByRole('heading', { name: 'No matches' }).waitFor(); // passwords are not searchable
    await page.fill('input[type=search]', '');
  });

  await step('moves through the list with the keyboard', async () => {
    await page.locator('input[type=search]').focus();
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    const second = page.locator('.list .row').nth(1);
    assert.equal(await second.getAttribute('aria-selected'), 'true');
    const name = await second.locator('.row-title').textContent();
    assert.equal(await page.locator('.detail-title').textContent(), name);
  });

  await step('marks favorites', async () => {
    await row(page, 'GitHub').click();
    await page.getByRole('button', { name: 'Add to favorites' }).click();
    await page.getByRole('button', { name: 'Remove from favorites' }).waitFor();
    await navItem(page, 'Favorites').click();
    assert.equal(await page.locator('.list .row').count(), 1);
    await navItem(page, 'All items').click();
  });

  await step('creates, uses, renames and deletes folders', async () => {
    await page.getByRole('button', { name: 'New folder' }).click();
    const prompt = page.getByRole('dialog', { name: 'New folder' });
    await prompt.getByLabel('Folder name').fill('Work');
    await prompt.getByRole('button', { name: 'Create' }).click();
    await navItem(page, 'Work').waitFor();

    await row(page, 'GitHub').click();
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Folder', { exact: true }).selectOption({ label: 'Work' });
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');
    await page.locator('.detail-meta', { hasText: 'Work' }).waitFor();

    await navItem(page, 'Work').click();
    assert.equal(await page.locator('.list .row').count(), 1);
    assert.equal(await page.locator('.list-title').textContent(), 'Work');

    await page.getByRole('button', { name: 'Options for Work' }).click();
    await page.getByRole('menuitem', { name: 'Rename' }).click();
    const rename = page.getByRole('dialog', { name: 'Rename folder' });
    await rename.getByLabel('Folder name').fill('Office');
    await rename.getByRole('button', { name: 'Save' }).click();
    await navItem(page, 'Office').waitFor();
    await page.locator('.detail-meta', { hasText: 'Office' }).waitFor();

    // A folder can also be created from inside the editor.
    await navItem(page, 'All items').click();
    await row(page, 'Door code').click();
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Folder', { exact: true }).selectOption({ label: 'New folder…' });
    const inline = page.getByRole('dialog', { name: 'New folder' });
    await inline.getByLabel('Folder name').fill('Home');
    await inline.getByRole('button', { name: 'Create' }).click();
    await assert.doesNotReject(page.waitForFunction(() => document.querySelector('select')?.selectedOptions[0]?.textContent === 'Home'));
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.detail-meta', { hasText: 'Home' }).waitFor();

    await page.getByRole('button', { name: 'Options for Office' }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await page.getByRole('dialog', { name: /Delete “Office”/ }).getByRole('button', { name: 'Delete folder' }).click();
    await sawToast(page, 'Folder deleted');
    assert.equal(await navItem(page, 'Office').count(), 0);
    await row(page, 'GitHub').waitFor(); // the item survives, now unfiled
  });

  await step('trashes, restores and permanently deletes', async () => {
    await row(page, 'example.org').click();
    await page.getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'Move to trash' }).click();
    await sawToast(page, 'Moved to trash');
    assert.equal(await row(page, 'example.org').count(), 0);

    await navItem(page, 'Trash').click();
    assert.equal(await page.locator('.list .row').count(), 2);
    await row(page, 'example.org').click();
    await page.locator('.banner', { hasText: 'In the trash' }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Edit' }).count(), 0, 'trashed items are read-only');
    await page.getByRole('button', { name: 'Restore' }).click();
    await sawToast(page, 'Item restored');
    assert.equal(await page.locator('.list .row').count(), 1);

    await page.locator('.list .row').first().click();
    await page.getByRole('button', { name: 'Delete now' }).click();
    await page.getByRole('dialog', { name: 'Delete permanently?' }).getByRole('button', { name: 'Delete permanently' }).click();
    await sawToast(page, 'Item deleted');
    await page.getByRole('heading', { name: 'Trash is empty' }).waitFor();
    await navItem(page, 'All items').click();
    await row(page, 'example.org').waitFor();
  });

  await step('saves with Ctrl+S and cancels with Escape', async () => {
    await row(page, 'Door code').click();
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Front door code');
    await page.keyboard.press('Control+s');
    await sawToast(page, 'Changes saved');
    await page.locator('.detail-title', { hasText: 'Front door code' }).waitFor();

    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Name', { exact: true }).fill('Door code');
    await page.keyboard.press('Control+s');
    await sawToast(page, 'Changes saved');

    await page.getByRole('button', { name: 'Edit' }).click();
    await page.keyboard.press('Escape'); // nothing changed, so no confirmation is needed
    await page.locator('.detail-title', { hasText: 'Door code' }).waitFor();
    assert.equal(await page.locator('.editor-head').count(), 0);
  });

  await step('keeps an edit safe when the connection drops', async () => {
    await row(page, 'Door code').click();
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Notes').fill('typed while offline');
    await context.setOffline(true);
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Can’t reach the server');
    assert.equal(await page.getByLabel('Notes').inputValue(), 'typed while offline', 'nothing typed is lost');
    assert.equal(await page.getByRole('button', { name: 'Save' }).isEnabled(), true, 'saving can be tried again');

    await context.setOffline(false);
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');
    assert.equal(await field(page, 'Note').locator('.field-value').textContent(), 'typed while offline');

    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Notes').fill('4321 then #');
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');
  });

  await step('duplicates an item', async () => {
    await row(page, 'GitHub').click();
    await page.getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'Duplicate' }).click();
    assert.equal(await page.getByLabel('Name', { exact: true }).inputValue(), 'GitHub (copy)');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.locator('.detail-title', { hasText: 'GitHub (copy)' }).waitFor();
    assert.equal(await page.locator('.history').count(), 0, 'a copy starts without password history');
  });

  console.log('\nLocking');

  await step('locks, rejects the wrong password, and unlocks with everything intact', async () => {
    await page.getByRole('button', { name: 'Lock vault' }).click();
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
    assert.equal(await page.locator('.shell').count(), 0);
    assert.equal(await page.getByLabel('Email').inputValue(), EMAIL, 'the email is remembered');
    assert.equal(await page.getByText('Create a vault').count(), 0, 'sign-ups close after the first account');
    assert.ok(!(await page.content()).includes('octocat'), 'nothing from the vault may remain in the page');

    await page.getByLabel('Master password').fill('definitely-not-the-password');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.locator('.auth-error', { hasText: 'Incorrect email or master password' }).waitFor();

    await page.getByLabel('Master password').fill(MASTER);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.locator('.shell').waitFor();
    await row(page, 'GitHub (copy)').waitFor();
    await row(page, 'GitHub').first().click();
    await field(page, 'Password').getByRole('button', { name: 'Copy password' }).click();
    assert.equal(await clipboard(page), 'a-brand-new-Passw0rd!');
  });

  await step('locks a tab the browser parks in its back/forward cache, and only that tab', async () => {
    const parked = await newPage(context, 'parked tab');
    await parked.goto(server.url);
    await unlock(parked);
    await parked.locator('.shell').waitFor();

    // Browsers keep such pages alive in memory; simulate the page being parked.
    await parked.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
    await parked.getByRole('heading', { name: 'Welcome back' }).waitFor();
    assert.ok(!(await parked.content()).includes('octocat'));
    await parked.close();

    // Leaving one tab is not a reason to lock the others (and lose their unsaved edits).
    await page.waitForTimeout(400);
    assert.equal(await page.locator('.shell').count(), 1);
    // An ordinary page unload needs no handling: memory is discarded anyway.
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false })));
    await page.waitForTimeout(200);
    assert.equal(await page.locator('.shell').count(), 1);
  });

  await step('locks every tab together and syncs changes between tabs', async () => {
    const second = await newPage(context, 'second tab');
    await second.goto(server.url);
    await unlock(second);
    await second.locator('.shell').waitFor();
    await row(second, 'Door code').waitFor();

    await addLogin(page, { name: 'Made in tab one', username: 'first', password: 'Tab-One-Passw0rd!' });
    await row(second, 'Made in tab one').waitFor({ timeout: 10_000 });

    await second.getByRole('button', { name: 'Lock vault' }).click();
    await second.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor({ timeout: 10_000 });
    await second.close();
    await unlock(page);
    await page.locator('.shell').waitFor();
  });

  await step('warns before overwriting a change made in another tab', async () => {
    const other = await newPage(context, 'other tab');
    await other.goto(server.url);
    await unlock(other);
    await other.locator('.shell').waitFor();

    // This tab starts editing...
    await row(page, 'Door code').click();
    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Notes').fill('edited in the first tab');

    // ...while the other tab changes and saves the same item.
    await row(other, 'Door code').click();
    await other.getByRole('button', { name: 'Edit' }).click();
    await other.getByLabel('Notes').fill('edited in the other tab');
    await other.getByRole('button', { name: 'Save' }).click();
    await sawToast(other, 'Changes saved');
    await page.waitForTimeout(800); // let the first tab sync in the background

    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'changed on another device');
    assert.equal(await page.getByLabel('Notes').inputValue(), 'edited in the first tab', 'the edit in progress is kept');
    await other.reload(); // nothing was overwritten yet
    await unlock(other);
    await row(other, 'Door code').click();
    assert.equal(await field(other, 'Note').locator('.field-value').textContent(), 'edited in the other tab');

    // Saving again is a deliberate choice to keep this version.
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');
    await other.waitForFunction(() => document.querySelector('.detail .field-value.pre')?.textContent === 'edited in the first tab');
    await other.close();

    await page.getByRole('button', { name: 'Edit' }).click();
    await page.getByLabel('Notes').fill('4321 then #');
    await page.getByRole('button', { name: 'Save' }).click();
    await sawToast(page, 'Changes saved');
  });

  // The next two tests control time. Playwright's fake clock belongs to the
  // whole browser context, so they each get a context of their own.
  await step('locks automatically when idle, and clears the clipboard', async () => {
    const timedContext = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    await timedContext.clock.install();
    const timed = await newPage(timedContext, 'timed tab');
    await timed.goto(server.url);
    await unlock(timed);
    await timed.locator('.shell').waitFor();

    await row(timed, 'Door code').click();
    await timed.locator('.detail .field', { hasText: '4321' }).getByRole('button', { name: 'Copy note' }).click();
    assert.equal(await clipboard(timed), '4321 then #');
    await timedContext.clock.fastForward(31_000);
    await assert.doesNotReject(timed.waitForFunction(() => navigator.clipboard.readText().then((text) => text === '')));

    await timedContext.clock.fastForward('14:00');
    await timed.waitForTimeout(300);
    assert.equal(await timed.locator('.shell').count(), 1, 'still unlocked before the timeout');
    await timedContext.clock.fastForward('02:00');
    await timed.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await timed.locator('.auth-notice', { hasText: 'inactivity' }).waitFor();
    await timedContext.close();
  });

  await step('gives up on a refused clipboard wipe rather than erasing something unrelated later', async () => {
    const timedContext = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    await timedContext.clock.install();
    const tab = await newPage(timedContext, 'clipboard tab');
    await tab.goto(server.url);
    await unlock(tab);
    await tab.locator('.shell').waitFor();
    // Never lock during this test; only the clipboard timing matters here.
    await tab.evaluate(() => localStorage.setItem('vault.prefs.v1', JSON.stringify({ ...JSON.parse(localStorage.getItem('vault.prefs.v1') || '{}'), autoLockMinutes: 0 })));
    await tab.reload();
    await unlock(tab);
    await tab.locator('.shell').waitFor();

    // Make the browser refuse to empty the clipboard, as it does when the
    // page is in the background (Chrome) or there is no click (Safari, Firefox).
    const refuseWipes = (refuse) =>
      tab.evaluate((on) => {
        window.__realWrite ??= navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = (text) => (on && text === '' ? Promise.reject(new Error('refused')) : window.__realWrite(text));
      }, refuse);
    const copyNote = async () => {
      await row(tab, 'Door code').click();
      await tab.locator('.detail .field', { hasText: '4321' }).getByRole('button', { name: 'Copy note' }).click();
      assert.equal(await clipboard(tab), '4321 then #');
    };

    // Refused, but the person is back within a couple of minutes: the wipe goes through on their next click.
    await copyNote();
    await refuseWipes(true);
    await timedContext.clock.fastForward(31_000);
    assert.equal(await clipboard(tab), '4321 then #', 'the refused wipe leaves the clipboard as it was');
    await refuseWipes(false);
    await timedContext.clock.fastForward(60_000);
    await tab.locator('.list-title').click();
    await assert.doesNotReject(tab.waitForFunction(() => navigator.clipboard.readText().then((text) => text === '')));

    // Refused, and the person only comes back much later, having copied something else meanwhile.
    await copyNote();
    await refuseWipes(true);
    await timedContext.clock.fastForward(31_000);
    await refuseWipes(false);
    await tab.evaluate(() => window.__realWrite('something copied in another app'));
    await timedContext.clock.fastForward('03:00:00');
    await tab.locator('.list-title').click();
    await tab.waitForTimeout(300);
    assert.equal(await clipboard(tab), 'something copied in another app', 'an old pending wipe must not erase unrelated content');
    await timedContext.close();
  });

  await step('locks on the first click after the computer wakes from sleep', async () => {
    const timedContext = await browser.newContext();
    await timedContext.clock.install();
    const sleepy = await newPage(timedContext, 'sleepy tab');
    await sleepy.goto(server.url);
    await unlock(sleepy);
    await sleepy.locator('.shell').waitFor();
    await row(sleepy, 'GitHub').first().click();
    await sleepy.locator('.detail-title', { hasText: 'GitHub' }).waitFor();

    // Eight hours pass with no timers running, as when a laptop sleeps. The
    // very first thing that happens on waking is the person clicking, before
    // any timer has had the chance to notice.
    await timedContext.clock.setSystemTime(Date.now() + 8 * 60 * 60 * 1000);
    await sleepy.mouse.click(700, 500);
    await sleepy.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await sleepy.locator('.auth-notice', { hasText: 'inactivity' }).waitFor();
    assert.ok(!(await sleepy.content()).includes('octocat'), 'nothing from the vault is left on screen');
    await timedContext.close();
  });

  await step('does not lock while another tab is in use', async () => {
    const timedContext = await browser.newContext();
    await timedContext.clock.install();
    const busy = await newPage(timedContext, 'busy tab');
    const idle = await newPage(timedContext, 'idle tab');
    for (const tab of [busy, idle]) {
      await tab.goto(server.url);
      await unlock(tab);
      await tab.locator('.shell').waitFor();
    }

    await timedContext.clock.fastForward('14:00');
    await busy.locator('.list-title').click(); // the person is working in the first tab
    await idle.waitForTimeout(300);
    await timedContext.clock.fastForward('02:00'); // 16 minutes since the idle tab was last touched
    await idle.waitForTimeout(600);
    assert.equal(await idle.locator('.shell').count(), 1, 'activity in one tab keeps the others unlocked');
    assert.equal(await busy.locator('.shell').count(), 1);

    await timedContext.clock.fastForward('16:00'); // now nobody has touched anything
    await idle.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await busy.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await timedContext.close();
  });

  console.log('\nImport and export');

  await step('imports a Bitwarden export', async () => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Import' }).click();
    await settings.locator('input[type=file]').setInputFiles(fixture);
    await settings.locator('.summary-list', { hasText: 'Bitwarden (JSON)' }).waitFor();
    const summary = await settings.locator('.summary-list').textContent();
    assert.match(summary, /Logins18/);
    assert.match(summary, /Cards2/);
    assert.match(summary, /Folders4/);
    await settings.getByRole('button', { name: 'Import 23 items' }).click();
    await settings.locator('.all-clear', { hasText: '23 items imported' }).waitFor();
    await settings.locator('.callout', { hasText: 'Delete the export file' }).waitFor();

    // Importing the same file again must not create duplicates.
    await settings.getByRole('button', { name: 'Import another file' }).click();
    await settings.locator('input[type=file]').setInputFiles(fixture);
    await settings.getByRole('button', { name: 'Import 23 items' }).click();
    await settings.locator('.all-clear', { hasText: 'Nothing new to import' }).waitFor();
    await settings.getByRole('button', { name: 'Done' }).click();

    await navItem(page, 'Finance').click();
    assert.equal(await page.locator('.list .row').count(), 5);
    await navItem(page, 'All items').click();
    await row(page, 'First National Bank').click();
    await page.locator('.totp-code').waitFor();
  });

  await step('rejects files it cannot import, with a useful message', async () => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Import' }).click();
    await settings.locator('input[type=file]').setInputFiles({
      name: 'bitwarden_encrypted_export.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"encrypted":true,"passwordProtected":true,"data":"2.abc|def|ghi"}'),
    });
    await settings.locator('.auth-error', { hasText: 'can only be opened by Bitwarden' }).waitFor();
    await settings.locator('input[type=file]').setInputFiles({ name: 'photo.csv', mimeType: 'text/csv', buffer: Buffer.from('color,size\nred,large\n') });
    await settings.locator('.auth-error', { hasText: 'Could not find any recognizable columns' }).waitFor();
    await page.keyboard.press('Escape');
  });

  let backupFile = '';
  await step('exports an encrypted backup that hides its contents', async () => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Export' }).click();
    await settings.getByLabel('Backup password', { exact: true }).fill('backup-file-password');
    await settings.getByLabel('Confirm backup password').fill('backup-file-password');

    await settings.getByLabel('Confirm with your master password').fill('wrong-master-password');
    await settings.getByRole('button', { name: 'Export vault' }).click();
    await settings.locator('.auth-error', { hasText: 'master password is not correct' }).waitFor();

    await settings.getByLabel('Confirm with your master password').fill(MASTER);
    const [download] = await Promise.all([page.waitForEvent('download'), settings.getByRole('button', { name: 'Export vault' }).click()]);
    assert.match(download.suggestedFilename(), /^vault-backup-\d{4}-\d{2}-\d{2}\.json$/);
    backupFile = path.join(outputDir, 'backup.json');
    await download.saveAs(backupFile);

    const text = await readFile(backupFile, 'utf8');
    for (const secret of ['GitHub', 'octocat', 'a-brand-new-Passw0rd', 'Lovelace', '4242', MASTER]) {
      assert.ok(!text.includes(secret), `"${secret}" is readable in the encrypted backup`);
    }
    const envelope = JSON.parse(text);
    await assert.rejects(openEncryptedBackup(envelope, 'not-the-password'));
    const restored = parseImport(await openEncryptedBackup(envelope, 'backup-file-password'));
    assert.ok(restored.items.some((item) => item.name === 'GitHub' && item.login.password === 'a-brand-new-Passw0rd!'));
    assert.ok(restored.items.every((item) => item.name !== 'Made by mistake'));
  });

  await step('exports plain JSON and CSV after a warning', async () => {
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByText('Bitwarden JSON').click();
    await settings.locator('.callout-danger', { hasText: 'will not be encrypted' }).waitFor();
    await settings.getByLabel('Confirm with your master password').fill(MASTER);
    const [json] = await Promise.all([page.waitForEvent('download'), settings.getByRole('button', { name: 'Export vault' }).click()]);
    const jsonFile = path.join(outputDir, 'export.json');
    await json.saveAs(jsonFile);
    const exported = JSON.parse(await readFile(jsonFile, 'utf8'));
    assert.equal(exported.encrypted, false);
    assert.ok(exported.items.length >= 28);
    assert.ok(exported.folders.some((folder) => folder.name === 'Finance'));
    assert.equal(parseImport(JSON.stringify(exported)).items.length, exported.items.length);

    await settings.getByText('CSV', { exact: true }).click();
    await settings.getByLabel('Confirm with your master password').fill(MASTER);
    const [csv] = await Promise.all([page.waitForEvent('download'), settings.getByRole('button', { name: 'Export vault' }).click()]);
    const csvFile = path.join(outputDir, 'export.csv');
    await csv.saveAs(csvFile);
    const lines = (await readFile(csvFile, 'utf8')).trim().split('\r\n');
    assert.equal(lines[0], 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp');
    assert.ok(lines.some((line) => line.includes('GitHub') && line.includes('a-brand-new-Passw0rd!')));
    await page.keyboard.press('Escape');
    await rm(jsonFile, { force: true });
    await rm(csvFile, { force: true });
  });

  await step('restores an encrypted backup into a fresh vault', async () => {
    const other = await startServer();
    const fresh = await newPage(context, 'restore');
    try {
      await signUp(fresh, other.url, 'restore@example.com', MASTER);
      await fresh.getByRole('button', { name: 'Import passwords' }).click();
      const settings = fresh.getByRole('dialog', { name: 'Settings' });
      await settings.locator('input[type=file]').setInputFiles(backupFile);
      await settings.getByLabel('Backup password').fill('wrong');
      await settings.getByRole('button', { name: 'Open backup' }).click();
      await settings.locator('.auth-error', { hasText: 'not correct' }).waitFor();
      await settings.getByLabel('Backup password').fill('backup-file-password');
      await settings.getByRole('button', { name: 'Open backup' }).click();
      await settings.locator('.summary-list', { hasText: 'Bitwarden (JSON)' }).waitFor();
      await settings.getByRole('button', { name: /^Import \d+ items$/ }).click();
      await settings.locator('.all-clear', { hasText: 'imported' }).waitFor();
      assert.equal(await settings.locator('.callout', { hasText: 'Delete the export file' }).count(), 0, 'no warning for encrypted backups');
      await settings.getByRole('button', { name: 'Done' }).click();
      await row(fresh, 'First National Bank').waitFor();
      await navItem(fresh, 'Finance').waitFor();
    } finally {
      await fresh.close();
      await other.close();
      await rm(backupFile, { force: true });
    }
  });

  console.log('\nTools and settings');

  await step('reports weak and reused passwords', async () => {
    await page.getByRole('button', { name: 'Vault health' }).click();
    const health = page.getByRole('dialog', { name: 'Vault health' });
    await health.locator('.report', { hasText: 'Weak passwords' }).locator('.row', { hasText: 'Home Router' }).waitFor();
    const reused = health.locator('.report', { hasText: 'Reused passwords' });
    await reused.locator('.row', { hasText: 'Netflix' }).waitFor();
    await reused.locator('.row', { hasText: 'Spotify' }).waitFor();
    await health.locator('.report', { hasText: 'Unencrypted websites' }).locator('.row', { hasText: 'Home Router' }).waitFor();
    await reused.locator('.row', { hasText: 'Netflix' }).click();
    await page.locator('.detail-title', { hasText: 'Netflix' }).waitFor();
    assert.equal(await health.count(), 0);
  });

  await step('checks for breached passwords without sending any password', async () => {
    // The real service is replaced with a stand-in that knows one breached password.
    const { createHash } = await import('node:crypto');
    const hash = createHash('sha1').update('admin123').digest('hex').toUpperCase();
    const requested = [];
    const endpoint = 'https://api.pwnedpasswords.com/range/*';
    await page.route(endpoint, (route) => {
      const url = route.request().url();
      requested.push(url);
      const body = url.endsWith(hash.slice(0, 5)) ? `${hash.slice(5)}:4242\r\n` : '00000000000000000000000000000000000:7\r\n';
      return route.fulfill({ status: 200, contentType: 'text/plain', headers: { 'Access-Control-Allow-Origin': '*' }, body });
    });

    await page.getByRole('button', { name: 'Vault health' }).click();
    const health = page.getByRole('dialog', { name: 'Vault health' });
    await health.getByRole('button', { name: 'Check now' }).click();
    const breached = health.locator('.report', { hasText: '1 breached password' });
    await breached.locator('.row', { hasText: 'Home Router' }).waitFor();
    assert.match(await breached.textContent(), /Seen 4,242×/);

    assert.ok(requested.length >= 20, 'one lookup per distinct password');
    for (const url of requested) assert.match(url, /^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/, 'only a 5-character hash prefix may be sent');
    await page.keyboard.press('Escape');

    // If the service cannot be reached, say so rather than reporting "all clear".
    await page.unroute(endpoint);
    await page.route(endpoint, (route) => route.abort());
    await page.getByRole('button', { name: 'Vault health' }).click();
    await health.getByRole('button', { name: 'Check now' }).click();
    await health.getByText('could not be reached').waitFor();
    assert.equal(await health.locator('.all-clear', { hasText: 'No breached passwords' }).count(), 0);
    await page.keyboard.press('Escape');
    await page.unroute(endpoint);
  });

  await step('keeps a setting changed in one tab when another tab saves a different one', async () => {
    const other = await newPage(context, 'settings tab');
    await other.goto(server.url);
    await unlock(other);
    await other.locator('.shell').waitFor();

    // Tighten security in the first tab...
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByLabel('Clear clipboard').selectOption({ label: 'After 10 seconds' });
    await page.keyboard.press('Escape');

    // ...then do something in the other tab that saves an unrelated preference.
    await other.getByRole('button', { name: 'Generator' }).click();
    await other.getByRole('dialog', { name: 'Generator' }).getByRole('button', { name: 'Generate another' }).click();
    await other.keyboard.press('Escape');

    const stored = await page.evaluate(() => JSON.parse(localStorage.getItem('vault.prefs.v1')));
    assert.equal(stored.clipboardClearSeconds, 10, 'the other tab must not write its stale copy back');
    assert.ok(stored.generator, 'and its own change is saved too');
    await other.getByRole('button', { name: 'Settings' }).click();
    assert.equal(await other.getByLabel('Clear clipboard').inputValue(), '10', 'the other tab sees the new value');
    await other.close();

    await page.getByRole('button', { name: 'Settings' }).click();
    await settings.getByLabel('Clear clipboard').selectOption({ label: 'After 30 seconds' });
    await page.keyboard.press('Escape');
  });

  await step('switches theme and remembers settings', async () => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Dark' }).click();
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'dark');
    await settings.getByRole('button', { name: 'Light' }).click();
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'light');
    await settings.getByLabel('Lock automatically').selectOption({ label: 'After 5 minutes' });
    await page.keyboard.press('Escape');
    await page.reload();
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'light');
    await unlock(page);
    await page.locator('.shell').waitFor();
    await page.getByRole('button', { name: 'Settings' }).click();
    assert.equal(await page.getByLabel('Lock automatically').inputValue(), '5');
    await page.keyboard.press('Escape');
  });

  await step('generates passwords and passphrases to order', async () => {
    await page.getByRole('button', { name: 'Generator' }).click();
    const dialog = page.getByRole('dialog', { name: 'Generator' });
    const value = async () => (await dialog.locator('.gen-value').textContent()).trim();
    await dialog.getByRole('spinbutton', { name: 'Length' }).fill('32');
    assert.equal((await value()).length, 32);
    await dialog.getByLabel('Symbols').uncheck({ force: true });
    await dialog.getByLabel('Numbers').uncheck({ force: true });
    assert.match(await value(), /^[A-Za-z]{32}$/);
    await dialog.getByLabel('Uppercase').uncheck({ force: true });
    await dialog.getByLabel('Lowercase').click({ force: true }); // the last one refuses to switch off
    assert.match(await value(), /^[a-z]{32}$/, 'one character set always stays on');
    assert.equal(await dialog.getByLabel('Lowercase').isChecked(), true);

    await dialog.getByRole('button', { name: 'Passphrase' }).click();
    assert.match(await value(), /^[a-z-]+(-[a-z-]+){4}$/);
    await dialog.getByLabel('Capitalize words').check({ force: true });
    await dialog.getByLabel('Word separator').fill('.');
    assert.match(await value(), /^[A-Z][a-z-]*(\.[A-Z][a-z-]*){4}$/);
    const phrase = await value();
    await dialog.getByRole('button', { name: 'Copy and close' }).click();
    assert.equal(await clipboard(page), phrase);

    // Choices are remembered for next time.
    await page.getByRole('button', { name: 'Generator' }).click();
    assert.equal(await dialog.getByRole('button', { name: 'Passphrase' }).getAttribute('aria-pressed'), 'true');
    await dialog.getByRole('button', { name: 'Password', exact: true }).click();
    await dialog.getByLabel('Symbols').check({ force: true });
    await dialog.getByLabel('Numbers').check({ force: true });
    await dialog.getByLabel('Uppercase').check({ force: true });
    await dialog.getByRole('button', { name: 'Close' }).last().click();
  });

  await step('changes the master password', async () => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Account' }).click();
    await settings.getByLabel('Current master password').fill('not-the-current-one');
    await settings.getByLabel('New master password', { exact: true }).fill(NEW_MASTER);
    await settings.getByLabel('Confirm new master password').fill(NEW_MASTER);
    await settings.getByRole('button', { name: 'Change master password' }).click();
    await settings.locator('.auth-error', { hasText: 'not correct' }).waitFor();
    assert.equal(await page.locator('.shell').count(), 1, 'a wrong current password must not lock the vault');

    await settings.getByLabel('Current master password').fill(MASTER);
    await settings.getByRole('button', { name: 'Change master password' }).click();
    await sawToast(page, 'Master password changed');
    await page.keyboard.press('Escape');

    // Still signed in and able to save.
    await addLogin(page, { name: 'After the change', username: 'me', password: 'Still-Works-12345!' });
    await page.getByRole('button', { name: 'Lock vault' }).click();
    await unlock(page, MASTER);
    await page.locator('.auth-error', { hasText: 'Incorrect email or master password' }).waitFor();
    await page.getByLabel('Master password').fill(NEW_MASTER);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.locator('.shell').waitFor();
    await row(page, 'After the change').waitFor();
    await row(page, 'GitHub').first().waitFor();
  });

  await step('signs out when the master password is changed on another device', async () => {
    const elsewhere = await newPage(context, 'elsewhere');
    await elsewhere.goto(server.url);
    await unlock(elsewhere, NEW_MASTER);
    await elsewhere.locator('.shell').waitFor();
    await elsewhere.getByRole('button', { name: 'Settings' }).click();
    const settings = elsewhere.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Account' }).click();
    await settings.getByLabel('Current master password').fill(NEW_MASTER);
    await settings.getByLabel('New master password', { exact: true }).fill(MASTER);
    await settings.getByLabel('Confirm new master password').fill(MASTER);
    await settings.getByRole('button', { name: 'Change master password' }).click();
    await sawToast(elsewhere, 'Master password changed');
    await elsewhere.close();

    // The first tab finds out the next time it talks to the server.
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor({ timeout: 10_000 });
    await page.locator('.auth-notice', { hasText: 'session ended' }).waitFor();
    await unlock(page, MASTER);
    await page.locator('.shell').waitFor();
  });

  console.log('\nPhone layout');

  await step('works on a phone-sized screen', async () => {
    const phone = await browser.newContext({ ...devices['iPhone 13'] });
    const mobile = await newPage(phone, 'phone');
    currentPage = mobile;
    await mobile.goto(server.url);
    await unlock(mobile);
    await mobile.locator('.shell').waitFor();
    assert.equal(await mobile.locator('.sidebar').evaluate((el) => el.getBoundingClientRect().right <= 0), true, 'the sidebar starts off-screen');

    await row(mobile, 'GitHub').first().click();
    await mobile.locator('.detail-title', { hasText: 'GitHub' }).waitFor();
    assert.equal(await mobile.locator('.detail-pane').isVisible(), true);
    await mobile.getByRole('button', { name: 'Back' }).click();
    assert.equal(await mobile.locator('.detail-pane').isVisible(), false);

    // The browser's own Back button returns to the list too, instead of leaving the app.
    await row(mobile, 'GitHub').first().click();
    await mobile.locator('.detail-title', { hasText: 'GitHub' }).waitFor();
    await mobile.goBack();
    await mobile.locator('.detail-pane').waitFor({ state: 'hidden' });
    assert.equal(await mobile.locator('.shell').count(), 1, 'still unlocked and on the same page');

    // Back from an open editor closes the editor first, then the item.
    await row(mobile, 'GitHub').first().click();
    await mobile.getByRole('button', { name: 'Edit' }).click();
    await mobile.getByLabel('Name', { exact: true }).waitFor();
    await mobile.goBack();
    await mobile.locator('.detail-title', { hasText: 'GitHub' }).waitFor();
    await mobile.goBack();
    await mobile.locator('.detail-pane').waitFor({ state: 'hidden' });
    assert.equal(await mobile.locator('.shell').count(), 1);

    await mobile.getByRole('button', { name: 'Open menu' }).click();
    await navItem(mobile, 'Cards').click();
    assert.equal(await mobile.locator('.list-title').textContent(), 'Cards');
    assert.equal(await mobile.locator('.shell.is-nav-open').count(), 0, 'choosing a section closes the menu');

    const overflow = await mobile.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.equal(overflow, 0, 'no horizontal scrolling');
    await phone.close();
    currentPage = page;
  });

  console.log('\nAccount');

  await step('deletes the account', async () => {
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('button', { name: 'Account' }).click();
    await settings.getByRole('button', { name: 'Delete my account…' }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete your account?' });
    await confirm.getByLabel('Master password').fill('wrong-password-here');
    await confirm.getByRole('button', { name: 'Delete everything' }).click();
    await confirm.locator('.auth-error', { hasText: 'not correct' }).waitFor();
    await confirm.getByLabel('Master password').fill(MASTER);
    await confirm.getByRole('button', { name: 'Delete everything' }).click();
    await page.locator('.auth-notice', { hasText: 'has been deleted' }).waitFor();
    assert.equal(await page.locator('dialog[open]').count(), 0);
    // With no accounts left, the server offers sign-up again.
    await page.getByRole('heading', { name: 'Create your vault' }).waitFor();
  });

  await step('raised no console errors or security-policy violations', async () => {
    // Rejected sign-ins legitimately log a 401 and the deliberate edit conflict a
    // 409; the simulated outages (the breach service, and going offline) log
    // failed requests. Nothing else may appear.
    const expected = /Failed to load resource: (the server responded with a status of (401|409|429)|net::ERR_FAILED|net::ERR_INTERNET_DISCONNECTED)/;
    const unexpected = problems.filter((problem) => !expected.test(problem));
    assert.deepEqual(unexpected, []);
  });

  await browser.close();
  await server.close();

  const failed = results.filter((result) => !result.ok);
  console.log(`\n${results.length - failed.length} passed, ${failed.length} failed\n`);
  if (failed.length) process.exit(1); // screenshots of the failures stay in test/e2e/output
  await rm(outputDir, { recursive: true, force: true });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
