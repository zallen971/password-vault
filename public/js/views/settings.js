// Settings dialog: preferences, import, export, account and about.

import { h, icon, mount } from '../ui/dom.js';
import { confirmDialog, openDialog } from '../ui/dialog.js';
import { busy, passwordInput, select, strengthMeter, toggle } from '../ui/controls.js';
import { toast } from '../ui/toast.js';
import { describeError } from '../ui/errors.js';
import { prefs } from '../lib/prefs.js';
import { DEFAULT_KDF } from '../lib/crypto.js';
import { ImportError, parseImport } from '../lib/importers.js';
import { openEncryptedBackup, toBitwardenCsv, toBitwardenJson, toEncryptedBackup } from '../lib/exporters.js';
import { WEAK_MASTER_PASSWORD_WARNING, isWeakMasterPassword, masterPasswordProblem } from '../lib/policy.js';
import { TYPE_INFO } from '../lib/model.js';
import { downloadFile, plural } from './shared.js';

const TABS = [
  ['general', 'General', 'settings'],
  ['import', 'Import', 'upload'],
  ['export', 'Export', 'download'],
  ['account', 'Account', 'user'],
  ['about', 'About', 'info'],
];
const MAX_IMPORT_BYTES = 64 * 1024 * 1024;
const MIN_FILE_PASSWORD = 8;

const errorBox = () => h('div.auth-error', { role: 'alert', hidden: true });
function showError(box, message) {
  mount(box, icon('alert', 16), h('span', message));
  box.hidden = false;
}

/** One row of the settings list. `inline` keeps the control beside the text on narrow screens. */
const setting = (title, description, control, inline = false) =>
  h('div.setting', { class: inline ? 'setting-inline' : '' }, h('div.setting-text', h('strong', title), description ? h('small', description) : null), control);

/**
 * @param {object} options
 * @param {import('../lib/vault.js').Vault} options.vault
 * @param {object|null} options.serverInfo
 * @param {string} [options.tab]
 */
export function openSettings({ vault, serverInfo, tab = 'general' }) {
  const pane = h('div.settings-pane.scroll');
  const nav = h(
    'nav.settings-nav',
    { 'aria-label': 'Settings sections' },
    TABS.map(([id, label, iconName]) =>
      h('button.nav-item', { type: 'button', 'data-tab': id, onclick: () => show(id) }, icon(iconName, 16), h('span.nav-label', label)),
    ),
  );

  const panes = { general, import: importPane, export: exportPane, account, about };
  function show(id) {
    for (const button of nav.children) button.setAttribute('aria-current', String(button.dataset.tab === id));
    mount(pane, panes[id]());
    pane.scrollTop = 0;
  }

  // ---- General ----

  function general() {
    const themes = [
      ['system', 'System', 'monitor'],
      ['light', 'Light', 'sun'],
      ['dark', 'Dark', 'moon'],
    ];
    const themeControl = h(
      'div.segmented',
      { role: 'group', 'aria-label': 'Theme' },
      themes.map(([value, label, iconName]) =>
        h(
          'button',
          {
            type: 'button',
            'aria-pressed': String(prefs.get('theme') === value),
            onclick: (event) => {
              prefs.set('theme', value);
              for (const button of themeControl.children) button.setAttribute('aria-pressed', String(button === event.currentTarget));
            },
          },
          icon(iconName, 14),
          label,
        ),
      ),
    );

    return [
      h('h3', 'Appearance'),
      setting('Theme', 'Follow your device, or always use light or dark.', themeControl),
      h('h3', 'Security'),
      setting(
        'Lock automatically',
        'Locks the vault when you have not used it for a while.',
        select({
          label: 'Lock automatically',
          value: prefs.get('autoLockMinutes'),
          options: [[1, 'After 1 minute'], [5, 'After 5 minutes'], [15, 'After 15 minutes'], [30, 'After 30 minutes'], [60, 'After 1 hour'], [240, 'After 4 hours'], [0, 'Never']],
          onchange: (value) => prefs.set('autoLockMinutes', Number(value)),
        }),
      ),
      setting(
        'Clear clipboard',
        'Removes copied passwords from the clipboard after a delay.',
        select({
          label: 'Clear clipboard',
          value: prefs.get('clipboardClearSeconds'),
          options: [[10, 'After 10 seconds'], [30, 'After 30 seconds'], [60, 'After 1 minute'], [120, 'After 2 minutes'], [300, 'After 5 minutes'], [0, 'Never']],
          onchange: (value) => prefs.set('clipboardClearSeconds', Number(value)),
        }),
      ),
      setting(
        'Remember my email',
        'Fills in your email on the unlock screen. Your master password is never stored.',
        toggle({
          checked: prefs.get('rememberEmail'),
          label: 'Remember my email',
          onchange: (on) => {
            prefs.set('rememberEmail', on);
            prefs.set('email', on ? vault.email : '');
          },
        }).el,
        true,
      ),
      h('p', 'These settings are saved in this browser only.'),
    ];
  }

  // ---- Import ----

  function importPane() {
    const area = h('div.pane-stack');
    const stage = (...content) => {
      mount(area, content);
      return area;
    };

    function intro(message) {
      const error = errorBox();
      if (message) showError(error, message);
      const picker = h('input', { type: 'file', accept: '.json,.csv,application/json,text/csv,text/plain', hidden: true });
      picker.addEventListener('change', () => picker.files[0] && readFile(picker.files[0]));
      const zone = h(
        'div.dropzone',
        icon('upload', 24),
        h('strong', 'Drop your export file here'),
        h('span', 'Bitwarden .json or .csv, a browser or password manager CSV, or a Vault backup'),
        h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: () => picker.click() }, 'Choose file'),
        picker,
      );
      zone.addEventListener('dragover', (event) => {
        event.preventDefault();
        zone.classList.add('is-over');
      });
      zone.addEventListener('dragleave', () => zone.classList.remove('is-over'));
      zone.addEventListener('drop', (event) => {
        event.preventDefault();
        zone.classList.remove('is-over');
        const [file] = event.dataTransfer.files;
        if (file) readFile(file);
      });
      return stage(
        h('p', 'Move your passwords in from Bitwarden, your browser or another password manager. Everything is encrypted on this device before it is saved.'),
        error,
        zone,
        h('h3', 'Coming from Bitwarden?'),
        h(
          'ol.steps',
          h('li', 'In Bitwarden, open ', h('strong', 'Tools → Export vault'), ' (or ', h('strong', 'File → Export vault'), ' in the desktop app).'),
          h('li', 'Choose the file format ', h('strong', '.json'), ' and export. The encrypted formats can only be read by Bitwarden.'),
          h('li', 'Drop the file above. Logins, notes, cards, identities, folders and favorites all come across.'),
          h('li', 'Delete the export file afterwards. It contains your passwords unprotected.'),
        ),
      );
    }

    async function readFile(file) {
      if (file.size > MAX_IMPORT_BYTES) {
        intro('That file is too large to be a password export.');
        return;
      }
      try {
        handleParsed(parseImport(await file.text()), file.name);
      } catch (error) {
        intro(error instanceof ImportError ? error.message : 'That file could not be read.');
      }
    }

    function handleParsed(parsed, fileName, fromBackup = false) {
      if (parsed.encrypted) unlockBackup(parsed.envelope, fileName);
      else preview(parsed, fileName, fromBackup);
    }

    function unlockBackup(envelope, fileName) {
      const error = errorBox();
      const password = passwordInput({ id: 'backup-password', autocomplete: 'off', autofocus: true });
      const submit = h('button.btn.btn-primary', { type: 'submit' }, 'Open backup');
      stage(
        h('p', h('strong', fileName), ' is an encrypted Vault backup. Enter the password it was exported with.'),
        h(
          'form',
          {
            class: 'stack',
            style: { gap: '14px' },
            onsubmit: async (event) => {
              event.preventDefault();
              error.hidden = true;
              const restore = busy(submit, 'Opening…');
              try {
                handleParsed(parseImport(await openEncryptedBackup(envelope, password.input.value)), fileName, true);
              } catch (failure) {
                restore();
                showError(error, failure instanceof ImportError ? failure.message : 'That password is not correct, or the backup file is damaged.');
                password.input.select();
              }
            },
          },
          h('div', h('label.label', { for: 'backup-password' }, 'Backup password'), password.el),
          error,
          h('div.inline-row', submit, h('button.btn.btn-ghost', { type: 'button', onclick: () => intro() }, 'Choose another file')),
        ),
      );
      password.input.focus();
    }

    function preview(parsed, fileName, fromBackup) {
      const counts = {};
      const folders = new Set();
      for (const item of parsed.items) {
        counts[item.type] = (counts[item.type] ?? 0) + 1;
        if (item.folderName) folders.add(item.folderName.toLowerCase());
      }
      const skip = h('input', { type: 'checkbox', id: 'import-skip', checked: true });
      const error = errorBox();
      const submit = h('button.btn.btn-primary', { type: 'button' }, `Import ${plural(parsed.items.length, 'item')}`);
      submit.addEventListener('click', async () => {
        error.hidden = true;
        const restore = busy(submit, 'Encrypting and saving…');
        try {
          finished(await vault.importItems(parsed.items, { skipDuplicates: skip.checked }), fromBackup);
        } catch (failure) {
          restore();
          showError(error, describeError(failure));
        }
      });

      stage(
        h('p', 'Ready to import from ', h('strong', fileName), '.'),
        h(
          'ul.summary-list',
          h('li', h('span', 'Format'), h('span', parsed.label)),
          Object.keys(TYPE_INFO)
            .filter((type) => counts[type])
            .map((type) => h('li', h('span', TYPE_INFO[type].plural), h('span', counts[type].toLocaleString()))),
          folders.size ? h('li', h('span', 'Folders'), h('span', folders.size.toLocaleString())) : null,
        ),
        parsed.warnings.map((warning) => h('div.callout.callout-warning', icon('alert', 16), h('span', warning))),
        h('label.inline-row', { for: 'import-skip', style: { cursor: 'pointer' } }, skip, h('span', 'Skip items that are already in my vault')),
        error,
        h('div.inline-row', submit, h('button.btn.btn-ghost', { type: 'button', onclick: () => intro() }, 'Choose another file')),
      );
    }

    function finished(result, fromBackup) {
      const skipped = result.skipped ? ` ${plural(result.skipped, 'duplicate')} skipped.` : '';
      stage(
        h(
          'div.all-clear',
          icon('check', 20),
          h('span', h('strong', result.added ? `${plural(result.added, 'item')} imported. ` : 'Nothing new to import. '), skipped.trim()),
        ),
        fromBackup
          ? null
          : h(
              'div.callout.callout-warning',
              icon('alert', 16),
              h('span', h('strong', 'Delete the export file now. '), 'It holds your passwords in plain text. Remove it from your downloads folder and empty the bin.'),
            ),
        h(
          'div.inline-row',
          h('button.btn.btn-primary', { type: 'button', onclick: () => dialog.close() }, 'Done'),
          h('button.btn.btn-ghost', { type: 'button', onclick: () => intro() }, 'Import another file'),
        ),
      );
    }

    return intro();
  }

  // ---- Export ----

  function exportPane() {
    let format = 'backup';
    const formats = [
      ['backup', 'Encrypted backup', 'Recommended. Protected by a password you choose, and can be restored into Vault.'],
      ['json', 'Bitwarden JSON', 'Not encrypted. Opens in Bitwarden and most other password managers.'],
      ['csv', 'CSV', 'Not encrypted. Logins and notes only, for spreadsheets and simple imports.'],
    ];

    const error = errorBox();
    const details = h('div');
    const meter = strengthMeter();
    const filePassword = passwordInput({ id: 'export-file-password', autocomplete: 'new-password', oninput: (value) => meter.update(value) });
    const fileConfirm = passwordInput({ id: 'export-file-confirm', autocomplete: 'new-password' });
    const master = passwordInput({ id: 'export-master', autocomplete: 'current-password' });
    const submit = h('button.btn.btn-primary', { type: 'submit' }, icon('download', 16), 'Export vault');

    function renderDetails() {
      mount(
        details,
        format === 'backup'
          ? h(
              'div.form-grid',
              h('div', h('label.label', { for: 'export-file-password' }, 'Backup password'), filePassword.el, meter.el),
              h('div', h('label.label', { for: 'export-file-confirm' }, 'Confirm backup password'), fileConfirm.el),
              h('p.hint.span-2', { style: { marginTop: '-4px' } }, 'You will need this password to restore the backup. It can be different from your master password, and it cannot be recovered.'),
            )
          : h(
              'div.callout.callout-danger',
              icon('alert', 16),
              h('span', h('strong', 'This file will not be encrypted. '), 'Anyone who opens it can read every password in it. Keep it somewhere safe and delete it as soon as you are done.'),
            ),
      );
    }
    renderDetails();

    async function onSubmit(event) {
      event.preventDefault();
      error.hidden = true;
      if (format === 'backup') {
        if ([...filePassword.input.value].length < MIN_FILE_PASSWORD) {
          showError(error, `Choose a backup password of at least ${MIN_FILE_PASSWORD} characters.`);
          filePassword.input.focus();
          return;
        }
        if (filePassword.input.value !== fileConfirm.input.value) {
          showError(error, 'The two backup passwords do not match.');
          fileConfirm.input.focus();
          return;
        }
      }
      const restore = busy(submit, 'Preparing…');
      try {
        if (!(await vault.verifyPassword(master.input.value))) {
          showError(error, 'That master password is not correct.');
          master.input.select();
          return;
        }
        const { items, folders } = vault;
        const stamp = new Date().toISOString().slice(0, 10);
        if (format === 'backup') {
          const backup = await toEncryptedBackup(items, folders, filePassword.input.value, DEFAULT_KDF);
          downloadFile(`vault-backup-${stamp}.json`, JSON.stringify(backup, null, 2), 'application/json');
        } else if (format === 'json') {
          downloadFile(`vault-export-${stamp}.json`, JSON.stringify(toBitwardenJson(items, folders), null, 2), 'application/json');
        } else {
          downloadFile(`vault-export-${stamp}.csv`, toBitwardenCsv(items, folders), 'text/csv');
        }
        toast(format === 'backup' ? 'Encrypted backup downloaded' : 'Export downloaded');
        for (const field of [filePassword, fileConfirm, master]) field.input.value = '';
        meter.update('');
      } catch (failure) {
        showError(error, describeError(failure));
      } finally {
        restore();
      }
    }

    return [
      h('p', 'Download a copy of everything in your vault. Items in the trash are left out.'),
      h(
        'form',
        { onsubmit: onSubmit, novalidate: true, class: 'stack', style: { gap: '14px' } },
        h(
          'div',
          { role: 'radiogroup', 'aria-label': 'Export format' },
          formats.map(([value, label, description]) => {
            const radio = h('input', {
              type: 'radio',
              name: 'export-format',
              value,
              checked: value === format,
              onchange: () => {
                format = value;
                error.hidden = true;
                renderDetails();
              },
            });
            return h('label.choice', radio, h('span', h('strong', label), h('small', description)));
          }),
        ),
        details,
        h('div', h('label.label', { for: 'export-master' }, 'Confirm with your master password'), master.el),
        error,
        h('div', submit),
      ),
    ];
  }

  // ---- Account ----

  function account() {
    const error = errorBox();
    const meter = strengthMeter();
    const current = passwordInput({ id: 'pw-current', autocomplete: 'current-password' });
    const next = passwordInput({ id: 'pw-new', autocomplete: 'new-password', oninput: (value) => meter.update(value) });
    const confirm = passwordInput({ id: 'pw-confirm', autocomplete: 'new-password' });
    const submit = h('button.btn.btn-primary', { type: 'submit' }, 'Change master password');

    async function onSubmit(event) {
      event.preventDefault();
      error.hidden = true;
      const problem = masterPasswordProblem(next.input.value, confirm.input.value);
      if (problem) {
        showError(error, problem);
        next.input.focus();
        return;
      }
      if (next.input.value === current.input.value) {
        showError(error, 'The new master password is the same as the current one.');
        next.input.focus();
        return;
      }
      if (isWeakMasterPassword(next.input.value) && !(await confirmDialog(WEAK_MASTER_PASSWORD_WARNING))) {
        next.input.select();
        return;
      }
      const restore = busy(submit, 'Re-encrypting your key…');
      try {
        await vault.changeMasterPassword(current.input.value, next.input.value);
        for (const field of [current, next, confirm]) field.input.value = '';
        meter.update('');
        toast('Master password changed');
      } catch (failure) {
        showError(error, describeError(failure));
        current.input.select();
      } finally {
        restore();
      }
    }

    return [
      h('h3', 'Signed in as'),
      setting(
        vault.email,
        'Your vault locks when you close this tab.',
        h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: () => vault.lock('manual') }, icon('lock', 14), 'Lock now'),
        true,
      ),
      h('h3', 'Change master password'),
      h('p', 'Your items stay as they are; only the key that protects them is re-encrypted. Your other devices will be signed out and will need the new password.'),
      h(
        'form',
        { onsubmit: onSubmit, novalidate: true, class: 'stack', style: { gap: '14px' } },
        h('div', h('label.label', { for: 'pw-current' }, 'Current master password'), current.el),
        h(
          'div.form-grid',
          h('div', h('label.label', { for: 'pw-new' }, 'New master password'), next.el, meter.el),
          h('div', h('label.label', { for: 'pw-confirm' }, 'Confirm new master password'), confirm.el),
        ),
        error,
        h('div', submit),
      ),
      h('h3', 'Delete account'),
      h('p', 'Permanently removes your account and every item in it from this server. This cannot be undone, so export a backup first if you might want anything back.'),
      h('div', h('button.btn.btn-danger-ghost', { type: 'button', onclick: confirmDelete }, icon('trash', 16), 'Delete my account…')),
    ];
  }

  function confirmDelete() {
    const error = errorBox();
    const password = passwordInput({ id: 'delete-password', autocomplete: 'current-password', autofocus: true });
    const submit = h('button.btn.btn-danger', { type: 'submit', form: 'delete-form' }, 'Delete everything');
    const count = vault.items.length;
    const prompt = openDialog({
      title: 'Delete your account?',
      width: 440,
      body: h(
        'form',
        {
          id: 'delete-form',
          class: 'stack',
          style: { gap: '14px' },
          onsubmit: async (event) => {
            event.preventDefault();
            error.hidden = true;
            const restore = busy(submit, 'Deleting…');
            try {
              await vault.deleteAccount(password.input.value); // locks the vault, which closes these dialogs
            } catch (failure) {
              restore();
              showError(error, describeError(failure));
              password.input.select();
            }
          },
        },
        h('p', `This permanently deletes ${vault.email} and ${count ? `all ${plural(count, 'item')}` : 'everything'} in it. There is no way to get it back.`),
        h('div', h('label.label', { for: 'delete-password' }, 'Master password'), password.el),
        error,
      ),
      footer: [h('button.btn.btn-secondary', { type: 'button', onclick: () => prompt.close() }, 'Cancel'), submit],
    });
  }

  // ---- About ----

  function about() {
    return [
      h('div.brand', { style: { marginTop: '4px' } }, h('img', { src: 'icons/logo.svg', alt: '' }), 'Vault'),
      h('p', 'A private password manager you run yourself. Everything is encrypted in your browser before it is sent anywhere, so the server only ever holds data it cannot read.'),
      h(
        'dl.about-list',
        h('div', h('dt', 'Version'), h('dd', serverInfo?.version ?? 'Unknown')),
        h('div', h('dt', 'Encryption'), h('dd', 'AES-256-GCM')),
        h('div', h('dt', 'Key derivation'), h('dd', `PBKDF2-SHA256, ${DEFAULT_KDF.iterations.toLocaleString()} rounds`)),
        h('div', h('dt', 'Master password'), h('dd', 'Never leaves this device')),
        h('div', h('dt', 'Passphrase word list'), h('dd', 'EFF Large Wordlist (CC BY 3.0)')),
      ),
      h('p', 'There is no password reset. Keep an encrypted backup (Settings → Export) somewhere safe in case this server is ever lost.'),
    ];
  }

  const dialog = openDialog({ title: 'Settings', width: 780, flush: true, body: h('div.settings', nav, pane) });
  show(TABS.some(([id]) => id === tab) ? tab : 'general');
  return dialog;
}
