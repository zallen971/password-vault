// The form for creating and editing items.

import { h, icon, iconButton, mount } from '../ui/dom.js';
import { PRIVATE_INPUT, busy, secretInput, select, strengthMeter, toggle } from '../ui/controls.js';
import { openMenu } from '../ui/menu.js';
import { CARD_FIELDS, IDENTITY_FIELDS, TYPE_INFO, detectCardBrand, hostOf } from '../lib/model.js';
import { parseTotp } from '../lib/totp.js';
import { openGenerator } from './generator.js';

const NEW_FOLDER = '__new__';
let uid = 0;
const nextId = (prefix) => `${prefix}-${(uid += 1)}`;

/**
 * @param {object} options
 * @param {object} options.item       a private copy; it is edited in place
 * @param {boolean} options.isNew
 * @param {import('../lib/vault.js').Vault} options.vault
 * @param {() => void} options.onDirty
 * @param {(item: object) => Promise<void>} options.onSave   rejects if the save failed
 * @param {() => void} options.onCancel
 * @param {() => Promise<object|null>} options.createFolder
 * @param {(text: string, label: string) => void} options.copy
 * @returns {{el: HTMLElement, focus: () => void}}
 */
export function itemEditor({ item, isNew, vault, onDirty, onSave, onCancel, createFolder, copy }) {
  const type = TYPE_INFO[item.type];
  const dirty = () => onDirty();

  /** A plain text input bound to `target[key]`. */
  function textInput(target, key, props = {}) {
    const input = h('input.input', {
      ...PRIVATE_INPUT,
      type: 'text',
      value: target[key] ?? '',
      ...props,
      oninput: () => {
        target[key] = input.value;
        dirty();
        props.oninput?.(input.value);
      },
    });
    return input;
  }

  /** A labelled control inside the form grid. */
  function cell(label, control, { wide = false, id, hint } = {}) {
    return h('div', { class: wide ? 'span-2' : '' }, h('label.label', { for: id }, label), control, hint ?? null);
  }

  // ---- Name, folder, favorite ----

  const nameId = nextId('name');
  const nameInput = textInput(item, 'name', {
    id: nameId,
    class: 'input-lg',
    placeholder: item.type === 'login' ? 'e.g. GitHub' : `Name this ${type.label.toLowerCase()}`,
    maxLength: 200,
    autocomplete: 'off',
  });
  const nameError = h('p.field-error', { hidden: true }, 'Give this item a name.');

  const folderId = nextId('folder');
  const folderSelect = h('select.select', {
    id: folderId,
    onchange: async () => {
      if (folderSelect.value !== NEW_FOLDER) {
        item.folderId = folderSelect.value || null;
        dirty();
        return;
      }
      const folder = await createFolder();
      if (folder) {
        item.folderId = folder.id;
        dirty();
      }
      fillFolders();
    },
  });
  function fillFolders() {
    mount(
      folderSelect,
      h('option', { value: '' }, 'No folder'),
      vault.folders.map((folder) => h('option', { value: folder.id }, folder.name)),
      h('option', { value: NEW_FOLDER }, 'New folder…'),
    );
    folderSelect.value = item.folderId && vault.folder(item.folderId) ? item.folderId : '';
  }
  fillFolders();

  const favorite = toggle({
    checked: item.favorite,
    label: 'Favorite',
    onchange: (on) => {
      item.favorite = on;
      dirty();
    },
  });

  const general = h(
    'section.card.form-card',
    h('div', h('label.label', { for: nameId }, 'Name'), nameInput, nameError),
    h(
      'div.form-grid',
      cell('Folder', folderSelect, { id: folderId }),
      h('div', h('span.label', 'Favorite'), h('div.inline-row', { style: { height: '38px' } }, favorite.el, h('span.muted', 'Keep at hand in Favorites'))),
    ),
  );

  // ---- Type-specific sections ----

  const sections = [];

  if (item.type === 'login') {
    const { login } = item;
    const usernameId = nextId('username');
    const passwordId = nextId('password');
    const totpId = nextId('totp');

    const meter = strengthMeter();
    const password = secretInput({
      id: passwordId,
      value: login.password,
      oninput: (value) => {
        login.password = value;
        meter.update(value);
        dirty();
      },
      buttons: [
        iconButton('dice', 'Generate a password', {
          onclick: () =>
            openGenerator({
              copy,
              onUse: (generated) => {
                password.setValue(generated);
                password.reveal(true);
              },
            }),
        }),
      ],
    });
    meter.update(login.password);

    const totpHint = h('p.hint');
    const describeTotp = (value) => {
      const invalid = value.trim() && !parseTotp(value);
      totpHint.textContent = invalid
        ? 'That does not look like a valid key. Paste the secret key or otpauth:// link the site gave you.'
        : 'Optional. Paste the setup key a site shows when you turn on two-step login, and Vault will generate the codes.';
      totpHint.classList.toggle('field-error', Boolean(invalid));
      totpHint.classList.toggle('hint', !invalid);
    };
    const totp = secretInput({
      id: totpId,
      value: login.totp,
      placeholder: 'Secret key or otpauth:// link',
      oninput: (value) => {
        login.totp = value;
        describeTotp(value);
        dirty();
      },
    });
    describeTotp(login.totp);

    sections.push(
      h('h3.section-title', 'Sign-in details'),
      h(
        'section.card.form-card',
        h('div', h('label.label', { for: usernameId }, 'Username or email'), textInput(login, 'username', { id: usernameId, inputMode: 'email' })),
        h('div', h('label.label', { for: passwordId }, 'Password'), password.el, meter.el),
        h('div', h('label.label', { for: totpId }, 'Authenticator key'), totp.el, totpHint),
      ),
    );

    // Websites: a growable list of addresses.
    const uriList = h('div.stack');
    function renderUris() {
      mount(
        uriList,
        login.uris.map((uri, index) => {
          const input = h('input.input', {
            ...PRIVATE_INPUT,
            type: 'url',
            inputMode: 'url',
            value: uri,
            placeholder: 'https://example.com',
            'aria-label': `Website ${index + 1}`,
            oninput: () => {
              login.uris[index] = input.value;
              dirty();
            },
          });
          return h(
            'div.inline-row',
            h('div.grow', input),
            iconButton('x', 'Remove website', {
              onclick: () => {
                login.uris.splice(index, 1);
                dirty();
                renderUris();
              },
            }),
          );
        }),
      );
    }
    renderUris();
    sections.push(
      h('h3.section-title', 'Websites'),
      h(
        'section.card.form-card',
        uriList,
        h(
          'button.btn.btn-ghost.btn-sm.add-btn',
          {
            type: 'button',
            onclick: () => {
              login.uris.push('');
              renderUris();
              uriList.lastElementChild?.querySelector('input')?.focus();
            },
          },
          icon('plus', 15),
          'Add website',
        ),
      ),
    );
  }

  if (item.type === 'card' || item.type === 'identity') {
    const target = item.type === 'card' ? item.card : item.identity;
    const fields = item.type === 'card' ? CARD_FIELDS : IDENTITY_FIELDS;
    const controls = {};

    const grid = h(
      'div.form-grid',
      fields.map((field) => {
        const id = nextId(field.key);
        let control;
        if (field.options) {
          control = select({
            id,
            value: target[field.key],
            options: [['', '—'], ...field.options.map((option) => [option, option])],
            onchange: (value) => {
              target[field.key] = value;
              dirty();
            },
          });
          controls[field.key] = control;
        } else if (field.secret) {
          const secret = secretInput({
            id,
            value: target[field.key],
            inputMode: field.inputMode,
            placeholder: field.placeholder ?? '',
            oninput: (value) => {
              target[field.key] = value;
              dirty();
              // Fill in the card network from the number, unless one was picked by hand.
              if (item.type === 'card' && field.key === 'number' && !brandChosen) {
                const brand = detectCardBrand(value);
                target.brand = brand;
                controls.brand.value = brand;
              }
            },
          });
          control = secret.el;
        } else {
          control = textInput(target, field.key, { id, inputMode: field.inputMode, placeholder: field.placeholder ?? '', class: field.mono ? 'mono' : '' });
        }
        return cell(field.label, control, { id, wide: !field.half });
      }),
    );
    let brandChosen = item.type === 'card' && Boolean(target.brand);
    controls.brand?.addEventListener('change', () => (brandChosen = Boolean(controls.brand.value)));

    sections.push(h('h3.section-title', item.type === 'card' ? 'Card details' : 'Personal details'), h('section.card.form-card', grid));
  }

  // ---- Notes ----

  const notesId = nextId('notes');
  const notes = h('textarea.textarea', {
    ...PRIVATE_INPUT,
    id: notesId,
    value: item.notes,
    rows: item.type === 'note' ? 10 : 4,
    placeholder: item.type === 'note' ? 'Write your note…' : 'Anything worth remembering: recovery codes, security answers, account numbers…',
    oninput: () => {
      item.notes = notes.value;
      dirty();
    },
  });
  sections.push(h('h3.section-title', item.type === 'note' ? 'Note' : 'Notes'), h('section.card.form-card', h('div', h('label.label.sr-only', { for: notesId }, 'Notes'), notes)));

  // ---- Custom fields ----

  const fieldList = h('div.stack');
  function renderFields() {
    mount(
      fieldList,
      item.fields.map((field, index) => {
        const name = textInput(field, 'name', { placeholder: 'Field name', 'aria-label': 'Field name', maxLength: 100 });
        let value;
        if (field.type === 'boolean') {
          const box = h('input', {
            type: 'checkbox',
            id: nextId('check'),
            checked: field.value === 'true',
            onchange: () => {
              field.value = String(box.checked);
              dirty();
            },
          });
          value = h('label.check-cell', box, 'Checked');
        } else if (field.type === 'hidden') {
          value = secretInput({
            value: field.value,
            placeholder: 'Hidden value',
            oninput: (text) => {
              field.value = text;
              dirty();
            },
          }).el;
        } else {
          value = textInput(field, 'value', { placeholder: 'Value', 'aria-label': 'Field value' });
        }
        return h(
          'div.custom-field',
          name,
          value,
          iconButton('x', 'Remove field', {
            onclick: () => {
              item.fields.splice(index, 1);
              dirty();
              renderFields();
            },
          }),
        );
      }),
    );
  }
  renderFields();

  const addField = h('button.btn.btn-ghost.btn-sm.add-btn', { type: 'button', 'aria-haspopup': 'menu' }, icon('plus', 15), 'Add field');
  addField.addEventListener('click', () => {
    const add = (kind) => {
      item.fields.push({ name: '', value: kind === 'boolean' ? 'false' : '', type: kind });
      dirty();
      renderFields();
      fieldList.lastElementChild?.querySelector('input')?.focus();
    };
    openMenu(addField, [
      { label: 'Text', icon: 'edit', onSelect: () => add('text') },
      { label: 'Hidden (masked)', icon: 'eye-off', onSelect: () => add('hidden') },
      { label: 'Checkbox', icon: 'check', onSelect: () => add('boolean') },
    ]);
  });
  sections.push(h('h3.section-title', 'Custom fields'), h('section.card.form-card', fieldList, addField));

  // ---- Form ----

  const saveButton = h('button.btn.btn-primary.btn-sm', { type: 'submit' }, 'Save');

  async function onSubmit(event) {
    event.preventDefault();
    if (saveButton.disabled) return;
    // A login can borrow its name from its first website.
    if (!item.name.trim() && item.type === 'login') {
      const firstUri = item.login.uris.find((uri) => uri.trim());
      if (firstUri) {
        item.name = hostOf(firstUri);
        nameInput.value = item.name;
      }
    }
    if (!item.name.trim()) {
      nameError.hidden = false;
      nameInput.setAttribute('aria-invalid', 'true');
      nameInput.focus();
      return;
    }
    const restore = busy(saveButton, 'Saving…');
    try {
      await onSave(item);
    } catch {
      restore(); // the caller has already explained what went wrong
    }
  }

  nameInput.addEventListener('input', () => {
    nameError.hidden = true;
    nameInput.removeAttribute('aria-invalid');
  });

  const el = h(
    'form.detail',
    { onsubmit: onSubmit, novalidate: true, autocomplete: 'off' },
    h(
      'header.editor-head',
      h('h2.truncate', isNew ? `New ${type.label.toLowerCase()}` : `Edit ${type.label.toLowerCase()}`),
      h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: onCancel }, 'Cancel'),
      saveButton,
    ),
    general,
    sections,
  );

  // Escape cancels, as long as it was not meant for a field or menu.
  el.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !event.defaultPrevented && !document.querySelector('.menu:popover-open')) {
      event.preventDefault();
      onCancel();
    }
  });

  return {
    el,
    focus: () => {
      if (isNew && matchMedia('(pointer: fine)').matches) nameInput.focus({ preventScroll: true });
    },
  };
}
