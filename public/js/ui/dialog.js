// Modal dialogs built on the native <dialog> element, which provides focus
// trapping, Escape handling and correct screen-reader semantics.

import { h, iconButton } from './dom.js';

const openDialogs = new Set();

/**
 * @param {object} options
 * @param {string} options.title
 * @param {*} options.body                  node(s) for the scrolling body
 * @param {*} [options.footer]              node(s) for the action bar
 * @param {number} [options.width]          max width in pixels
 * @param {boolean} [options.dismissable]   allow Escape / backdrop / close button
 * @param {boolean} [options.flush]         no padding around the body
 * @returns {{el: HTMLDialogElement, close: (result?: any) => void, result: Promise<any>}}
 */
export function openDialog({ title, body, footer, width, dismissable = true, flush = false }) {
  let settle;
  let outcome;
  const result = new Promise((resolve) => (settle = resolve));
  const close = (value) => {
    outcome = value;
    if (dialog.open) dialog.close();
  };

  const dialog = h(
    'dialog.dialog',
    { 'aria-label': title },
    h(
      'div.dialog-panel',
      { style: width ? { '--dialog-width': `${width}px` } : null },
      h('header.dialog-head', h('h2', title), dismissable ? iconButton('x', 'Close', { onclick: () => close() }) : null),
      h('div.dialog-body.scroll', { style: flush ? { padding: '0' } : null }, body),
      footer ? h('footer.dialog-foot', footer) : null,
    ),
  );

  // Close on a click that both starts and ends on the backdrop, so dragging a
  // text selection out of the panel does not dismiss the dialog.
  let pressedBackdrop = false;
  dialog.addEventListener('pointerdown', (event) => {
    pressedBackdrop = event.target === dialog;
  });
  dialog.addEventListener('click', (event) => {
    if (dismissable && pressedBackdrop && event.target === dialog) close();
  });
  dialog.addEventListener('cancel', (event) => {
    if (!dismissable) event.preventDefault();
  });
  dialog.addEventListener('close', () => {
    openDialogs.delete(handle);
    dialog.remove();
    settle(outcome);
  });

  const handle = { el: dialog, close, result };
  openDialogs.add(handle);
  document.body.append(dialog);
  dialog.showModal();
  return handle;
}

/** Closes every open dialog (used when the vault locks). */
export function closeAllDialogs() {
  for (const dialog of [...openDialogs]) dialog.close();
}

/** @returns {Promise<boolean>} */
export function confirmDialog({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
  const dialog = openDialog({
    title,
    width: 420,
    body: h('p', message),
    footer: [
      h('button.btn.btn-secondary', { type: 'button', autofocus: danger, onclick: () => dialog.close(false) }, cancelLabel),
      h(
        'button.btn',
        { type: 'button', class: danger ? 'btn-danger' : 'btn-primary', autofocus: !danger, onclick: () => dialog.close(true) },
        confirmLabel,
      ),
    ],
  });
  return dialog.result.then(Boolean);
}

/** Asks for one line of text. Resolves to the trimmed text, or null if cancelled. */
export function promptDialog({ title, label, value = '', placeholder = '', confirmLabel = 'Save', maxLength = 120 }) {
  const input = h('input.input', {
    id: 'prompt-input',
    type: 'text',
    value,
    placeholder,
    maxLength,
    autocomplete: 'off',
    autofocus: true,
    oninput: () => (submit.disabled = !input.value.trim()),
  });
  const submit = h('button.btn.btn-primary', { type: 'submit', form: 'prompt-form', disabled: !value.trim() }, confirmLabel);
  const dialog = openDialog({
    title,
    width: 400,
    body: h(
      'form',
      {
        id: 'prompt-form',
        onsubmit: (event) => {
          event.preventDefault();
          if (input.value.trim()) dialog.close(input.value.trim());
        },
      },
      h('label.label', { for: 'prompt-input' }, label),
      input,
    ),
    footer: [h('button.btn.btn-secondary', { type: 'button', onclick: () => dialog.close(null) }, 'Cancel'), submit],
  });
  input.select();
  return dialog.result.then((text) => text ?? null);
}
