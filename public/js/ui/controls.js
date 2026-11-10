// Reusable form controls.

import { h, icon, iconButton } from './dom.js';
import { estimateStrength } from '../lib/strength.js';

// On desktop, secrets are plain text inputs masked with CSS, so the browser's
// own password manager does not try to save or fill vault items. On touch
// devices real password inputs are used instead, so on-screen keyboards do not
// learn or suggest what is typed.
const CSS_MASKING =
  typeof CSS !== 'undefined' && CSS.supports('-webkit-text-security', 'disc') && matchMedia('(pointer: fine)').matches;

/** Attributes that tell browsers and extensions to leave a field alone. */
export const PRIVATE_INPUT = Object.freeze({
  autocomplete: 'off',
  spellcheck: false,
  autocapitalize: 'off',
  autocorrect: 'off',
  'data-lpignore': 'true',
  'data-1p-ignore': 'true',
  'data-bwignore': 'true',
  'data-form-type': 'other',
});

/**
 * A masked input with a show/hide button.
 * @returns {{el: HTMLElement, input: HTMLInputElement, setValue: (v: string) => void, reveal: (on: boolean) => void}}
 */
export function secretInput({ id, value = '', placeholder = '', mono = true, inputMode, oninput, buttons = [] }) {
  let revealed = false;
  const input = h('input.input.secret.is-masked', {
    ...PRIVATE_INPUT,
    id,
    type: CSS_MASKING ? 'text' : 'password',
    class: mono ? 'mono' : '',
    value,
    placeholder,
    inputMode,
    oninput: () => oninput?.(input.value),
  });
  const toggle = iconButton('eye', 'Show', { 'aria-pressed': 'false', onclick: () => reveal(!revealed) });

  function reveal(on) {
    revealed = on;
    input.classList.toggle('is-masked', !on);
    if (!CSS_MASKING) input.type = on ? 'text' : 'password';
    toggle.replaceChildren(icon(on ? 'eye-off' : 'eye', 16));
    toggle.title = on ? 'Hide' : 'Show';
    toggle.setAttribute('aria-label', toggle.title);
    toggle.setAttribute('aria-pressed', String(on));
  }

  const el = h('div.affix', { style: { '--affix': String(buttons.length + 1) } }, input, h('div.affix-buttons', buttons, toggle));
  return {
    el,
    input,
    reveal,
    setValue(next) {
      input.value = next;
      oninput?.(next);
    },
  };
}

/** A real password field (used for master passwords) with a show/hide button. */
export function passwordInput({ id, autocomplete, placeholder = '', large = false, autofocus = false, oninput }) {
  let revealed = false;
  const input = h('input.input', {
    id,
    type: 'password',
    class: large ? 'input-lg' : '',
    autocomplete,
    placeholder,
    autofocus,
    required: true,
    spellcheck: false,
    autocapitalize: 'off',
    autocorrect: 'off',
    oninput: () => oninput?.(input.value),
  });
  const toggle = iconButton('eye', 'Show password', {
    'aria-pressed': 'false',
    onclick: () => {
      revealed = !revealed;
      input.type = revealed ? 'text' : 'password';
      toggle.replaceChildren(icon(revealed ? 'eye-off' : 'eye', 16));
      toggle.title = revealed ? 'Hide password' : 'Show password';
      toggle.setAttribute('aria-label', toggle.title);
      toggle.setAttribute('aria-pressed', String(revealed));
    },
  });
  return { el: h('div.affix', input, h('div.affix-buttons', toggle)), input };
}

/** Four-segment strength bar. Call update() with a password, or with a ready-made result. */
export function strengthMeter() {
  const label = h('span');
  const el = h(
    'div.meter',
    { 'data-empty': '', role: 'status', 'aria-live': 'polite' },
    h('div.meter-bars', { 'aria-hidden': 'true' }, h('i'), h('i'), h('i'), h('i')),
    h('span.meter-label', h('span.sr-only', 'Password strength: '), label),
  );
  return {
    el,
    update(input) {
      const result = typeof input === 'string' ? (input ? estimateStrength(input) : null) : input;
      if (!result) {
        el.setAttribute('data-empty', '');
        el.removeAttribute('data-score');
        label.textContent = '';
        return null;
      }
      el.removeAttribute('data-empty');
      el.setAttribute('data-score', String(result.score));
      label.textContent = result.label;
      return result;
    },
  };
}

/** An on/off switch. */
export function toggle({ checked = false, label, onchange }) {
  const input = h('input', { type: 'checkbox', checked, 'aria-label': label, onchange: () => onchange?.(input.checked) });
  return { el: h('label.switch', input, h('span')), input };
}

/** Text with digits and symbols tinted, so similar characters are easy to tell apart. */
export function colorize(text) {
  const parts = [];
  for (const run of String(text).match(/[A-Za-z]+|[0-9]+|[^A-Za-z0-9]+/g) ?? []) {
    if (/^[0-9]/.test(run)) parts.push(h('span.pw-digit', run));
    else if (/^[A-Za-z]/.test(run)) parts.push(run);
    else parts.push(h('span.pw-symbol', run));
  }
  return parts;
}

/** A labelled form field. */
export function labelled(label, control, { id, hint } = {}) {
  return h('div', h('label.label', { for: id }, label), control, hint ? h('p.hint', hint) : null);
}

/** A <select>. `options` are [value, label] pairs. */
export function select({ id, value, options, onchange, label }) {
  const el = h(
    'select.select',
    { id, 'aria-label': label, onchange: () => onchange?.(el.value) },
    options.map(([optionValue, text]) => h('option', { value: String(optionValue), selected: String(optionValue) === String(value) }, text)),
  );
  return el;
}

/** Puts a button into its busy state; returns a function that restores it. */
export function busy(button, text) {
  const previous = [...button.childNodes];
  button.disabled = true;
  button.replaceChildren(h('span.spinner'), text);
  return () => {
    button.disabled = false;
    button.replaceChildren(...previous);
  };
}
