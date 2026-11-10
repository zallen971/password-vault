// Password and passphrase generator dialog.

import { h, icon, iconButton, mount } from '../ui/dom.js';
import { openDialog } from '../ui/dialog.js';
import { colorize, strengthMeter, toggle } from '../ui/controls.js';
import { prefs } from '../lib/prefs.js';
import {
  PASSPHRASE_WORDS,
  PASSWORD_LENGTH,
  generatePassphrase,
  generatePassword,
  normalizePassphraseOptions,
  normalizePasswordOptions,
  passphraseEntropy,
  passwordEntropy,
} from '../lib/generator.js';
import { scoreForBits } from '../lib/strength.js';

const SLIDER_MAX = 64; // the slider covers everyday lengths; the number box goes further

/**
 * @param {object} options
 * @param {(text: string, label: string) => void} options.copy
 * @param {(password: string) => void} [options.onUse]  when set, offers "Use password"
 */
export function openGenerator({ copy, onUse }) {
  const saved = prefs.get('generator') ?? {};
  const state = {
    mode: saved.mode === 'passphrase' ? 'passphrase' : 'password',
    password: normalizePasswordOptions(saved.password),
    passphrase: normalizePassphraseOptions(saved.passphrase),
  };
  let value = '';

  const output = h('div.gen-value', { 'aria-live': 'polite', 'aria-label': 'Generated password' });
  const meter = strengthMeter();
  const bitsEl = h('span.meter-bits');
  const optionsEl = h('div.gen-options');

  function regenerate() {
    const passwordMode = state.mode === 'password';
    value = passwordMode ? generatePassword(state.password) : generatePassphrase(state.passphrase);
    mount(output, colorize(value));
    const bits = passwordMode ? passwordEntropy(state.password) : passphraseEntropy(state.passphrase);
    meter.update(scoreForBits(bits));
    bitsEl.textContent = `${Math.round(bits)} bits`;
    prefs.set('generator', { mode: state.mode, password: state.password, passphrase: state.passphrase });
  }

  /** A slider paired with a number box. */
  function lengthControl(label, options, key, limits, sliderMax) {
    const id = `gen-${key}`;
    const slider = h('input', { type: 'range', id, min: limits.min, max: sliderMax, step: 1, value: Math.min(options[key], sliderMax) });
    const box = h('input.input', { type: 'number', min: limits.min, max: limits.max, value: options[key], 'aria-label': label, inputMode: 'numeric' });
    const apply = (raw, source) => {
      const number = Number.parseInt(raw, 10);
      if (!Number.isFinite(number)) return;
      options[key] = Math.min(limits.max, Math.max(limits.min, number));
      if (source !== slider) slider.value = String(Math.min(options[key], sliderMax));
      if (source !== box) box.value = String(options[key]);
      regenerate();
    };
    slider.addEventListener('input', () => apply(slider.value, slider));
    box.addEventListener('input', () => apply(box.value, box));
    box.addEventListener('blur', () => (box.value = String(options[key])));
    return h('div', h('label.label', { for: id }, label), h('div.gen-length', slider, box));
  }

  function option(label, sample, options, key, wide = false) {
    const control = toggle({
      checked: options[key],
      standalone: false, // the surrounding <label> names it
      onchange: (on) => {
        options[key] = on;
        // At least one kind of character has to stay switched on.
        const normalized = state.mode === 'password' ? normalizePasswordOptions(options) : normalizePassphraseOptions(options);
        const corrected = normalized[key] !== on || Object.keys(normalized).some((name) => normalized[name] !== options[name]);
        Object.assign(options, normalized);
        if (corrected) renderOptions();
        regenerate();
      },
    });
    return h('label.option', { class: wide ? 'option-wide' : '' }, h('span', label, sample ? [' ', h('span.mono', sample)] : null), control.el);
  }

  function renderOptions() {
    if (state.mode === 'password') {
      const o = state.password;
      mount(
        optionsEl,
        lengthControl('Length', o, 'length', PASSWORD_LENGTH, SLIDER_MAX),
        h(
          'div.option-grid',
          option('Uppercase', 'A–Z', o, 'uppercase'),
          option('Lowercase', 'a–z', o, 'lowercase'),
          option('Numbers', '0–9', o, 'numbers'),
          option('Symbols', '!@#$', o, 'symbols'),
          option('Avoid look-alike characters', 'I l 1 O 0', o, 'avoidAmbiguous', true),
        ),
      );
    } else {
      const o = state.passphrase;
      const separator = h('input.input', {
        type: 'text',
        value: o.separator,
        maxLength: 3,
        'aria-label': 'Word separator',
        autocomplete: 'off',
        spellcheck: false,
        oninput: () => {
          o.separator = separator.value;
          regenerate();
        },
      });
      mount(
        optionsEl,
        lengthControl('Number of words', o, 'words', PASSPHRASE_WORDS, PASSPHRASE_WORDS.max),
        h(
          'div.option-grid',
          option('Capitalize words', '', o, 'capitalize'),
          option('Include a number', '', o, 'includeNumber'),
          h('label.option.option-wide', h('span', 'Separator between words'), separator),
        ),
      );
    }
  }

  const modeButton = (mode, label) =>
    h(
      'button',
      {
        type: 'button',
        'aria-pressed': String(state.mode === mode),
        onclick: (event) => {
          state.mode = mode;
          for (const button of modes.children) button.setAttribute('aria-pressed', String(button === event.currentTarget));
          renderOptions();
          regenerate();
        },
      },
      label,
    );
  const modes = h('div.segmented', { role: 'group', 'aria-label': 'What to generate' }, modeButton('password', 'Password'), modeButton('passphrase', 'Passphrase'));

  const dialog = openDialog({
    title: 'Generator',
    width: 480,
    body: [
      h(
        'div.gen-output',
        output,
        iconButton('refresh', 'Generate another', { onclick: regenerate }),
        iconButton('copy', 'Copy', { onclick: () => copy(value, 'Password') }),
      ),
      h('div.meter-row', meter.el, bitsEl),
      modes,
      optionsEl,
    ],
    footer: onUse
      ? [
          h('button.btn.btn-secondary', { type: 'button', onclick: () => dialog.close() }, 'Cancel'),
          h(
            'button.btn.btn-primary',
            {
              type: 'button',
              autofocus: true,
              onclick: () => {
                onUse(value);
                dialog.close();
              },
            },
            icon('check', 16),
            'Use password',
          ),
        ]
      : [
          h('button.btn.btn-secondary', { type: 'button', onclick: () => dialog.close() }, 'Close'),
          h(
            'button.btn.btn-primary',
            {
              type: 'button',
              autofocus: true,
              onclick: () => {
                copy(value, 'Password');
                dialog.close();
              },
            },
            icon('copy', 16),
            'Copy and close',
          ),
        ],
  });

  renderOptions();
  regenerate();
  return dialog;
}
