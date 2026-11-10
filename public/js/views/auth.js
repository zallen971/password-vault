// The locked screen: log in to an existing vault, or create a new one.

import { h, icon, mount } from '../ui/dom.js';
import { busy, passwordInput, strengthMeter } from '../ui/controls.js';
import { describeError } from '../ui/errors.js';
import { prefs } from '../lib/prefs.js';
import { WEAK_MASTER_PASSWORD_WARNING, isWeakMasterPassword, masterPasswordProblem } from '../lib/policy.js';
import { confirmDialog } from '../ui/dialog.js';

const brand = () => h('div.brand', h('img', { src: 'icons/logo.svg', alt: '' }), 'Vault');

const footer = () =>
  h(
    'footer.auth-foot',
    h('span', icon('lock', 13), 'End-to-end encrypted'),
    h('span', icon('shield-check', 13), 'AES-256'),
    h('span', icon('eye-off', 13), 'Zero-knowledge'),
  );

/**
 * @param {HTMLElement} root
 * @param {object} options
 * @param {import('../lib/vault.js').Vault} options.vault
 * @param {{signupsOpen: boolean, firstRun: boolean}|null} options.config  null if the server is unreachable
 * @param {string} [options.notice]      why the vault was locked, if worth saying
 * @param {() => void} options.onUnlocked
 * @param {() => void} options.onRetry
 */
export function renderAuth(root, { vault, config, notice, onUnlocked, onRetry }) {
  if (!config) {
    mount(
      root,
      h(
        'main.auth',
        h(
          'div.auth-card.message-card',
          h('div.message-icon', icon('alert', 24)),
          h('h1.auth-title', 'Can’t reach the server'),
          h('p', 'Vault could not connect to its server. Check that it is running and that you are online.'),
          h('button.btn.btn-primary.btn-lg.btn-block', { type: 'button', style: { marginTop: '22px' }, onclick: onRetry }, 'Try again'),
        ),
        footer(),
      ),
    );
    return;
  }

  let mode = config.firstRun && config.signupsOpen ? 'signup' : 'login';
  let email = prefs.get('rememberEmail') ? prefs.get('email') : '';

  function render(message = notice) {
    const signup = mode === 'signup';
    const errorBox = h('div.auth-error', { role: 'alert', hidden: true });
    const showError = (text) => {
      mount(errorBox, icon('alert', 16), h('span', text));
      errorBox.hidden = false;
    };

    const emailInput = h('input.input.input-lg', {
      id: 'auth-email',
      type: 'email',
      value: email,
      placeholder: 'you@example.com',
      autocomplete: 'username',
      autocapitalize: 'off',
      spellcheck: false,
      required: true,
      autofocus: !email,
      oninput: () => (email = emailInput.value),
    });
    const meter = strengthMeter();
    const password = passwordInput({
      id: 'auth-password',
      autocomplete: signup ? 'new-password' : 'current-password',
      large: true,
      autofocus: Boolean(email),
      oninput: signup ? (value) => meter.update(value) : undefined,
    });
    const confirm = signup ? passwordInput({ id: 'auth-confirm', autocomplete: 'new-password', large: true }) : null;
    const submit = h('button.btn.btn-primary.btn-lg.btn-block', { type: 'submit' }, signup ? 'Create vault' : 'Unlock');

    async function onSubmit(event) {
      event.preventDefault();
      errorBox.hidden = true;
      const address = emailInput.value.trim();
      const secret = password.input.value;
      if (!/^[^\s@]+@[^\s@]+$/.test(address)) {
        showError('Enter a valid email address.');
        emailInput.focus();
        return;
      }
      if (signup) {
        const problem = masterPasswordProblem(secret, confirm.input.value);
        if (problem) {
          showError(problem);
          password.input.focus();
          return;
        }
        if (isWeakMasterPassword(secret) && !(await confirmDialog(WEAK_MASTER_PASSWORD_WARNING))) {
          password.input.select();
          return;
        }
      }
      const restore = busy(submit, signup ? 'Creating your vault…' : 'Unlocking…');
      try {
        if (signup) await vault.signUp(address, secret);
        else await vault.unlock(address, secret);
        prefs.set('email', prefs.get('rememberEmail') ? address : '');
        onUnlocked();
      } catch (error) {
        restore();
        showError(describeError(error));
        password.input.select();
      }
    }

    const switcher = signup
      ? ['Already have a vault? ', h('button.link-btn', { type: 'button', onclick: () => swap('login') }, 'Log in')]
      : config.signupsOpen
        ? ['New here? ', h('button.link-btn', { type: 'button', onclick: () => swap('signup') }, 'Create a vault')]
        : null;

    mount(
      root,
      h(
        'main.auth',
        h(
          'div.auth-card',
          brand(),
          h('h1.auth-title', signup ? 'Create your vault' : 'Welcome back'),
          h(
            'p.auth-sub',
            signup
              ? 'One master password protects everything. Make it long, and make it one you will remember.'
              : 'Enter your master password to unlock your vault.',
          ),
          message ? h('div.auth-notice', { role: 'status' }, icon('info', 16), h('span', message)) : null,
          h(
            'form.auth-form',
            { onsubmit: onSubmit, novalidate: true },
            h('div', h('label.label', { for: 'auth-email' }, 'Email'), emailInput),
            h('div', h('label.label', { for: 'auth-password' }, 'Master password'), password.el, signup ? meter.el : null),
            signup ? h('div', h('label.label', { for: 'auth-confirm' }, 'Confirm master password'), confirm.el) : null,
            signup
              ? h(
                  'div.callout.callout-warning',
                  icon('alert', 16),
                  h(
                    'span',
                    h('strong', 'There is no password reset. '),
                    'Your vault is encrypted with your master password and nobody, including this server, can recover it for you.',
                  ),
                )
              : null,
            errorBox,
            submit,
          ),
          switcher ? h('p.auth-switch', switcher) : null,
        ),
        footer(),
      ),
    );
  }

  function swap(next) {
    mode = next;
    render(null);
  }

  render();
}

/** Shown when the browser cannot run the app at all. */
export function renderUnsupported(root, { title, lines }) {
  mount(
    root,
    h(
      'main.auth',
      h('div.auth-card.message-card', h('div.message-icon', icon('alert', 24)), h('h1.auth-title', title), lines.map((line) => h('p', line))),
      footer(),
    ),
  );
}
