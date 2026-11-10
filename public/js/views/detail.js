// Read-only view of one item, with copy, reveal and launch actions.

import { h, icon, iconButton, mount, svg } from '../ui/dom.js';
import { colorize } from '../ui/controls.js';
import { openMenu } from '../ui/menu.js';
import { TRASH_RETENTION_DAYS, TYPE_INFO, displayName, formatCardNumber, fullName, launchUrl } from '../lib/model.js';
import { generateTotp, parseTotp } from '../lib/totp.js';
import { estimateStrength } from '../lib/strength.js';
import { formatDate, formatDateTime, itemAvatar } from './shared.js';

const MASK = '••••••••••';
const RING = 2 * Math.PI * 9;

/**
 * @param {object} options
 * @param {object} options.item
 * @param {string} options.folderName
 * @param {boolean} options.animate
 * @param {object} options.actions  copy, back, edit, clone, favorite, trash, restore, remove
 * @returns {{el: HTMLElement, dispose: () => void}}
 */
export function itemView({ item, folderName, animate, actions }) {
  const disposers = [];
  const trashed = Boolean(item.deletedAt);

  /**
   * One labelled value with its action buttons.
   * `secret` values start masked; `masked` overrides what is shown while hidden.
   */
  function valueRow({ label, value, copyValue = value, mono = false, secret = false, tint = false, pre = false, masked = MASK, display, badge, extra = [], clickToCopy = true }) {
    if (!value) return null;
    let revealed = !secret;
    const valueEl = h('div.field-value', { class: `${mono ? 'mono' : ''} ${pre ? 'pre' : ''}` });
    const paint = () => {
      valueEl.classList.toggle('is-hidden', !revealed && masked === MASK);
      mount(valueEl, revealed ? (tint ? colorize(value) : (display ?? value)) : masked);
    };
    paint();

    const reveal = secret
      ? iconButton('eye', `Show ${label.toLowerCase()}`, {
          'aria-pressed': 'false',
          onclick: (event) => {
            event.stopPropagation();
            revealed = !revealed;
            paint();
            reveal.replaceChildren(icon(revealed ? 'eye-off' : 'eye', 16));
            reveal.title = `${revealed ? 'Hide' : 'Show'} ${label.toLowerCase()}`;
            reveal.setAttribute('aria-label', reveal.title);
            reveal.setAttribute('aria-pressed', String(revealed));
          },
        })
      : null;
    const copyButton = iconButton('copy', `Copy ${label.toLowerCase()}`, {
      onclick: (event) => {
        event.stopPropagation();
        actions.copy(copyValue, label);
      },
    });

    return h(
      'div.field',
      {
        class: clickToCopy ? 'is-copyable' : '',
        // Clicking anywhere on the row copies, unless the user is selecting text.
        onclick: clickToCopy
          ? () => {
              if (!String(window.getSelection())) actions.copy(copyValue, label);
            }
          : null,
      },
      h('div.field-main', h('div.field-name', label, badge), valueEl),
      h('div.field-actions', extra, reveal, copyButton),
    );
  }

  function totpRow(secret) {
    if (!secret) return null;
    const config = parseTotp(secret);
    if (!config) {
      return h('div.field', h('div.field-main', h('div.field-name', 'Verification code'), h('div.field-value.muted', 'The authenticator key saved for this login is not valid.')));
    }
    let current = '';
    const codeEl = h('span.totp-code', '······');
    const progress = svg('circle', { class: 'progress', cx: 11, cy: 11, r: 9, 'stroke-dasharray': RING, 'stroke-dashoffset': 0 });
    const wrap = h(
      'div.totp',
      codeEl,
      svg('svg', { class: 'totp-ring', width: 22, height: 22, viewBox: '0 0 22 22', 'aria-hidden': 'true' }, svg('circle', { class: 'track', cx: 11, cy: 11, r: 9 }), progress),
    );

    let alive = true;
    async function tick() {
      const { code, remaining, period } = await generateTotp(config);
      if (!alive) return;
      current = code;
      const half = Math.ceil(code.length / 2);
      codeEl.textContent = `${code.slice(0, half)} ${code.slice(half)}`;
      // Snap back instantly when a new code starts instead of sweeping backwards.
      progress.style.transition = remaining >= period - 1 ? 'none' : '';
      progress.setAttribute('stroke-dashoffset', String(RING * (1 - (remaining - 1) / period)));
      wrap.classList.toggle('is-ending', remaining <= 5);
      wrap.title = `Changes in ${remaining} second${remaining === 1 ? '' : 's'}`;
    }
    tick();
    const timer = setInterval(tick, 1000);
    disposers.push(() => {
      alive = false;
      clearInterval(timer);
    });

    const copyCode = () => current && actions.copy(current, 'Verification code');
    return h(
      'div.field.is-copyable',
      { onclick: copyCode },
      h('div.field-main', h('div.field-name', 'Verification code'), h('div.field-value', wrap)),
      h(
        'div.field-actions',
        iconButton('copy', 'Copy verification code', {
          onclick: (event) => {
            event.stopPropagation();
            copyCode();
          },
        }),
      ),
    );
  }

  function websiteRow(uri) {
    const url = launchUrl(uri);
    const open = (event) => {
      event.stopPropagation();
      event.preventDefault();
      window.open(url, '_blank', 'noopener,noreferrer');
    };
    return valueRow({
      label: 'Website',
      value: uri,
      display: url ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', title: 'Open in a new tab', onclick: open }, uri) : uri,
      extra: url ? [iconButton('external', 'Open website', { onclick: open })] : [],
    });
  }

  const card = (rows) => {
    const present = rows.filter(Boolean);
    return present.length ? h('section.card', present) : null;
  };
  const titled = (title, content) => (content ? [h('h3.section-title', title), content] : null);

  // ---- Body, by item type ----

  const body = [];

  if (item.type === 'login') {
    const { username, password, totp, uris } = item.login;
    const weak = password && estimateStrength(password).score <= 1;
    body.push(
      card([
        valueRow({ label: 'Username', value: username }),
        valueRow({
          label: 'Password',
          value: password,
          mono: true,
          secret: true,
          tint: true,
          badge: weak ? h('span.badge.badge-danger', 'Weak') : null,
        }),
        totpRow(totp),
      ]),
      titled(uris.length > 1 ? 'Websites' : 'Website', card(uris.map(websiteRow))),
    );
  }

  if (item.type === 'card') {
    const { cardholder, number, brand, expMonth, expYear, code } = item.card;
    const digits = number.replace(/\D/g, '');
    const expiry = [expMonth && expMonth.padStart(2, '0'), expYear].filter(Boolean).join(' / ');
    body.push(
      card([
        valueRow({ label: 'Cardholder name', value: cardholder }),
        valueRow({
          label: 'Card number',
          value: number,
          copyValue: digits || number,
          display: formatCardNumber(number),
          masked: digits.length >= 8 ? `•••• •••• •••• ${digits.slice(-4)}` : MASK,
          mono: true,
          secret: true,
        }),
        valueRow({ label: 'Brand', value: brand, clickToCopy: false }),
        valueRow({ label: 'Expires', value: expiry, mono: true }),
        valueRow({ label: 'Security code', value: code, mono: true, secret: true }),
      ]),
    );
  }

  if (item.type === 'identity') {
    const id = item.identity;
    const cityLine = [id.city, [id.state, id.postalCode].filter(Boolean).join(' ')].filter(Boolean).join(', ');
    const address = [id.address1, id.address2, id.address3, cityLine, id.country].filter(Boolean).join('\n');
    body.push(
      card([
        valueRow({ label: 'Name', value: fullName(id) }),
        valueRow({ label: 'Username', value: id.username }),
        valueRow({ label: 'Company', value: id.company }),
        valueRow({ label: 'Email', value: id.email }),
        valueRow({ label: 'Phone', value: id.phone }),
      ]),
      titled(
        'Identification',
        card([
          valueRow({ label: 'Social Security / national ID number', value: id.ssn, mono: true, secret: true }),
          valueRow({ label: 'Passport number', value: id.passportNumber, mono: true, secret: true }),
          valueRow({ label: 'License number', value: id.licenseNumber, mono: true, secret: true }),
        ]),
      ),
      titled('Address', card([valueRow({ label: 'Address', value: address, pre: true })])),
    );
  }

  body.push(
    titled(
      item.type === 'note' ? 'Note' : 'Notes',
      card([valueRow({ label: item.type === 'note' ? 'Note' : 'Notes', value: item.notes, pre: true, clickToCopy: false })]),
    ),
    titled(
      'Custom fields',
      card(
        item.fields.map((field) => {
          const label = field.name || 'Field';
          if (field.type === 'boolean') {
            const on = field.value === 'true';
            return h(
              'div.field',
              h('div.field-main', h('div.field-name', label), h('div.field-value', h('span.check-value', icon(on ? 'check' : 'x', 15), on ? 'Yes' : 'No'))),
            );
          }
          return valueRow({ label, value: field.value, secret: field.type === 'hidden', mono: field.type === 'hidden' });
        }),
      ),
    ),
  );

  const hasContent = body.flat(Infinity).some(Boolean);
  if (!hasContent) {
    body.push(h('section.card', h('div.field', h('div.field-main', h('div.field-value.muted', 'This item has no details yet. Choose Edit to add some.')))));
  }

  // ---- Password history ----

  const history = item.passwordHistory.length
    ? h(
        'details.history',
        h('summary', icon('clock', 13), `Password history (${item.passwordHistory.length})`, icon('chevron-right', 13)),
        h(
          'section.card',
          item.passwordHistory.map((entry) =>
            valueRow({ label: `Replaced ${formatDateTime(entry.changedAt)}`, value: entry.password, copyValue: entry.password, mono: true, secret: true, tint: true }),
          ),
        ),
      )
    : null;

  // ---- Header ----

  const star = iconButton('star', item.favorite ? 'Remove from favorites' : 'Add to favorites', {
    class: item.favorite ? 'is-on' : '',
    'aria-pressed': String(item.favorite),
    size: 17,
    onclick: () => actions.favorite(!item.favorite),
  });
  const more = iconButton('more', 'More actions', {
    'aria-haspopup': 'menu',
    size: 17,
    onclick: () =>
      openMenu(
        more,
        [
          { label: 'Duplicate', icon: 'copy', onSelect: actions.clone },
          'separator',
          { label: 'Move to trash', icon: 'trash', danger: true, onSelect: actions.trash },
        ],
        { align: 'end' },
      ),
  });

  const purgeDate = trashed ? new Date(new Date(item.deletedAt).getTime() + TRASH_RETENTION_DAYS * 86_400_000).toISOString() : null;

  const el = h(
    'article.detail',
    { style: animate ? null : { animation: 'none' } },
    h('div.detail-top', h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: actions.back }, icon('arrow-left', 16), 'Back')),
    h(
      'header.detail-head',
      itemAvatar(item, { large: true }),
      h(
        'div.detail-heading',
        h('h2.detail-title', { tabIndex: -1 }, displayName(item)),
        h(
          'div.detail-meta',
          h('span', icon(TYPE_INFO[item.type].icon, 13), TYPE_INFO[item.type].label),
          folderName ? [h('i.dot'), h('span', icon('folder', 13), folderName)] : null,
        ),
      ),
      trashed
        ? null
        : h('div.detail-actions', star, h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: actions.edit }, icon('edit', 14), 'Edit'), more),
    ),
    trashed
      ? h(
          'div.banner',
          icon('trash', 16),
          h('span', `In the trash. It will be deleted for good on ${formatDate(purgeDate)}.`),
          h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: actions.restore }, icon('undo', 14), 'Restore'),
          h('button.btn.btn-danger-ghost.btn-sm', { type: 'button', onclick: actions.remove }, 'Delete now'),
        )
      : null,
    body,
    history,
    h('footer.detail-foot', h('span', `Updated ${formatDateTime(item.updatedAt)}`), h('span', `Created ${formatDateTime(item.createdAt)}`)),
  );

  return { el, dispose: () => disposers.forEach((dispose) => dispose()) };
}
