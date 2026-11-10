// Vault health report: weak, reused, unprotected and breached passwords.

import { h, icon, mount } from '../ui/dom.js';
import { openDialog } from '../ui/dialog.js';
import { busy } from '../ui/controls.js';
import { analyzeVault } from '../lib/health.js';
import { findBreachedPasswords } from '../lib/breach.js';
import { displayName, itemSubtitle } from '../lib/model.js';
import { itemAvatar, plural } from './shared.js';

/**
 * @param {object} options
 * @param {import('../lib/vault.js').Vault} options.vault
 * @param {(id: string) => void} options.onOpen  show an item in the main view
 */
export function openHealth({ vault, onOpen }) {
  const report = analyzeVault(vault.items);
  const reusedCount = report.reused.reduce((total, group) => total + group.items.length, 0);

  const itemRow = (item, badge) =>
    h(
      'button.row',
      {
        type: 'button',
        onclick: () => {
          dialog.close();
          onOpen(item.id);
        },
      },
      itemAvatar(item),
      h('span.row-text', h('span.row-title.truncate', displayName(item)), h('span.row-sub.truncate', itemSubtitle(item) || 'Login')),
      badge,
      icon('chevron-right', 14),
    );

  const section = (title, description, rows) =>
    h('section.report', h('div.report-head', h('p', title, h('small', description))), rows);

  const stat = (count, label, tone) => h('div.stat', { class: count ? tone : 'is-good' }, h('b', count.toLocaleString()), h('span', label));

  // ---- Breach check (opt-in, because it talks to an outside service) ----

  const breachArea = h('div');
  function renderBreachIntro(message) {
    const button = h('button.btn.btn-secondary.btn-sm', { type: 'button' }, 'Check now');
    button.addEventListener('click', () => runBreachCheck(button));
    mount(
      breachArea,
      h(
        'section.report',
        h(
          'div.report-head',
          icon('shield', 18),
          h(
            'p',
            'Check for breached passwords',
            h('small', message ?? 'Compares your passwords with known data breaches. Only the first 5 characters of a scrambled hash leave this device, never a password.'),
          ),
          button,
        ),
      ),
    );
  }

  async function runBreachCheck(button) {
    const logins = vault.items.filter((item) => item.type === 'login' && !item.deletedAt && item.login.password);
    const restore = busy(button, 'Checking…');
    try {
      const counts = await findBreachedPasswords(
        logins.map((item) => item.login.password),
        { onProgress: (done, total) => (button.lastChild.textContent = `${Math.round((done / total) * 100)}%`) },
      );
      const exposed = logins
        .map((item) => ({ item, count: counts.get(item.login.password) ?? 0 }))
        .filter((entry) => entry.count > 0)
        .sort((a, b) => b.count - a.count);
      if (!exposed.length) {
        mount(
          breachArea,
          h('div.all-clear', icon('shield-check', 20), h('span', h('strong', 'No breached passwords. '), `None of your ${plural(logins.length, 'password')} appear in known data breaches.`)),
        );
        return;
      }
      mount(
        breachArea,
        section(
          `${plural(exposed.length, 'breached password')}`,
          'These passwords have appeared in data breaches. Anyone can try them, so change them soon.',
          exposed.map(({ item, count }) => itemRow(item, h('span.badge.badge-danger', `Seen ${count.toLocaleString()}×`))),
        ),
      );
    } catch {
      restore();
      renderBreachIntro('The breach database could not be reached. Check your connection and try again.');
    }
  }

  // ---- Body ----

  const body = [];
  if (!report.logins) {
    body.push(h('div.all-clear', icon('info', 20), h('span', 'Add some logins and Vault will keep an eye on weak and reused passwords here.')));
  } else {
    body.push(
      h(
        'div.stats',
        stat(report.weak.length, 'Weak', 'is-bad'),
        stat(reusedCount, 'Reused', 'is-warn'),
        stat(report.insecure.length, 'Unencrypted sites', 'is-warn'),
      ),
    );
    if (!report.weak.length && !reusedCount && !report.insecure.length) {
      body.push(
        h('div.all-clear', icon('shield-check', 20), h('span', h('strong', 'Looking good. '), `All ${plural(report.logins, 'password')} are strong and unique.`)),
      );
    }
    renderBreachIntro();
    body.push(breachArea);

    if (report.weak.length) {
      body.push(
        section(
          'Weak passwords',
          'Short or predictable passwords are quick to guess. Replace them with generated ones.',
          report.weak.map(({ item, strength }) => itemRow(item, h('span.badge', { class: strength.score === 0 ? 'badge-danger' : 'badge-warning' }, strength.label))),
        ),
      );
    }
    if (report.reused.length) {
      body.push(
        section(
          'Reused passwords',
          'If one of these sites is breached, every account sharing its password is exposed.',
          report.reused.map((group) => h('div.report-group', group.items.map((item) => itemRow(item, h('span.badge.badge-warning', `Used ${group.items.length}×`))))),
        ),
      );
    }
    if (report.insecure.length) {
      body.push(
        section(
          'Unencrypted websites',
          'These logins use http://, which sends your password across the network unprotected. Use https:// where the site supports it.',
          report.insecure.map((item) => itemRow(item, h('span.badge.badge-warning', 'http'))),
        ),
      );
    }
  }

  const dialog = openDialog({ title: 'Vault health', width: 620, body });
  return dialog;
}
