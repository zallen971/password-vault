// Small pieces shared by the list, detail and report views.

import { h, hueFor, icon } from '../ui/dom.js';
import { TYPE_INFO, displayName } from '../lib/model.js';

const TYPE_HUES = { note: 38, card: 162, identity: 262 };

/** The colored tile shown beside an item: its initial for logins, an icon otherwise. */
export function itemAvatar(item, { large = false } = {}) {
  const name = displayName(item);
  const initial = item.type === 'login' ? [...name].find((char) => /[\p{L}\p{N}]/u.test(char)) : null;
  const hue = item.type === 'login' ? hueFor(name.toLowerCase()) : TYPE_HUES[item.type];
  return h(
    'span.avatar',
    { class: large ? 'avatar-lg' : '', style: { '--hue': String(hue) }, 'aria-hidden': 'true' },
    initial ?? icon(TYPE_INFO[item.type].icon, large ? 24 : 18),
  );
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });

export const formatDateTime = (iso) => dateTime.format(new Date(iso));
export const formatDate = (iso) => dateOnly.format(new Date(iso));

export const plural = (count, one, many = `${one}s`) => `${count.toLocaleString()} ${count === 1 ? one : many}`;

/** Saves text as a file through the browser's download mechanism. */
export function downloadFile(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = h('a', { href: url, download: name, hidden: true });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
