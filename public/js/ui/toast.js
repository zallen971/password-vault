// Brief confirmation messages at the bottom of the screen.

import { h, icon } from './dom.js';

let container = null;

function ensureContainer() {
  if (!container) {
    container = h('div.toasts', { role: 'status', 'aria-live': 'polite', popover: 'manual' });
    document.body.append(container);
  }
  // Re-open the popover so toasts sit above any dialog opened since.
  try {
    if (container.matches(':popover-open')) container.hidePopover();
    container.showPopover();
  } catch {
    /* Popover API unavailable: the fixed-position fallback still works outside dialogs. */
  }
  return container;
}

/**
 * @param {string} message
 * @param {{type?: 'success'|'error', duration?: number}} [options]
 */
export function toast(message, { type = 'success', duration = type === 'error' ? 5200 : 2800 } = {}) {
  const parent = ensureContainer();
  const el = h('div.toast', { class: type === 'error' ? 'is-error' : '' }, icon(type === 'error' ? 'alert' : 'check', 16), h('span', message));
  // Keep at most three on screen.
  while (parent.children.length >= 3) parent.firstChild.remove();
  parent.append(el);

  const remove = () => {
    el.classList.add('is-leaving');
    el.addEventListener('animationend', () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400);
  };
  const timer = setTimeout(remove, duration);
  el.addEventListener('click', () => {
    clearTimeout(timer);
    remove();
  });
}

export function clearToasts() {
  container?.replaceChildren();
}
