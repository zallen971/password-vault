// Dropdown menus, built on the Popover API (light dismiss and Escape for free).

import { h, icon } from './dom.js';

/**
 * @param {HTMLElement} anchor  the button the menu belongs to
 * @param {Array<{label: string, icon?: string, onSelect: () => void, danger?: boolean, checked?: boolean}
 *               | {heading: string} | 'separator'>} items
 * @param {{align?: 'start'|'end'}} [options]
 */
export function openMenu(anchor, items, { align = 'start' } = {}) {
  // A click on the anchor while its menu is open should just close it.
  if (Number(anchor.dataset.menuClosedAt) > Date.now() - 250) return;

  const menu = h('div.menu', { role: 'menu', popover: 'auto' });
  for (const item of items) {
    if (!item) continue;
    if (item === 'separator') {
      menu.append(h('div.menu-sep', { role: 'separator' }));
    } else if (item.heading) {
      menu.append(h('div.menu-heading', item.heading));
    } else {
      menu.append(
        h(
          'button.menu-item',
          {
            type: 'button',
            role: item.checked === undefined ? 'menuitem' : 'menuitemradio',
            class: item.danger ? 'is-danger' : '',
            'aria-checked': item.checked === undefined ? null : String(item.checked),
            onclick: () => {
              menu.hidePopover();
              item.onSelect();
            },
          },
          item.icon ? icon(item.icon, 16) : null,
          h('span', item.label),
        ),
      );
    }
  }

  document.body.append(menu);
  menu.showPopover();
  anchor.setAttribute('aria-expanded', 'true');

  // Place below the anchor, flipping or shifting to stay on screen.
  const gap = 6;
  const edge = 8;
  const a = anchor.getBoundingClientRect();
  const m = menu.getBoundingClientRect();
  let left = align === 'end' ? a.right - m.width : a.left;
  left = Math.max(edge, Math.min(left, window.innerWidth - m.width - edge));
  let top = a.bottom + gap;
  if (top + m.height > window.innerHeight - edge) top = Math.max(edge, a.top - gap - m.height);
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;

  const buttons = [...menu.querySelectorAll('.menu-item')];
  buttons[0]?.focus({ preventScroll: true });
  menu.addEventListener('keydown', (event) => {
    const index = buttons.indexOf(document.activeElement);
    let next = null;
    if (event.key === 'ArrowDown') next = buttons[(index + 1) % buttons.length];
    else if (event.key === 'ArrowUp') next = buttons[(index - 1 + buttons.length) % buttons.length];
    else if (event.key === 'Home') [next] = buttons;
    else if (event.key === 'End') next = buttons.at(-1);
    else if (event.key === 'Tab') menu.hidePopover();
    if (next) {
      event.preventDefault();
      next.focus();
    }
  });

  menu.addEventListener('toggle', (event) => {
    if (event.newState !== 'closed') return;
    anchor.removeAttribute('aria-expanded');
    anchor.dataset.menuClosedAt = String(Date.now());
    const focusWasInside = menu.contains(document.activeElement);
    menu.remove();
    if (focusWasInside && anchor.isConnected) anchor.focus({ preventScroll: true });
  });
  return menu;
}

/** Closes any open menu (used when the vault locks). */
export function closeMenus() {
  for (const menu of document.querySelectorAll('.menu:popover-open')) menu.hidePopover();
}
