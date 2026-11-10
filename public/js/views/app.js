// The unlocked app: sidebar, item list and detail pane.

import { h, icon, iconButton, mount } from '../ui/dom.js';
import { openMenu } from '../ui/menu.js';
import { confirmDialog, promptDialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { describeError } from '../ui/errors.js';
import { prefs } from '../lib/prefs.js';
import { copyText } from '../lib/clipboard.js';
import { VaultError } from '../lib/vault.js';
import { ITEM_TYPES, TRASH_RETENTION_DAYS, TYPE_INFO, blankItem, displayName, itemSubtitle, normalizeItem, searchText } from '../lib/model.js';
import { itemAvatar, plural } from './shared.js';
import { itemView } from './detail.js';
import { itemEditor } from './editor.js';
import { openGenerator } from './generator.js';
import { openHealth } from './health.js';
import { openSettings } from './settings.js';

const PAGE_SIZE = 150;
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
const sameFilter = (a, b) => a.type === b.type && a.value === b.value;

/**
 * Renders the app into `root` and returns a function that tears it down.
 * @param {HTMLElement} root
 * @param {{vault: import('../lib/vault.js').Vault, serverInfo: object|null}} context
 */
export function renderApp(root, { vault, serverInfo }) {
  const state = {
    filter: { type: 'all' },
    query: '',
    selectedId: null,
    editor: null, // { item, isNew, dirty } while an item is being edited
    sort: prefs.get('sort') === 'updated' ? 'updated' : 'name',
  };
  let shown = null; // what the detail pane currently displays
  let disposeDetail = null;
  let searchIndex = new WeakMap();
  let listItems = [];
  let listRendered = 0;

  // ---- Helpers ----

  /** Runs a vault action, reporting failure as a toast. Resolves to true on success. */
  async function attempt(action, success) {
    try {
      await action();
      if (success) toast(success);
      return true;
    } catch (error) {
      toast(describeError(error), { type: 'error' });
      return false;
    }
  }

  async function copy(text, label) {
    try {
      await copyText(text, Number(prefs.get('clipboardClearSeconds')));
      toast(`${label} copied`);
    } catch {
      toast('Your browser blocked access to the clipboard.', { type: 'error' });
    }
  }

  function filterLabel(filter) {
    switch (filter.type) {
      case 'favorites':
        return 'Favorites';
      case 'kind':
        return TYPE_INFO[filter.value].plural;
      case 'folder':
        return vault.folder(filter.value)?.name ?? 'Folder';
      case 'unfiled':
        return 'No folder';
      case 'trash':
        return 'Trash';
      default:
        return 'All items';
    }
  }

  function visibleItems() {
    const { filter } = state;
    const inTrash = filter.type === 'trash';
    const terms = state.query.toLowerCase().split(/\s+/).filter(Boolean);
    const matches = [];
    for (const item of vault.items) {
      if (Boolean(item.deletedAt) !== inTrash) continue;
      if (filter.type === 'favorites' && !item.favorite) continue;
      if (filter.type === 'kind' && item.type !== filter.value) continue;
      if (filter.type === 'folder' && item.folderId !== filter.value) continue;
      if (filter.type === 'unfiled' && item.folderId) continue;
      if (terms.length) {
        let haystack = searchIndex.get(item);
        if (haystack === undefined) {
          haystack = searchText(item, vault.folder(item.folderId)?.name);
          searchIndex.set(item, haystack);
        }
        if (!terms.every((term) => haystack.includes(term))) continue;
      }
      matches.push(item);
    }

    const byName = (a, b) => collator.compare(displayName(a), displayName(b));
    if (terms.length) {
      // Matches in the name come first, best (earliest) match on top.
      const rank = (item) => {
        const name = displayName(item).toLowerCase();
        if (name.startsWith(terms[0])) return 0;
        return name.includes(terms[0]) ? 1 : 2;
      };
      return matches.sort((a, b) => rank(a) - rank(b) || byName(a, b));
    }
    if (inTrash) return matches.sort((a, b) => b.deletedAt.localeCompare(a.deletedAt));
    if (state.sort === 'updated') return matches.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return matches.sort(byName);
  }

  /** Asks before throwing away unsaved edits. Resolves to true if it is fine to continue. */
  async function leaveEditor() {
    if (!state.editor?.dirty) return true;
    return confirmDialog({
      title: 'Discard changes?',
      message: 'You have unsaved changes to this item. If you leave now they will be lost.',
      confirmLabel: 'Discard',
      cancelLabel: 'Keep editing',
      danger: true,
    });
  }

  // On narrow screens the list and the detail view take turns filling the
  // screen. Opening the detail view adds a history entry, so the browser's
  // Back button (or the Android back gesture) returns to the list instead of
  // leaving the app.
  const singlePane = matchMedia('(max-width: 860px)');
  const DETAIL_ENTRY = 'vault-detail';

  function showPane(pane) {
    if (shell.dataset.pane === pane) return;
    shell.dataset.pane = pane;
    if (pane === 'detail') {
      if (singlePane.matches) history.pushState(DETAIL_ENTRY, '');
    } else if (history.state === DETAIL_ENTRY) {
      history.back();
    }
  }

  function onPopState() {
    if (shell.dataset.pane !== 'detail') return; // we went back ourselves
    if (state.editor) {
      // Leaving an open editor is a step of its own: stay on this level and
      // close it (asking first if there are unsaved changes).
      history.pushState(DETAIL_ENTRY, '');
      cancelEdit();
      return;
    }
    shell.dataset.pane = 'list';
  }

  const closeNav = () => shell.classList.remove('is-nav-open');

  // ---- Actions ----

  function setFilter(filter) {
    state.filter = filter;
    closeNav();
    renderNav();
    renderList();
    listEl.scrollTop = 0;
  }

  async function select(id) {
    if (state.selectedId === id && !state.editor) {
      showPane('detail');
      return;
    }
    if (!(await leaveEditor())) return;
    state.editor = null;
    state.selectedId = id;
    renderDetail(true);
    markSelection();
    showPane('detail');
  }

  async function newItem(type) {
    if (!(await leaveEditor())) return;
    const folderId = state.filter.type === 'folder' ? state.filter.value : null;
    state.editor = { item: blankItem(type, folderId), isNew: true, dirty: false };
    renderDetail(true);
    showPane('detail');
  }

  function editItem(item) {
    state.editor = { item: structuredClone(item), isNew: false, dirty: false };
    renderDetail(true);
  }

  async function cloneItem(item) {
    const copyOf = normalizeItem({ ...structuredClone(item), id: undefined, name: `${displayName(item)} (copy)`, passwordHistory: [], createdAt: undefined });
    state.editor = { item: copyOf, isNew: true, dirty: true };
    renderDetail(true);
  }

  async function saveDraft(draft) {
    const { isNew } = state.editor;
    try {
      const saved = await vault.saveItem(draft);
      state.editor = null;
      state.selectedId = saved.id;
      toast(isNew ? 'Item added' : 'Changes saved');
      renderDetail(false);
      markSelection(true);
    } catch (error) {
      const conflict = error instanceof VaultError && error.code === 'conflict';
      toast(
        conflict
          ? 'This item was changed on another device. Save again to keep your version, or cancel to keep theirs.'
          : describeError(error),
        { type: 'error', duration: conflict ? 9000 : undefined },
      );
      throw error;
    }
  }

  async function cancelEdit() {
    if (!state.editor || !(await leaveEditor())) return;
    state.editor = null;
    renderDetail(true); // falls back to the list when there is nothing to show
  }

  async function trashItem(item) {
    if (await attempt(() => vault.trashItems([item.id]), 'Moved to trash')) showPane('list');
  }

  async function deleteForever(item) {
    const ok = await confirmDialog({
      title: 'Delete permanently?',
      message: `“${displayName(item)}” will be deleted for good. This cannot be undone.`,
      confirmLabel: 'Delete permanently',
      danger: true,
    });
    if (ok && (await attempt(() => vault.deleteItems([item.id]), 'Item deleted'))) showPane('list');
  }

  async function emptyTrash() {
    const count = vault.items.filter((item) => item.deletedAt).length;
    const ok = await confirmDialog({
      title: 'Empty trash?',
      message: `${plural(count, 'item')} will be deleted for good. This cannot be undone.`,
      confirmLabel: 'Empty trash',
      danger: true,
    });
    if (ok) await attempt(() => vault.emptyTrash(), 'Trash emptied');
  }

  /** Prompts for a name and creates a folder. Resolves to the folder, or null. */
  async function createFolder() {
    const name = await promptDialog({ title: 'New folder', label: 'Folder name', placeholder: 'e.g. Work', confirmLabel: 'Create' });
    if (!name) return null;
    try {
      const folder = await vault.saveFolder({ name });
      toast('Folder created');
      return folder;
    } catch (error) {
      toast(describeError(error), { type: 'error' });
      return null;
    }
  }

  async function renameFolder(folder) {
    const name = await promptDialog({ title: 'Rename folder', label: 'Folder name', value: folder.name });
    if (name && name !== folder.name) await attempt(() => vault.saveFolder({ id: folder.id, name }), 'Folder renamed');
  }

  async function deleteFolder(folder) {
    const ok = await confirmDialog({
      title: `Delete “${folder.name}”?`,
      message: 'The folder will be removed. The items inside it are kept and moved to “No folder”.',
      confirmLabel: 'Delete folder',
      danger: true,
    });
    if (ok) await attempt(() => vault.deleteFolder(folder.id), 'Folder deleted');
  }

  function openItemFromReport(id) {
    state.filter = { type: 'all' };
    state.query = '';
    searchInput.value = '';
    renderNav();
    renderList();
    select(id);
  }

  // ---- Sidebar ----

  const navEl = h('nav.sidebar-nav.scroll', { 'aria-label': 'Vault sections' });

  function navItem(filter, iconName, label, count) {
    return h(
      'button.nav-item',
      { type: 'button', 'aria-current': sameFilter(filter, state.filter) ? 'true' : null, onclick: () => setFilter(filter) },
      icon(iconName, 16),
      h('span.nav-label.truncate', label),
      count ? h('span.nav-count', count.toLocaleString()) : null,
    );
  }

  function renderNav() {
    const live = [];
    let trashed = 0;
    for (const item of vault.items) {
      if (item.deletedAt) trashed += 1;
      else live.push(item);
    }
    const count = (test) => live.reduce((total, item) => total + (test(item) ? 1 : 0), 0);
    const folders = vault.folders;

    mount(
      navEl,
      navItem({ type: 'all' }, 'layers', 'All items', live.length),
      navItem({ type: 'favorites' }, 'star', 'Favorites', count((item) => item.favorite)),
      h('div.nav-heading', 'Types'),
      ITEM_TYPES.map((type) => navItem({ type: 'kind', value: type }, TYPE_INFO[type].icon, TYPE_INFO[type].plural, count((item) => item.type === type))),
      h('div.nav-heading', h('span', 'Folders'), iconButton('plus', 'New folder', { size: 14, onclick: createFolder })),
      folders.map((folder) => {
        const more = iconButton('more', `Options for ${folder.name}`, {
          class: 'nav-more',
          size: 15,
          onclick: () =>
            openMenu(more, [
              { label: 'Rename', icon: 'edit', onSelect: () => renameFolder(folder) },
              { label: 'Delete', icon: 'trash', danger: true, onSelect: () => deleteFolder(folder) },
            ]),
        });
        return h(
          'div.nav-row',
          navItem({ type: 'folder', value: folder.id }, 'folder', folder.name, count((item) => item.folderId === folder.id)),
          more,
        );
      }),
      folders.length
        ? navItem({ type: 'unfiled' }, 'inbox', 'No folder', count((item) => !item.folderId))
        : h('p.nav-empty', 'Folders keep related items together.'),
      h('div.nav-heading'),
      navItem({ type: 'trash' }, 'trash', 'Trash', trashed),
    );
  }

  const sidebar = h(
    'aside.sidebar',
    h('header.sidebar-head', h('div.brand', h('img', { src: 'icons/logo.svg', alt: '' }), 'Vault')),
    navEl,
    h(
      'footer.sidebar-foot',
      h('button.nav-item', { type: 'button', onclick: () => (closeNav(), openGenerator({ copy })) }, icon('dice', 16), h('span.nav-label', 'Generator')),
      h(
        'button.nav-item',
        { type: 'button', onclick: () => (closeNav(), openHealth({ vault, onOpen: openItemFromReport })) },
        icon('shield-check', 16),
        h('span.nav-label', 'Vault health'),
      ),
      h(
        'button.nav-item',
        { type: 'button', onclick: () => (closeNav(), openSettings({ vault, serverInfo })) },
        icon('settings', 16),
        h('span.nav-label', 'Settings'),
      ),
      h(
        'div.account',
        h('span.account-avatar', { 'aria-hidden': 'true' }, (vault.email ?? '?')[0]),
        h('span.account-email.truncate', { title: vault.email }, vault.email),
        iconButton('lock', 'Lock vault', { onclick: () => vault.lock('manual') }),
      ),
    ),
  );

  // ---- List ----

  const titleEl = h('h1.list-title.truncate');
  const headAction = h('div');
  const searchEnd = h('div.search-end');
  const searchInput = h('input.input', {
    type: 'search',
    'aria-label': 'Search',
    autocomplete: 'off',
    spellcheck: false,
    autocapitalize: 'off',
    enterkeyhint: 'search',
    oninput: () => {
      state.query = searchInput.value;
      renderList();
      listEl.scrollTop = 0;
    },
    onkeydown: (event) => {
      if (event.key === 'ArrowDown' || event.key === 'Enter') {
        const first = listEl.querySelector('.row');
        if (!first) return;
        event.preventDefault();
        if (event.key === 'Enter') first.click();
        else first.focus();
      } else if (event.key === 'Escape' && searchInput.value) {
        event.preventDefault();
        clearSearch();
      }
    },
  });
  const listEl = h('div.list.scroll', { role: 'listbox', 'aria-label': 'Items' });

  function clearSearch() {
    searchInput.value = '';
    state.query = '';
    renderList();
    searchInput.focus();
  }

  function row(item) {
    const subtitle = itemSubtitle(item);
    return h(
      'button.row',
      {
        type: 'button',
        role: 'option',
        'aria-selected': String(item.id === state.selectedId),
        'data-id': item.id,
        tabIndex: -1,
        onclick: () => select(item.id),
      },
      itemAvatar(item),
      h('span.row-text', h('span.row-title.truncate', displayName(item)), subtitle ? h('span.row-sub.truncate', subtitle) : null),
      item.favorite ? h('span.row-star', { title: 'Favorite' }, icon('star', 13)) : null,
    );
  }

  function appendRows(upTo = listRendered + PAGE_SIZE) {
    const next = listItems.slice(listRendered, upTo);
    listEl.append(...next.map(row));
    listRendered += next.length;
  }

  function emptyState() {
    const searching = state.query.trim() !== '';
    const vaultEmpty = vault.items.length === 0;
    if (searching) {
      return h(
        'div.empty',
        h('div.empty-icon', icon('search', 22)),
        h('h3', 'No matches'),
        h('p', `Nothing in ${filterLabel(state.filter)} matches “${state.query.trim()}”.`),
        h('div.empty-actions', h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: clearSearch }, 'Clear search')),
      );
    }
    if (state.filter.type === 'trash') {
      return h(
        'div.empty',
        h('div.empty-icon', icon('trash', 22)),
        h('h3', 'Trash is empty'),
        h('p', `Deleted items wait here for ${TRASH_RETENTION_DAYS} days before they are removed for good.`),
      );
    }
    if (vaultEmpty) {
      return h(
        'div.empty',
        h('div.empty-icon', icon('key', 22)),
        h('h3', 'Your vault is ready'),
        h('p', 'Add your first login, or bring everything over from Bitwarden or your browser.'),
        h(
          'div.empty-actions',
          h('button.btn.btn-primary', { type: 'button', onclick: () => newItem('login') }, icon('plus', 16), 'Add a login'),
          h(
            'button.btn.btn-secondary',
            { type: 'button', onclick: () => openSettings({ vault, serverInfo, tab: 'import' }) },
            icon('upload', 16),
            'Import passwords',
          ),
        ),
      );
    }
    const type = state.filter.type === 'kind' ? state.filter.value : 'login';
    return h(
      'div.empty',
      h('div.empty-icon', icon(state.filter.type === 'favorites' ? 'star' : state.filter.type === 'kind' ? TYPE_INFO[type].icon : 'folder', 22)),
      h('h3', 'Nothing here yet'),
      h('p', state.filter.type === 'favorites' ? 'Star the items you use most to find them here.' : `No items in ${filterLabel(state.filter)}.`),
      state.filter.type === 'favorites'
        ? null
        : h(
            'div.empty-actions',
            h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: () => newItem(type) }, icon('plus', 15), `New ${TYPE_INFO[type].label.toLowerCase()}`),
          ),
    );
  }

  function renderList({ keepScroll = false } = {}) {
    const previous = keepScroll ? { top: listEl.scrollTop, rendered: listRendered } : null;
    listItems = visibleItems();
    listRendered = 0;
    const { filter } = state;
    const label = filterLabel(filter);
    titleEl.textContent = label;
    searchInput.placeholder = filter.type === 'all' ? 'Search vault' : `Search ${label}`;

    const trashCount = filter.type === 'trash' ? listItems.length : 0;
    const newButton = h('button.btn.btn-primary.btn-sm', { type: 'button', 'aria-haspopup': 'menu' }, icon('plus', 15), 'New');
    newButton.addEventListener('click', () =>
      openMenu(
        newButton,
        ITEM_TYPES.map((type) => ({ label: TYPE_INFO[type].label, icon: TYPE_INFO[type].icon, onSelect: () => newItem(type) })),
        { align: 'end' },
      ),
    );
    mount(
      headAction,
      filter.type === 'trash'
        ? trashCount && !state.query
          ? h('button.btn.btn-danger-ghost.btn-sm', { type: 'button', onclick: emptyTrash }, 'Empty trash')
          : null
        : newButton,
    );
    mount(searchEnd, state.query ? iconButton('x', 'Clear search', { size: 14, onclick: clearSearch }) : h('kbd', { title: 'Press / to search' }, '/'));

    if (!listItems.length) {
      mount(listEl, emptyState());
      return;
    }

    const sortButton = h(
      'button.btn.btn-ghost',
      { type: 'button', 'aria-haspopup': 'menu', title: 'Change sort order' },
      state.sort === 'updated' ? 'Recently updated' : 'Name',
      icon('sort', 12),
    );
    sortButton.addEventListener('click', () =>
      openMenu(
        sortButton,
        [
          { heading: 'Sort by' },
          { label: 'Name', checked: state.sort === 'name', onSelect: () => setSort('name') },
          { label: 'Recently updated', checked: state.sort === 'updated', onSelect: () => setSort('updated') },
        ],
        { align: 'end' },
      ),
    );
    mount(
      listEl,
      h(
        'div.list-meta',
        h('span', state.query.trim() ? plural(listItems.length, 'result') : plural(listItems.length, 'item')),
        filter.type === 'trash' || state.query.trim() ? null : sortButton,
      ),
    );
    appendRows(Math.max(PAGE_SIZE, previous?.rendered ?? 0));
    markSelection();
    if (previous) listEl.scrollTop = previous.top;
  }

  function setSort(sort) {
    state.sort = sort;
    prefs.set('sort', sort);
    renderList();
  }

  /**
   * Highlights the selected row. The list is a single tab stop: the selected
   * row (or the first one) takes focus from Tab, and the arrow keys move within.
   */
  function markSelection(reveal = false) {
    let tabStop = null;
    for (const el of listEl.querySelectorAll('.row')) {
      const selected = el.dataset.id === state.selectedId;
      el.setAttribute('aria-selected', String(selected));
      el.tabIndex = -1;
      if (selected) tabStop = el;
      if (selected && reveal) el.scrollIntoView({ block: 'nearest' });
    }
    tabStop ??= listEl.querySelector('.row');
    if (tabStop) tabStop.tabIndex = 0;
  }

  listEl.addEventListener('scroll', () => {
    if (listRendered < listItems.length && listEl.scrollTop + listEl.clientHeight > listEl.scrollHeight - 800) appendRows();
  });

  listEl.addEventListener('keydown', (event) => {
    const current = event.target.closest?.('.row');
    if (!current) return;
    let target = null;
    if (event.key === 'ArrowDown') target = current.nextElementSibling;
    else if (event.key === 'ArrowUp') target = current.previousElementSibling;
    else if (event.key === 'Home') target = listEl.querySelector('.row');
    else if (event.key === 'End') target = listEl.querySelector('.row:last-of-type');
    else return;
    event.preventDefault();
    if (target?.classList.contains('row')) {
      target.focus();
      target.click();
    } else if (event.key === 'ArrowUp') {
      searchInput.focus();
    }
  });

  const listPane = h(
    'main.list-pane',
    h(
      'header.list-head',
      iconButton('menu', 'Open menu', { class: 'menu-btn', size: 18, onclick: () => shell.classList.add('is-nav-open') }),
      titleEl,
      headAction,
    ),
    h('div.search', { role: 'search' }, icon('search', 15), searchInput, searchEnd),
    listEl,
  );

  // ---- Detail ----

  const detailPane = h('section.detail-pane.scroll', { 'aria-label': 'Item details' });

  function detailPlaceholder() {
    return h(
      'div.detail-empty',
      h('img', { src: 'icons/logo.svg', alt: '' }),
      h('h3', vault.items.length ? 'Select an item' : 'Welcome to your vault'),
      h('p', vault.items.length ? 'Choose something from the list to see its details.' : 'Everything you add is encrypted on this device before it is saved.'),
      h('div.shortcuts', h('span', h('kbd', '/'), 'Search'), h('span', h('kbd', '↑'), h('kbd', '↓'), 'Browse'), h('span', h('kbd', 'Esc'), 'Clear')),
    );
  }

  function renderDetail(animate) {
    if (state.editor) {
      disposeDetail?.();
      disposeDetail = null;
      shown = null;
      const session = state.editor;
      const editor = itemEditor({
        item: session.item,
        isNew: session.isNew,
        vault,
        onDirty: () => (session.dirty = true),
        onSave: saveDraft,
        onCancel: cancelEdit,
        createFolder,
        copy,
      });
      mount(detailPane, editor.el);
      detailPane.scrollTop = 0;
      editor.focus();
      return;
    }

    const item = state.selectedId ? vault.item(state.selectedId) : null;
    const folderName = item ? (vault.folder(item.folderId)?.name ?? '') : '';
    if (shown && shown.item === item && shown.folderName === folderName) return; // nothing changed

    disposeDetail?.();
    disposeDetail = null;
    if (!item) {
      state.selectedId = null;
      shown = { item: null, folderName: '' };
      mount(detailPane, detailPlaceholder());
      showPane('list');
      return;
    }

    const sameItem = shown?.item?.id === item.id;
    shown = { item, folderName };
    const view = itemView({
      item,
      folderName,
      animate: animate && !sameItem,
      actions: {
        copy,
        back: () => showPane('list'),
        edit: () => editItem(item),
        clone: () => cloneItem(item),
        favorite: (on) => attempt(() => vault.setFavorite(item.id, on)),
        trash: () => trashItem(item),
        restore: () => attempt(() => vault.restoreItems([item.id]), 'Item restored'),
        remove: () => deleteForever(item),
      },
    });
    disposeDetail = view.dispose;
    const top = sameItem ? detailPane.scrollTop : 0;
    mount(detailPane, view.el);
    detailPane.scrollTop = top;
  }

  // ---- Wiring ----

  const shell = h(
    'div.shell',
    { 'data-pane': 'list' },
    sidebar,
    h('button.scrim', { type: 'button', 'aria-label': 'Close menu', tabIndex: -1, onclick: closeNav }),
    listPane,
    detailPane,
  );

  function onVaultChange() {
    searchIndex = new WeakMap();
    if (state.filter.type === 'folder' && !vault.folder(state.filter.value)) state.filter = { type: 'all' };
    renderNav();
    renderList({ keepScroll: true });
    if (!state.editor) renderDetail(false);
  }

  function onKeydown(event) {
    if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
    if (document.querySelector('dialog[open], .menu:popover-open')) return;
    const typing = event.target.closest?.('input, textarea, select, [contenteditable]');
    if (event.key === '/' && !typing) {
      event.preventDefault();
      showPane('list');
      searchInput.focus();
      searchInput.select();
    } else if (event.key === 'Escape' && shell.classList.contains('is-nav-open')) {
      closeNav();
    }
  }

  function onBeforeUnload(event) {
    if (state.editor?.dirty) event.preventDefault();
  }

  vault.addEventListener('change', onVaultChange);
  document.addEventListener('keydown', onKeydown);
  window.addEventListener('beforeunload', onBeforeUnload);
  window.addEventListener('popstate', onPopState);

  mount(root, shell);
  renderNav();
  renderList();
  renderDetail(false);

  return function teardown() {
    vault.removeEventListener('change', onVaultChange);
    document.removeEventListener('keydown', onKeydown);
    window.removeEventListener('beforeunload', onBeforeUnload);
    window.removeEventListener('popstate', onPopState);
    if (history.state === DETAIL_ENTRY) history.back();
    disposeDetail?.();
    state.editor = null;
    mount(root);
  };
}
