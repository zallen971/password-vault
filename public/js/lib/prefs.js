// Per-device preferences, kept in localStorage. Nothing secret is stored
// here: only display and convenience settings, and the last email used.

const STORAGE_KEY = 'vault.prefs.v1';

const DEFAULTS = Object.freeze({
  theme: 'system', // 'system' | 'light' | 'dark'
  autoLockMinutes: 15, // 0 = never
  clipboardClearSeconds: 30, // 0 = never
  rememberEmail: true,
  email: '',
  sort: 'name', // 'name' | 'updated'
  generator: null, // last-used generator options
});

function read() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

let cache = null;
const listeners = new Set();

export const prefs = {
  get(key) {
    cache ??= read();
    return Object.hasOwn(cache, key) && cache[key] !== undefined ? cache[key] : DEFAULTS[key];
  },

  set(key, value) {
    // Start from what is stored now rather than this tab's copy, so a setting
    // changed in another tab is not undone by saving a different one here.
    cache = { ...cache, ...read(), [key]: value };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(cache));
    } catch {
      /* private browsing or storage disabled: keep the value for this session only */
    }
    for (const listener of listeners) listener(key, value);
  },

  /** Calls `listener(key, value)` after every change. Returns an unsubscribe function. */
  subscribe(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};

// Pick up settings changed in another tab straight away (a tightened
// auto-lock time should apply everywhere, not only where it was set).
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key !== null && event.key !== STORAGE_KEY) return;
    const before = cache ?? {};
    cache = read();
    for (const key of new Set([...Object.keys(before), ...Object.keys(cache)])) {
      if (JSON.stringify(before[key]) !== JSON.stringify(cache[key])) {
        for (const listener of listeners) listener(key, prefs.get(key));
      }
    }
  });
}

/** Applies the chosen theme to the page. */
export function applyTheme() {
  const choice = prefs.get('theme');
  const dark = choice === 'dark' || (choice !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
}
