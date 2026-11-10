// Application entry point: decides between the locked and unlocked screens,
// and looks after everything that outlives a single screen (auto-lock,
// background sync, theme, and keeping several tabs in step).

import { Api } from './lib/api.js';
import { Vault } from './lib/vault.js';
import { applyTheme, prefs } from './lib/prefs.js';
import { clearClipboardNow } from './lib/clipboard.js';
import { closeAllDialogs } from './ui/dialog.js';
import { closeMenus } from './ui/menu.js';
import { clearToasts, toast } from './ui/toast.js';
import { h } from './ui/dom.js';
import { renderAuth, renderUnsupported } from './views/auth.js';
import { renderApp } from './views/app.js';

const SYNC_INTERVAL_MS = 30_000;
const LOCK_NOTICES = {
  idle: 'Your vault was locked after a period of inactivity.',
  expired: 'Your session ended. Unlock your vault to continue.',
  deleted: 'Your account and everything in it has been deleted.',
};

const root = document.getElementById('app');
const base = new URL('.', location.href).pathname.replace(/\/$/, '');
const api = new Api(base);
const vault = new Vault(api);

let closeApp = null;
let lastActivity = Date.now();
let serverInfo = null;

// Other tabs of this browser: lock together, and pick up each other's changes.
const channel = 'BroadcastChannel' in window ? new BroadcastChannel('vault') : null;

applyTheme();
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);
prefs.subscribe((key) => {
  if (key === 'theme') applyTheme();
});

async function showLocked(notice) {
  let config = null;
  try {
    config = await api.config();
    serverInfo = config;
  } catch {
    config = null;
  }
  if (vault.unlocked) return; // unlocked in the meantime, e.g. by a fast double submit
  renderAuth(root, { vault, config, notice, onUnlocked: showUnlocked, onRetry: () => showLocked(notice) });
}

function showUnlocked() {
  lastActivity = Date.now();
  closeApp = renderApp(root, { vault, serverInfo });
  if (vault.unreadable) {
    toast(`${vault.unreadable} item${vault.unreadable === 1 ? '' : 's'} could not be decrypted and ${vault.unreadable === 1 ? 'is' : 'are'} not shown.`, {
      type: 'error',
      duration: 9000,
    });
  }
}

vault.addEventListener('lock', (event) => {
  const { reason } = event.detail;
  closeApp?.();
  closeApp = null;
  closeAllDialogs();
  closeMenus();
  clearToasts();
  clearClipboardNow();
  if (reason === 'manual' || reason === 'idle') channel?.postMessage({ type: 'lock' });
  showLocked(LOCK_NOTICES[reason]);
});

vault.addEventListener('change', () => channel?.postMessage({ type: 'changed' }));

channel?.addEventListener('message', (event) => {
  // Activity in any tab counts for all of them, so an idle background tab
  // does not lock the vault while another tab is in use.
  if (event.data?.type === 'active') lastActivity = Date.now();
  if (!vault.unlocked) return;
  if (event.data?.type === 'lock') vault.lock('manual');
  else if (event.data?.type === 'changed') checkForChanges();
});

// ---- Auto-lock ----

const ACTIVITY_SHARE_MS = 10_000;
let lastShared = 0;

function noteActivity() {
  lastActivity = Date.now();
  if (lastActivity - lastShared >= ACTIVITY_SHARE_MS) {
    lastShared = lastActivity;
    channel?.postMessage({ type: 'active' });
  }
}

for (const type of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
  window.addEventListener(type, noteActivity, { capture: true, passive: true });
}

setInterval(() => {
  const minutes = Number(prefs.get('autoLockMinutes'));
  if (vault.unlocked && minutes > 0 && Date.now() - lastActivity >= minutes * 60_000) vault.lock('idle');
}, 5000);

// ---- Background sync ----

let checking = false;
async function checkForChanges() {
  if (checking || !vault.unlocked || document.visibilityState !== 'visible') return;
  checking = true;
  try {
    await vault.checkForChanges();
  } catch {
    /* offline or locked meanwhile; the next attempt will sort it out */
  } finally {
    checking = false;
  }
}

setInterval(checkForChanges, SYNC_INTERVAL_MS);
document.addEventListener('visibilitychange', checkForChanges);
window.addEventListener('focus', checkForChanges);
window.addEventListener('online', checkForChanges);

// ---- Start ----

if (!window.isSecureContext || !window.crypto?.subtle) {
  renderUnsupported(root, {
    title: 'A secure connection is required',
    lines: [
      'Vault encrypts everything in your browser, and browsers only allow that on secure pages.',
      ['Open Vault over ', h('code', 'https://'), ' or, on the computer running it, at ', h('code', 'http://localhost'), '.'],
    ],
  });
} else if (!('showModal' in HTMLDialogElement.prototype) || !('showPopover' in HTMLElement.prototype)) {
  renderUnsupported(root, {
    title: 'Please update your browser',
    lines: ['Vault needs a current version of Chrome, Edge, Firefox or Safari.'],
  });
} else {
  showLocked();
}
