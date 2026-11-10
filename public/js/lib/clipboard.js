// Copying secrets to the clipboard, and wiping them again after a delay.
//
// A web page cannot read the clipboard without asking, so the wipe cannot
// check that the clipboard still holds what was copied; it simply empties it.
// Two rules keep that from being a nuisance: a wipe that the browser refuses
// is only retried for a few minutes, and never long after the fact, when the
// clipboard has probably been used for something else.

const RETRY_WINDOW_MS = 5 * 60 * 1000;

let clearTimer = null;
let retryUntil = 0; // while Date.now() is below this, a refused wipe is retried

async function wipe() {
  clearTimer = null;
  try {
    await navigator.clipboard.writeText('');
    retryUntil = 0;
  } catch {
    // Browsers restrict clipboard writes: Chrome and Edge need the page to
    // have focus, Safari and Firefox need a click or key press. Try again
    // when the user comes back to the page, if that is soon.
    if (!retryUntil) retryUntil = Date.now() + RETRY_WINDOW_MS;
  }
}

function retry() {
  if (!retryUntil) return;
  if (Date.now() > retryUntil) retryUntil = 0;
  else wipe();
}

if (typeof window !== 'undefined') {
  // Returning to the page, or any of the gestures browsers accept as permission to write.
  for (const type of ['focus', 'pointerdown', 'pointerup', 'touchend', 'click', 'keydown', 'keyup']) {
    window.addEventListener(type, retry, true);
  }
}

/**
 * @param {string} text
 * @param {number} clearAfterSeconds 0 leaves the clipboard alone
 */
export async function copyText(text, clearAfterSeconds = 0) {
  await navigator.clipboard.writeText(text);
  clearTimeout(clearTimer);
  clearTimer = null;
  retryUntil = 0;
  if (clearAfterSeconds > 0) clearTimer = setTimeout(wipe, clearAfterSeconds * 1000);
}

/** Wipes immediately if something we copied is still waiting to be cleared. */
export function clearClipboardNow() {
  if (clearTimer === null && !retryUntil) return;
  clearTimeout(clearTimer);
  wipe();
}
