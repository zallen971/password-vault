// Copying secrets to the clipboard, and wiping them again after a delay.

let clearTimer = null;
let clearWhenFocused = false;

async function wipe() {
  clearTimer = null;
  try {
    await navigator.clipboard.writeText('');
    clearWhenFocused = false;
  } catch {
    // Browsers only allow clipboard writes while the page has focus. If the
    // user is in another window, finish the job as soon as they come back.
    clearWhenFocused = true;
  }
}

if (typeof window !== 'undefined') {
  window.addEventListener('focus', () => {
    if (clearWhenFocused) wipe();
  });
}

/**
 * @param {string} text
 * @param {number} clearAfterSeconds 0 leaves the clipboard alone
 */
export async function copyText(text, clearAfterSeconds = 0) {
  await navigator.clipboard.writeText(text);
  clearTimeout(clearTimer);
  clearTimer = null;
  clearWhenFocused = false;
  if (clearAfterSeconds > 0) clearTimer = setTimeout(wipe, clearAfterSeconds * 1000);
}

/** Wipes immediately if something we copied is still waiting to be cleared. */
export function clearClipboardNow() {
  if (clearTimer === null && !clearWhenFocused) return;
  clearTimeout(clearTimer);
  wipe();
}
