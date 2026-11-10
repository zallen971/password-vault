// Copying secrets to the clipboard, and wiping them again after a delay.

let clearTimer = null;
let clearWhenAllowed = false;

async function wipe() {
  clearTimer = null;
  try {
    await navigator.clipboard.writeText('');
    clearWhenAllowed = false;
  } catch {
    // Browsers restrict clipboard writes: Chrome and Edge need the page to
    // have focus, Safari and Firefox need a click or key press. If the wipe
    // is refused, finish the job the moment the user comes back to the page.
    clearWhenAllowed = true;
  }
}

if (typeof window !== 'undefined') {
  for (const type of ['focus', 'pointerdown', 'keydown']) {
    window.addEventListener(
      type,
      () => {
        if (clearWhenAllowed) wipe();
      },
      true,
    );
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
  clearWhenAllowed = false;
  if (clearAfterSeconds > 0) clearTimer = setTimeout(wipe, clearAfterSeconds * 1000);
}

/** Wipes immediately if something we copied is still waiting to be cleared. */
export function clearClipboardNow() {
  if (clearTimer === null && !clearWhenAllowed) return;
  clearTimeout(clearTimer);
  wipe();
}
