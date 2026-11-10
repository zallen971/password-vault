// Rules for master passwords.

import { estimateStrength } from './strength.js';

export const MIN_MASTER_PASSWORD_LENGTH = 12;

/** Returns why a master password cannot be used, or null if it is acceptable. */
export function masterPasswordProblem(password, confirmation) {
  if ([...password].length < MIN_MASTER_PASSWORD_LENGTH) {
    return `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters. A few unrelated words work well.`;
  }
  if (estimateStrength(password).score === 0) {
    return 'That password is too easy to guess. Try a longer phrase of several unrelated words.';
  }
  if (confirmation !== undefined && password !== confirmation) return 'The two passwords do not match.';
  return null;
}

/** Acceptable, but worth a second thought before it guards everything. */
export const isWeakMasterPassword = (password) => estimateStrength(password).score <= 1;

export const WEAK_MASTER_PASSWORD_WARNING = Object.freeze({
  title: 'Use a weak master password?',
  message:
    'This password would not take long to guess, and it is the only thing protecting your vault. ' +
    'A phrase of four or five unrelated words is much stronger and still easy to remember.',
  confirmLabel: 'Use it anyway',
  cancelLabel: 'Choose another',
  danger: true,
});
