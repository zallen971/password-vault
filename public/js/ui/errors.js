// Turns errors into messages a person can act on.

import { ApiError } from '../lib/api.js';
import { VaultError } from '../lib/vault.js';
import { ImportError } from '../lib/importers.js';

function wait(seconds) {
  if (!seconds) return 'a little while';
  if (seconds < 90) return `${seconds} second${seconds === 1 ? '' : 's'}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minutes`;
}

export function describeError(error) {
  if (error instanceof ImportError) return error.message;

  if (error instanceof VaultError) {
    switch (error.code) {
      case 'locked':
        return 'Your vault is locked. Unlock it and try again.';
      case 'conflict':
        return 'This was changed on another device. The latest version has been loaded.';
      case 'wrong_password':
        return 'That master password is not correct.';
      case 'damaged_key':
        return 'This vault’s encryption key could not be opened. The data on the server may be damaged.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  if (error instanceof ApiError) {
    switch (error.code) {
      case 'network':
        return 'Can’t reach the server. Check your connection and try again.';
      case 'invalid_credentials':
        return 'Incorrect email or master password.';
      case 'too_many_attempts':
      case 'too_many_requests':
        return `Too many attempts. Try again in ${wait(error.data.retryAfter)}.`;
      case 'signups_closed':
        return 'This server is not accepting new accounts.';
      case 'email_taken':
        return 'An account with this email already exists. Try logging in instead.';
      case 'unauthorized':
        return 'Your session has ended. Unlock your vault again.';
      case 'record_too_large':
      case 'payload_too_large':
        return 'That is too large to save. Try shortening the notes.';
      case 'vault_full':
        return 'This vault has reached its size limit.';
      case 'bad_response':
        return 'The server sent an unexpected reply. If you use a proxy or VPN, check that it is passing requests through.';
      default:
        return error.status >= 500 ? 'The server ran into a problem. Please try again.' : 'That request was not accepted. Please try again.';
    }
  }

  return 'Something went wrong. Please try again.';
}
