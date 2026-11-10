// Thin client for the server's JSON API. Nothing sensitive passes through
// here in the clear: only the derived auth key and already-encrypted records.

export class ApiError extends Error {
  /**
   * @param {number} status HTTP status, or 0 if the server could not be reached
   * @param {string} code   machine-readable reason, e.g. "invalid_credentials"
   * @param {object} [data] any extra fields the server sent
   */
  constructor(status, code, data) {
    super(code);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.data = data ?? {};
  }
}

export class Api {
  #token = null;
  #base;

  /** Called when the server rejects our session (expired or signed out elsewhere). */
  onUnauthorized = null;

  constructor(base = '') {
    this.#base = base;
  }

  setToken(token) {
    this.#token = token;
  }

  async #request(method, path, body, { auth = false } = {}) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth) {
      if (!this.#token) throw new ApiError(401, 'unauthorized');
      headers.Authorization = `Bearer ${this.#token}`;
    }
    const token = this.#token;

    let response;
    try {
      response = await fetch(this.#base + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch {
      throw new ApiError(0, 'network');
    }

    let data = null;
    if (response.status !== 204) {
      try {
        data = await response.json();
      } catch {
        data = null;
      }
    }
    if (!response.ok) {
      // "unauthorized" means the session itself is gone; a wrong password
      // on a sensitive action is reported as "invalid_credentials" instead.
      if (auth && data?.error === 'unauthorized' && token === this.#token) this.onUnauthorized?.();
      throw new ApiError(response.status, data?.error ?? 'http_error', data);
    }
    // A 200 that is not JSON means something in between (a proxy, a captive
    // portal) answered instead of the vault server.
    if (response.status !== 204 && data === null) throw new ApiError(response.status, 'bad_response');
    return data;
  }

  config() {
    return this.#request('GET', '/api/config');
  }

  prelogin(email) {
    return this.#request('POST', '/api/auth/prelogin', { email });
  }

  register(fields) {
    return this.#request('POST', '/api/auth/register', fields);
  }

  login(email, authKey) {
    return this.#request('POST', '/api/auth/login', { email, authKey });
  }

  logout() {
    return this.#request('POST', '/api/auth/logout', undefined, { auth: true });
  }

  getVault() {
    return this.#request('GET', '/api/vault', undefined, { auth: true });
  }

  getRevision() {
    return this.#request('GET', '/api/vault/revision', undefined, { auth: true });
  }

  sync(changes) {
    return this.#request('POST', '/api/vault/sync', changes, { auth: true });
  }

  changePassword(fields) {
    return this.#request('POST', '/api/account/password', fields, { auth: true });
  }

  deleteAccount(authKey) {
    return this.#request('POST', '/api/account/delete', { authKey }, { auth: true });
  }
}
