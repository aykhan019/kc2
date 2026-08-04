// Thin client for the npm registry dist-tag endpoints, shared by both roles.
//
//   GET    /-/package/<pkg>/dist-tags          (anonymous read)
//   PUT    /-/package/<pkg>/dist-tags/<tag>    (auth; body = JSON string of version)
//   DELETE /-/package/<pkg>/dist-tags/<tag>    (auth)
//
// Behavior: request timeout, retries with exponential backoff on network
// errors and 5xx responses, clear non-retriable errors on 401/403/404.

export class RegistryError extends Error {
  constructor(message, { status = 0, retriable = false, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'RegistryError';
    this.status = status;
    this.retriable = retriable;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class RegistryClient {
  /**
   * @param {object} opts
   * @param {string} opts.registryUrl  e.g. http://localhost:4873
   * @param {string} opts.packageName  e.g. my-package (scoped names supported)
   * @param {string} [opts.token]      bearer token (writes only)
   * @param {number} [opts.timeoutMs]  per-request timeout
   * @param {number} [opts.maxRetries] retries after the first attempt
   * @param {number} [opts.baseDelayMs] base for exponential backoff
   * @param {Function} [opts.fetchImpl] fetch implementation (for tests)
   * @param {object} [opts.logger]
   */
  constructor({
    registryUrl,
    packageName,
    token = '',
    timeoutMs = 10_000,
    maxRetries = 3,
    baseDelayMs = 500,
    fetchImpl = globalThis.fetch,
    logger = null,
  }) {
    if (!registryUrl) throw new Error('RegistryClient: registryUrl is required');
    if (!packageName) throw new Error('RegistryClient: packageName is required');
    this.base = registryUrl.replace(/\/+$/, '');
    this.packageName = packageName;
    this.token = token;
    this.timeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
    this.baseDelayMs = baseDelayMs;
    this.fetchImpl = fetchImpl;
    this.logger = logger;
  }

  #url(pathSuffix = '') {
    return `${this.base}/-/package/${encodeURIComponent(this.packageName)}/dist-tags${pathSuffix}`;
  }

  async #request(pathSuffix, { method = 'GET', body } = {}) {
    const headers = {
      accept: 'application/json',
      'user-agent': 'npm-c2-lab/1.0 (educational research)',
    };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.token) headers.authorization = `Bearer ${this.token}`;

    let attempt = 0;
    for (;;) {
      try {
        const res = await this.fetchImpl(this.#url(pathSuffix), {
          method,
          headers,
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (res.status >= 500) {
          throw new RegistryError(`registry server error: HTTP ${res.status}`, {
            status: res.status,
            retriable: true,
          });
        }
        if (res.status === 401 || res.status === 403) {
          throw new RegistryError(
            `authentication failed (HTTP ${res.status}) — check NPM_C2_TOKEN and registry permissions`,
            { status: res.status },
          );
        }
        if (res.status === 404) {
          throw new RegistryError(
            `not found (HTTP 404) — package "${this.packageName}" (or the tag) does not exist on ${this.base}`,
            { status: res.status },
          );
        }
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          throw new RegistryError(`registry rejected ${method} request: HTTP ${res.status} ${text}`.trim(), {
            status: res.status,
          });
        }
        return res;
      } catch (err) {
        let regErr;
        if (err instanceof RegistryError) {
          regErr = err;
        } else if (err && err.name === 'TimeoutError') {
          regErr = new RegistryError(`request timed out after ${this.timeoutMs}ms`, {
            retriable: true,
            cause: err,
          });
        } else if (err && err.name === 'AbortError') {
          regErr = new RegistryError('request aborted', { retriable: true, cause: err });
        } else {
          // undici's "fetch failed" hides the real reason in `cause`
          // (ENOTFOUND, ECONNREFUSED, CERT_*, proxy refusal, ...). Surface it.
          const c = err.cause;
          const detail = c ? ` [${c.code ?? c.message ?? String(c)}]` : '';
          regErr = new RegistryError(`network error contacting registry: ${err.message}${detail}`, {
            retriable: true,
            cause: err,
          });
        }
        if (!regErr.retriable || attempt >= this.maxRetries) throw regErr;
        const delay = this.baseDelayMs * 2 ** attempt;
        this.logger?.debug(`registry ${method} failed (${regErr.message}); retry ${attempt + 1}/${this.maxRetries} in ${delay}ms`);
        await sleep(delay);
        attempt++;
      }
    }
  }

  /** @returns {Promise<Record<string, string>>} map of tag name -> version */
  async getDistTags() {
    const res = await this.#request('');
    return res.json();
  }

  /**
   * Create or move a dist-tag. The value MUST be an existing version of the
   * package — this lab always uses PINNED_VERSION.
   */
  async setDistTag(tag, version) {
    await this.#request(`/${encodeURIComponent(tag)}`, {
      method: 'PUT',
      body: JSON.stringify(version),
    });
  }

  async deleteDistTag(tag) {
    await this.#request(`/${encodeURIComponent(tag)}`, { method: 'DELETE' });
  }
}
