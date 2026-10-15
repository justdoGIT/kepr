'use strict';
// Credential metadata for hovers, listed at most once per `ttlMs` (each
// list is one audited daemon request), and the Node SDK client.

class CredCache {
  constructor(client, { ttlMs = 15000, now = Date.now } = {}) {
    this.client = client;
    this.ttlMs = ttlMs;
    this.now = now;
    this.clear();
  }

  clear() {
    this.at = -Infinity;
    this.pending = null;
  }

  /** All credentials' metadata (cached). */
  async all() {
    if (!this.pending || this.now() - this.at >= this.ttlMs) {
      this.at = this.now();
      this.pending = this.client.credentials().catch((e) => {
        this.clear();
        throw e;
      });
    }
    return this.pending;
  }

  /** Metadata for one name, or null. */
  async info(name) {
    const n = String(name).toUpperCase();
    return (await this.all()).find((c) => c.name === n) || null;
  }
}

/** The kepr Node SDK: installed package, or the copy in this repository. */
function loadSdk() {
  try {
    return require('kepr-client');
  } catch {
    return require('../../../sdk/node');
  }
}

function newClient(socketPath) {
  const { Client } = loadSdk();
  return new Client(socketPath ? { path: socketPath } : {});
}

module.exports = { CredCache, newClient };
