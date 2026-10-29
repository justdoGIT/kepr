'use strict';
// Credential metadata and lock state from the kepr CLI's JSON output
// (`kepr ls --json`, `kepr status --json`). There is no value anywhere in
// these inputs, so none can be shown. Copying a value goes through
// `kepr copy NAME`, which puts it on the clipboard and clears it later.

const NAME = /^[A-Za-z0-9_]{1,128}$/;

/** Credentials from `kepr ls --json`, sorted by name. Throws on a daemon error or a malformed reply. */
function parseList(text) {
  const reply = JSON.parse(text);
  if (reply.kind === 'err') throw new Error(typeof reply.error === 'string' ? reply.error : 'kepr failed');
  if (reply.kind !== 'list_ok' || !Array.isArray(reply.credentials)) throw new Error('unexpected reply from kepr');
  return reply.credentials
    .filter((c) => c && typeof c.name === 'string')
    .map((c) => ({
      name: c.name,
      modified: String(c.modified ?? ''),
      expiresAt: c.expires_at ?? null,
      recordType: c.record_type ?? null,
      tags: Array.isArray(c.tags) ? c.tags.map(String) : [],
      sealed: c.sealed === true,
      requiresConsent: c.requires_consent === true,
      requiresFido2: c.requires_fido2 === true,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** {state, detail} from `kepr status --json`; `state` is locked | unlocked | offline. */
function parseStatus(text) {
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    return { state: 'offline', detail: 'kepr gave no JSON' };
  }
  if (reply.kind === 'err') return { state: 'offline', detail: String(reply.error ?? 'kepr failed') };
  if (reply.kind !== 'status_ok') return { state: 'offline', detail: 'unexpected reply from kepr' };
  if (reply.locked) return { state: 'locked', detail: 'Run `kepr unlock` in a terminal.' };
  return { state: 'unlocked', detail: reply.password_protected ? 'unlocked' : 'open (no passphrase set)' };
}

/** One-line subtitle for a list row. */
function subtitle(c) {
  const bits = [c.recordType || 'value'];
  if (c.sealed) bits.push('sealed');
  if (c.tags.length) bits.push(c.tags.join(','));
  bits.push(c.expiresAt ? `expires ${c.expiresAt}` : 'no expiry');
  return bits.join(' · ');
}

/** Can `c` be copied? Sealed keys are write-only: only an agent gate can use them. */
function copyable(c) {
  return !c.sealed;
}

/** A name that is safe as one argv element. */
function validName(n) {
  return NAME.test(n);
}

module.exports = { parseList, parseStatus, subtitle, copyable, validName };
