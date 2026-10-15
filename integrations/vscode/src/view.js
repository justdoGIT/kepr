'use strict';
// Text shown by the extension. Inputs are credential metadata (the Node
// SDK's `credentials()` objects) and the daemon status; there is no value
// anywhere in this module's inputs, so none can be shown.

function flags(c) {
  const out = [];
  if (c.sealed) out.push('sealed (write-only: only an agent gate can use it)');
  if (c.requiresConsent) out.push('consent prompt on every read');
  if (c.requiresFido2) out.push('FIDO2 touch on every read');
  return out;
}

/** Markdown for a hover over `ref` ({name, field}); `info` null = unknown name. */
function hoverMarkdown(ref, info) {
  const target = `kepr://${ref.name}${ref.field ? `/${ref.field}` : ''}`;
  if (!info) {
    return `**${target}**\n\nNo credential named \`${ref.name}\` in kepr.`;
  }
  const lines = [`**${target}**`, ''];
  lines.push(`- type: ${info.recordType || 'value'}`);
  if (ref.field) {
    lines.push(
      info.recordType
        ? `- field: \`${ref.field}\``
        : `- field \`${ref.field}\`: not a record, so this reference will not resolve`,
    );
  }
  const tags = Array.isArray(info.tags) ? info.tags : [];
  lines.push(`- tags: ${tags.length ? tags.join(', ') : 'none'}`);
  lines.push(`- expires: ${info.expiresAt || 'never'}`);
  lines.push(`- modified: ${info.modified}`);
  for (const f of flags(info)) lines.push(`- ${f}`);
  if (info.sealed && Array.isArray(info.boundHosts) && info.boundHosts.length) {
    lines.push(`- bound to: ${info.boundHosts.join(', ')}`);
  }
  lines.push('', '_kepr never shows values here._');
  return lines.join('\n');
}

/** Status bar text/tooltip from a `status()` reply, or the error reaching it. */
function statusText(status, error) {
  if (error || !status) {
    return { text: '$(warning) kepr: offline', tooltip: `kepr daemon unreachable: ${error ? error.message : 'no reply'}` };
  }
  if (status.locked) {
    return { text: '$(lock) kepr: locked', tooltip: 'The vault is locked. Run `kepr unlock` in a terminal.' };
  }
  return {
    text: '$(unlock) kepr: unlocked',
    tooltip: status.password_protected ? 'The vault is unlocked.' : 'The vault is open (no passphrase set; see `kepr lock`).',
  };
}

/** Quick pick entries, sorted by name. */
function pickItems(creds) {
  return [...creds]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((c) => {
      const bits = [c.recordType || 'value'];
      if (c.sealed) bits.push('sealed');
      if (Array.isArray(c.tags) && c.tags.length) bits.push(c.tags.join(','));
      return {
        label: c.name,
        description: bits.join(' · '),
        detail: `${c.expiresAt ? `expires ${c.expiresAt}` : 'no expiry'} · modified ${c.modified}`,
      };
    });
}

module.exports = { hoverMarkdown, statusText, pickItems };
