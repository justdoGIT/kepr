'use strict';
// `kepr://NAME` and `kepr://NAME/field` references, matched exactly like
// `kepr inject` (src/cli_inject.rs): NAME is [A-Za-z0-9_]+ (upper-cased),
// a field is lower-case [a-z0-9_]+; anything else ends the reference.

const REF = /kepr:\/\/([A-Za-z0-9_]+)(?:\/([a-z0-9_]+))?/g;
const MAX_NAME = 128; // the daemon's limit

/** Every reference in one line: {name, field|null, start, end} (end exclusive). */
function findReferences(line) {
  const out = [];
  for (const m of line.matchAll(REF)) {
    if (m[1].length > MAX_NAME) continue;
    out.push({ name: m[1].toUpperCase(), field: m[2] || null, start: m.index, end: m.index + m[0].length });
  }
  return out;
}

/** The reference covering `character`, or null. */
function referenceAt(line, character) {
  return findReferences(line).find((r) => character >= r.start && character < r.end) || null;
}

module.exports = { findReferences, referenceAt };
