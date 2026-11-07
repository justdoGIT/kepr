#!/usr/bin/env node
// gen-rust-api.mjs — generate Fumadocs MDX API pages from rustdoc JSON.
//
// Pipeline
//   1. `cargo +nightly rustdoc --bin <bin> -- -Z unstable-options --output-format json`
//      — writes target/doc/<bin>.json per binary.
//   2. Walk the rustdoc index, keep items with `public` visibility.
//   3. Group by module (parent path) and emit one MDX per module under
//      content/docs/api/<bin>/<module>.mdx.
//   4. Rewrite content/docs/api/meta.json from the discovered modules.
//
// Requirements
//   - Rust nightly toolchain (`rustup toolchain install nightly`).
//   - Run from the docs/ directory: `npm run gen:api`.
//
// Non-goals
//   - Rendering doc strings as rich markdown (rustdoc JSON gives raw
//     markdown already; we emit it verbatim for MDX to handle).
//   - Private items. Filtering is strict on visibility == "public".

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, mkdtempSync, renameSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const OUT_ROOT  = resolve(__dirname, '..', 'content', 'docs', 'api');
const BINS      = ['kepr', 'kepr-daemon'];

// ── helpers ─────────────────────────────────────────────────────────

function run(bin, args, opts = {}) {
  return execFileSync(bin, args, { stdio: 'inherit', ...opts });
}

function ensureNightly() {
  try {
    execFileSync('cargo', ['+nightly', '--version'], { stdio: 'ignore' });
  } catch {
    console.error(
      'error: rustdoc JSON output requires the nightly toolchain.\n' +
      '       install with: rustup toolchain install nightly',
    );
    process.exit(1);
  }
}

function rustdocJson(bin) {
  run('cargo', [
    '+nightly', 'rustdoc',
    '--bin', bin,
    '--', '-Z', 'unstable-options', '--output-format', 'json',
  ], { cwd: REPO_ROOT });

  // Crate name in JSON uses underscores — the `kepr-daemon` binary
  // produces kepr_daemon.json. Try both.
  const candidates = [
    join(REPO_ROOT, 'target', 'doc', `${bin}.json`),
    join(REPO_ROOT, 'target', 'doc', `${bin.replace(/-/g, '_')}.json`),
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  throw new Error(`rustdoc JSON not found for ${bin}; looked at:\n  ${candidates.join('\n  ')}`);
}

function isPublic(item) {
  return item.visibility === 'public' || item.visibility === 'default';
}

function kindOf(item) {
  const k = item.inner && Object.keys(item.inner)[0];
  return k || 'unknown';
}


function slug(s) {
  return s.replace(/[^a-zA-Z0-9_-]+/g, '-').toLowerCase();
}

// Escape anything that would break MDX when we embed doc strings.
function mdxEscape(s = '') {
  return s.replace(/</g, '&lt;').replace(/{/g, '&#123;');
}

// ── emit ────────────────────────────────────────────────────────────

function emitModulePage({ bin, moduleName, items, outRoot }) {
  const frontmatter =
    `---\n` +
    `title: "${bin}::${moduleName}"\n` +
    `description: "Public API items in ${bin}::${moduleName} (auto-generated)."\n` +
    `---\n\n`;

  const header =
    `> Auto-generated from \`cargo +nightly rustdoc --output-format json\`. ` +
    `Do not edit by hand — regenerate with \`npm run gen:api\`.\n\n`;

  const body = items
    .sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''))
    .map((it) => {
      const name = it.name ?? '(anonymous)';
      const kind = kindOf(it);
      const docs = it.docs ? mdxEscape(it.docs) + '\n' : '';
      return `## \`${name}\`\n\n**kind**: \`${kind}\`\n\n${docs}`;
    })
    .join('\n---\n\n');

  const outPath = join(outRoot, bin, `${slug(moduleName)}.mdx`);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, frontmatter + header + body);
  return outPath;
}

function emitMeta({ bin, modules, outRoot }) {
  const meta = {
    title: bin,
    defaultOpen: false,
    pages: modules.sort(),
  };
  mkdirSync(join(outRoot, bin), { recursive: true });
  writeFileSync(
    join(outRoot, bin, 'meta.json'),
    JSON.stringify(meta, null, 2) + '\n',
  );
}

function publish(stageRoot) {
  const backup = `${OUT_ROOT}.backup-${process.pid}-${Date.now()}`;
  const hadOutput = existsSync(OUT_ROOT);
  if (hadOutput) renameSync(OUT_ROOT, backup);
  try {
    renameSync(stageRoot, OUT_ROOT);
  } catch (error) {
    if (hadOutput) renameSync(backup, OUT_ROOT);
    throw error;
  }
  if (hadOutput) rmSync(backup, { recursive: true, force: true });
}

// ── main ────────────────────────────────────────────────────────────

function main() {
  ensureNightly();

  mkdirSync(dirname(OUT_ROOT), { recursive: true });
  const stageRoot = mkdtempSync(join(dirname(OUT_ROOT), '.api-stage-'));
  try {
  const binModules = [];

  for (const bin of BINS) {
    console.log(`\n▸ generating rustdoc JSON for ${bin}`);
    const jsonPath = rustdocJson(bin);
    const data = JSON.parse(readFileSync(jsonPath, 'utf8'));

    // Group public items by their containing module (first segment of `path`
    // from the paths table, excluding the crate root itself).
    const modules = new Map();
    for (const [id, path] of Object.entries(data.paths || {})) {
      const item = data.index?.[id];
      if (!item || !isPublic(item)) continue;
      const segs = path.path || [];
      if (segs.length < 2) continue; // crate root only
      const moduleName = segs[1];
      if (!modules.has(moduleName)) modules.set(moduleName, []);
      modules.get(moduleName).push({ ...item, _path: segs.join('::') });
    }

    const moduleNames = [];
    for (const [moduleName, items] of modules) {
      emitModulePage({ bin, moduleName, items, outRoot: stageRoot });
      moduleNames.push(slug(moduleName));
    }
    emitMeta({ bin, modules: moduleNames, outRoot: stageRoot });
    binModules.push(bin);
    console.log(`  wrote ${moduleNames.length} module page(s) under content/docs/api/${bin}/`);
  }

  // Top-level api/meta.json — one group per binary.
  writeFileSync(
    join(stageRoot, 'meta.json'),
    JSON.stringify(
      { title: 'API reference', defaultOpen: false, pages: binModules },
      null,
      2,
    ) + '\n',
  );

  publish(stageRoot);
  console.log('\n✓ done. Append "api" to content/docs/meta.json "pages" to expose it in the sidebar.');
  } finally {
    if (existsSync(stageRoot)) rmSync(stageRoot, { recursive: true, force: true });
  }
}

main();
