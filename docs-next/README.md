# credman-docs (Fumadocs)

Fumadocs (Next.js + MDX) docs site for credman. The legacy Mintlify
scaffold still lives at `../docs/` so the two can be diffed during
migration.

## Layout

```
docs-next/
├── app/                       # Next.js App Router: home + /docs routes
├── components/
│   ├── mermaid.tsx            # client-side Mermaid renderer (fenced blocks)
│   └── mintlify-compat.tsx    # shims: <Note>/<Warning>/<CardGroup>/...
├── content/docs/              # MDX content + per-directory meta.json
│   ├── meta.json
│   ├── index.mdx
│   ├── quickstart.mdx
│   ├── architecture/{meta.json, *.mdx}
│   └── reference/{meta.json, *.mdx}
├── lib/source.ts              # fumadocs-core source loader
├── mdx-components.tsx         # MDX component registry
├── scripts/gen-rust-api.mjs   # rustdoc JSON → MDX generator
├── source.config.ts           # fumadocs-mdx config
├── next.config.mjs
├── tailwind.config.ts
└── tsconfig.json
```

`meta.json` controls sidebar order and group titles per directory.
Root meta.json uses `---Label---` strings as section separators;
subdirectories become collapsible groups via their own meta.json.

## Develop

```bash
cd docs-next
npm install
npm run dev       # http://localhost:3000
npm run build     # production build
```

## Regenerate Rust API pages

Requires the nightly Rust toolchain
(`rustup toolchain install nightly`).

```bash
npm run gen:api
```

Runs `cargo +nightly rustdoc --output-format json` for each binary
(`credman`, `credman-daemon`), walks the public items, and writes MDX
under `content/docs/api/<bin>/`. After the first run, add `"api"` to
the `pages` array in `content/docs/meta.json` to expose the section in
the sidebar.

## Deploy (GitHub → Vercel)

1. Push the repo to GitHub.
2. Import the repo on Vercel. Set **Root Directory** to `docs-next`.
3. Framework preset auto-detects Next.js. No env vars needed.
4. Subsequent pushes auto-deploy.

Preview deployments per PR are enabled by default.

## Migration notes

- MDX pages use a small Mintlify-compatibility shim
  (`components/mintlify-compat.tsx`) so `<Note>`, `<Warning>`,
  `<CardGroup>`, `<Steps>`, etc. resolve to Fumadocs UI equivalents
  without rewriting every page.
- Mintlify's `<Tabs><Tab title="X">` API differs from Fumadocs'
  `<Tabs items={[...]}><Tab value="X">`. `quickstart.mdx` has been
  migrated; check any new Tabs usage.
- Internal links are absolute from the site root
  (`/docs/architecture/overview`). The old Mintlify scaffold used
  docs-relative paths (`/architecture/overview`).
