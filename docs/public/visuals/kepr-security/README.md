# Kepr security flow explorer

Open `index.html` in a browser. It is self-contained and works offline, with
no external fonts, scripts, analytics or model calls. “How Kepr works” shows
current source foundations; “Controls to add” shows the proposed design.
Solid and dashed outlines distinguish those scopes. Example requests are
synthetic simulations; approval buttons send nothing and change no policy.

Files:

- `kepr-current-flow.svg` / `.png`: current protected-session path.
- `kepr-target-flow.svg` / `.png`: proposed classification/action controls.
- `preview.png` / `mobile-preview.png`: interactive explorer screenshots.

Source lives in `docs/components/security-flow*.tsx`,
`security-flow-data.ts` and `security-flow.module.css`. The same component is
used in `docs/content/docs/agent-security-flow.mdx`.

From the repository root, install temporary build/check tools in the ignored
target directory:

```bash
npm install --prefix target/kepr-visual-tools --ignore-scripts --no-audit --no-fund esbuild react react-dom react-zoom-pan-pinch playwright-core
node docs/scripts/build-security-visual.mjs
node docs/scripts/check-security-visual.mjs
```

The check uses `/usr/bin/chromium` with a temporary browser context and a local
HTTP server. It tests example decisions, zoom, exports, four viewport widths,
runtime errors and attempted external requests, then regenerates screenshots.
The SVG exports contain native vectors and no external assets.

These files explain capabilities. They do not install DLP, an NER model,
tenant SSO, a firewall, an approval service or production policy.
