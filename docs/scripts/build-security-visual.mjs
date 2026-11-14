// Bundle the same React component used in the docs into a self-contained offline HTML file.
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const modules = path.join(root, "target/kepr-visual-tools/node_modules");
const { build } = await import(path.join(modules, "esbuild/lib/main.js"));
const result = await build({
  stdin: {
    contents: `import React from 'react'; import { createRoot } from 'react-dom/client'; import { SecurityFlow } from './docs/components/security-flow'; createRoot(document.getElementById('root')).render(<SecurityFlow />);`,
    loader: "tsx",
    resolveDir: root,
  },
  bundle: true,
  write: false,
  outdir: "out",
  minify: true,
  jsx: "automatic",
  define: { "process.env.NODE_ENV": '"production"' },
  alias: {
    react: path.join(modules, "react"),
    "react-dom": path.join(modules, "react-dom"),
    "react-zoom-pan-pinch": path.join(modules, "react-zoom-pan-pinch"),
  },
});
const js = result.outputFiles.find((f) => f.path.endsWith(".js")).text;
const css = result.outputFiles.find((f) => f.path.endsWith(".css")).text;
if (/<\/script/i.test(js)) throw new Error("Unsafe embedded script terminator");
const hash = createHash("sha256").update(js).digest("base64");
const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-${hash}'; style-src 'unsafe-inline'; img-src data: blob:; font-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'"><title>Kepr — Security Flow Explorer</title><style>body{margin:0;background:#101715}${css}</style></head><body><div id="root"></div><script type="module">${js}</script></body></html>`;
const output = path.join(root, "docs/public/visuals/kepr-security");
await fs.mkdir(output, { recursive: true });
await fs.writeFile(path.join(output, "index.html"), html);
console.log(
  "Built offline security-flow artifact with embedded assets and network-disabled CSP.",
);
