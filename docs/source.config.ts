import { defineConfig, defineDocs } from 'fumadocs-mdx/config';

export const docs = defineDocs({
  dir: 'content/docs',
});

export default defineConfig({
  mdxOptions: {
    // Mermaid is rendered client-side via components/mermaid.tsx,
    // selected by the `pre` override in mdx-components.tsx.
  },
});
