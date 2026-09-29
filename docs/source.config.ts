import { defineConfig, defineDocs } from 'fumadocs-mdx/config';
import { visit } from 'unist-util-visit';

// Rewrite fenced ```mermaid blocks into <Mermaid chart={"..."} /> JSX
// BEFORE Shiki runs. Once Shiki tokenises a code block, the original
// language class and raw body are gone and a downstream `pre` override
// can no longer identify it. Converting at the mdast stage sidesteps
// Shiki entirely and routes the block to the client Mermaid component
// registered in mdx-components.tsx.
function remarkMermaid() {
  return (tree: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    visit(tree as any, 'code', (node: any, index, parent: any) => {
      if (node.lang !== 'mermaid' || index == null || parent == null) return;
      const raw = JSON.stringify(node.value);
      parent.children[index] = {
        type: 'mdxJsxFlowElement',
        name: 'Mermaid',
        attributes: [
          {
            type: 'mdxJsxAttribute',
            name: 'chart',
            // Expression form so quotes, braces, and newlines inside a
            // mermaid chart survive MDX serialisation. MDX requires a
            // parsed estree alongside the raw source; without it the
            // compiler emits `chart:` with no value and fails to build.
            value: {
              type: 'mdxJsxAttributeValueExpression',
              value: raw,
              data: {
                estree: {
                  type: 'Program',
                  sourceType: 'module',
                  body: [
                    {
                      type: 'ExpressionStatement',
                      expression: {
                        type: 'Literal',
                        value: node.value,
                        raw,
                      },
                    },
                  ],
                },
              },
            },
          },
        ],
        children: [],
      };
    });
  };
}

export const docs = defineDocs({
  dir: 'content/docs',
});

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [remarkMermaid],
    // No local images in content/docs; disabled to avoid depending on
    // image-size's removed default export (see docs/package.json
    // overrides — image-size is pinned to >=2.0.4 for CVE fixes, but
    // fumadocs-core's bundled remark-image plugin still imports the
    // v1-only default export, which is undefined on v2 and would throw
    // if this plugin ever ran against a local image).
    remarkImageOptions: false,
  },
});
