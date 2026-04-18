import defaultMdxComponents from 'fumadocs-ui/mdx';
import type { MDXComponents } from 'mdx/types';
import { Mermaid } from '@/components/mermaid';
import {
  Card,
  CardGroup,
  Cards,
  Check,
  Info,
  Note,
  Step,
  Steps,
  Tab,
  Tabs,
  Tip,
  Warning,
} from '@/components/mintlify-compat';

export function getMDXComponents(components?: MDXComponents): MDXComponents {
  return {
    ...defaultMdxComponents,
    // Fenced ```mermaid blocks are rewritten to <Mermaid chart={...} />
    // at the mdast stage by the remarkMermaid plugin in
    // source.config.ts, so all we need here is to expose the component.
    Mermaid,
    Card,
    CardGroup,
    Cards,
    Check,
    Info,
    Note,
    Step,
    Steps,
    Tab,
    Tabs,
    Tip,
    Warning,
    ...components,
  };
}
