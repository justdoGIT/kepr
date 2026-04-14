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
    // Fenced ```mermaid blocks → client-rendered SVG.
    pre: ({ children, ...props }) => {
      const child: any = children;
      if (
        child?.props?.className === 'language-mermaid' &&
        typeof child?.props?.children === 'string'
      ) {
        return <Mermaid chart={child.props.children} />;
      }
      return <defaultMdxComponents.pre {...props}>{children}</defaultMdxComponents.pre>;
    },
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
