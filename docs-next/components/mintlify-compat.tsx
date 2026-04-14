// Mintlify → Fumadocs UI component shims.
//
// Lets MDX authored against the Mintlify component set render under
// Fumadocs without rewriting every page. Add more shims here as needed.

import type { ReactNode } from 'react';
import { Callout } from 'fumadocs-ui/components/callout';
import { Cards, Card } from 'fumadocs-ui/components/card';
import { Steps, Step } from 'fumadocs-ui/components/steps';

export { Cards, Card, Steps, Step };

// <CardGroup cols={N}> → <Cards>
export function CardGroup({ children }: { cols?: number; children: ReactNode }) {
  return <Cards>{children}</Cards>;
}

// Mintlify callouts → Fumadocs Callout with matching severity.
export const Note    = (p: { children: ReactNode; title?: string }) =>
  <Callout title={p.title} type="info">{p.children}</Callout>;
export const Info    = (p: { children: ReactNode; title?: string }) =>
  <Callout title={p.title} type="info">{p.children}</Callout>;
export const Tip     = (p: { children: ReactNode; title?: string }) =>
  <Callout title={p.title} type="info">{p.children}</Callout>;
export const Check   = (p: { children: ReactNode; title?: string }) =>
  <Callout title={p.title ?? 'OK'} type="info">{p.children}</Callout>;
export const Warning = (p: { children: ReactNode; title?: string }) =>
  <Callout title={p.title} type="warn">{p.children}</Callout>;

// Mintlify <Tabs>/<Tab title="..."> → Fumadocs <Tabs items={[...]}>/<Tab value="...">.
// We can't inspect children at render time without parsing, so this shim accepts
// an `items` prop — MDX authors migrating from Mintlify should switch to the
// Fumadocs API (items + value) for Tabs. Left as-is elsewhere.
export { Tabs, Tab } from 'fumadocs-ui/components/tabs';
