'use client';

import { useEffect, useId, useRef, useState } from 'react';

let loader: Promise<typeof import('mermaid').default> | null = null;

function getMermaid() {
  if (!loader) {
    loader = import('mermaid').then((m) => {
      const mermaid = m.default;
      mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });
      return mermaid;
    });
  }
  return loader;
}

// `securityLevel: 'strict'` above instructs Mermaid to sanitise the
// chart input before emitting SVG. We parse the result with DOMParser
// and attach via replaceChildren, avoiding direct string-to-HTML injection.
export function Mermaid({ chart }: { chart: string }) {
  const id = useId().replace(/:/g, '_');
  const ref = useRef<HTMLDivElement>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMermaid().then(async (mermaid) => {
      try {
        const { svg } = await mermaid.render(`m${id}`, chart);
        if (cancelled || !ref.current) return;
        const doc = new DOMParser().parseFromString(svg, 'image/svg+xml');
        const root = doc.documentElement;
        if (root.nodeName === 'parsererror') {
          setErr('mermaid: SVG parse failed');
          return;
        }
        ref.current.replaceChildren(document.importNode(root, true));
      } catch (e) {
        if (!cancelled) setErr((e as Error).message);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [chart, id]);

  if (err) {
    return (
      <pre className="text-sm text-red-500 whitespace-pre-wrap">{err}</pre>
    );
  }
  return <div ref={ref} className="my-4 flex justify-center" />;
}
