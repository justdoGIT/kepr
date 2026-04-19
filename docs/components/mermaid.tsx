'use client';

import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTheme } from 'next-themes';
import { TransformWrapper, TransformComponent } from 'react-zoom-pan-pinch';

let loader: Promise<typeof import('mermaid').default> | null = null;

function getMermaid() {
  if (!loader) {
    loader = Promise.all([
      import('mermaid'),
      import('@mermaid-js/layout-elk').catch(() => null),
    ]).then(([m, elkMod]) => {
      const mermaid = m.default;
      // ELK provides reliable subgraph `direction LR/RL` support;
      // dagre (the default) silently drops it.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const anyMermaid = mermaid as any;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const elk = elkMod ? ((elkMod as any).default ?? elkMod) : null;
      if (elk && typeof anyMermaid.registerLayoutLoaders === 'function') {
        try { anyMermaid.registerLayoutLoaders(elk); } catch { /* noop */ }
      }
      return mermaid;
    });
  }
  return loader;
}

// Parses an SVG string and attaches the <svg> DOM subtree under `host`.
// Uses browser's HTML parser (lenient on foreignObject HTML-void tags like
// <br>) then replaceChildren — no innerHTML round-trip.
function attachSvg(host: HTMLElement, svgString: string): boolean {
  const doc = new DOMParser().parseFromString(svgString, 'text/html');
  const root = doc.body.querySelector('svg');
  if (!root) return false;
  host.replaceChildren(document.importNode(root, true));
  return true;
}

// Renders a serialised SVG string into a div via ref + replaceChildren.
// Lives inside TransformComponent so pan-zoom measures real content size.
function ZoomedSvg({ svg }: { svg: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) attachSvg(ref.current, svg);
  }, [svg]);
  // inline-block + explicit min-size so TransformWrapper can measure us
  // before the SVG attaches (prevents 0x0 collapse on first mount).
  return (
    <div
      ref={ref}
      className="inline-block p-4 md:p-8 [&_svg]:block [&_svg]:max-w-none [&_svg]:max-h-none [&_svg]:h-auto"
      style={{ minWidth: 200, minHeight: 200 }}
    />
  );
}

export function Mermaid({ chart }: { chart: string }) {
  const id = useId().replace(/:/g, '_');
  const ref = useRef<HTMLDivElement>(null);
  const [err, setErr] = useState<string | null>(null);
  const [zoomed, setZoomed] = useState(false);
  const [modalSvg, setModalSvg] = useState<string>('');
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';

  useEffect(() => {
    let cancelled = false;
    getMermaid().then(async (mermaid) => {
      const labelBg = isDark ? '#0f172a' : '#f8fafc';
      const slate = {
        primaryColor:       isDark ? '#1e293b' : '#f1f5f9',
        primaryTextColor:   isDark ? '#e2e8f0' : '#0f172a',
        primaryBorderColor: isDark ? '#64748b' : '#94a3b8',
        lineColor:          isDark ? '#94a3b8' : '#475569',
        secondaryColor:     isDark ? '#1e293b' : '#e2e8f0',
        tertiaryColor:      isDark ? '#0f172a' : '#f8fafc',
        background:         'transparent',

        actorBkg:              isDark ? '#1e293b' : '#e2e8f0',
        actorBorder:           isDark ? '#64748b' : '#94a3b8',
        actorTextColor:        isDark ? '#e2e8f0' : '#0f172a',
        actorLineColor:        isDark ? '#475569' : '#cbd5e1',
        signalColor:           isDark ? '#cbd5e1' : '#334155',
        signalTextColor:       isDark ? '#e2e8f0' : '#0f172a',
        labelBoxBkgColor:      isDark ? '#334155' : '#cbd5e1',
        labelBoxBorderColor:   isDark ? '#64748b' : '#94a3b8',
        labelTextColor:        isDark ? '#e2e8f0' : '#0f172a',
        noteBkgColor:          isDark ? '#3f2d14' : '#fef3c7',
        noteTextColor:         isDark ? '#fef3c7' : '#78350f',
        noteBorderColor:       isDark ? '#a16207' : '#f59e0b',
        activationBkgColor:    isDark ? '#475569' : '#cbd5e1',
        activationBorderColor: isDark ? '#64748b' : '#475569',
        sequenceNumberColor:   isDark ? '#0f172a' : '#ffffff',

        mainBkg:             isDark ? '#1e293b' : '#f1f5f9',
        nodeBkg:             isDark ? '#1e293b' : '#f1f5f9',
        nodeBorder:          isDark ? '#64748b' : '#94a3b8',
        nodeTextColor:       isDark ? '#e2e8f0' : '#0f172a',
        clusterBkg:          isDark ? '#0f172a' : '#f8fafc',
        clusterBorder:       isDark ? '#475569' : '#cbd5e1',
        titleColor:          isDark ? '#cbd5e1' : '#334155',
        edgeLabelBackground: labelBg,
        defaultLinkColor:    isDark ? '#94a3b8' : '#475569',
      };

      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'antiscript',
        fontFamily: 'inherit',
        theme: 'base',
        themeVariables: slate,
        // Global layout intentionally left as mermaid's default (dagre).
        // Diagrams that need ELK (e.g. subgraph `direction LR/RL`) opt in
        // via frontmatter inside the mermaid block:
        //   ---
        //   config:
        //     layout: elk
        //   ---
        //   flowchart TB ...
        flowchart: {
          nodeSpacing: 60,
          rankSpacing: 140,
          curve: 'basis',
          padding: 24,
          htmlLabels: true,
          useMaxWidth: true,
        },
        sequence: {
          diagramMarginX: 50,
          diagramMarginY: 20,
          boxMargin: 16,
          boxTextMargin: 8,
          actorMargin: 110,
          noteMargin: 14,
          messageMargin: 55,
          messageAlign: 'center',
          mirrorActors: false,
          bottomMarginAdj: 10,
          wrap: true,
          wrapPadding: 12,
          useMaxWidth: true,
        },
        themeCSS: `
          .actor { font-weight: 600; font-size: 14px; }
          .messageText { font-size: 13px; font-weight: 500; letter-spacing: 0.1px; }
          .loopText, .noteText { font-size: 12px; }
          .sequenceNumber { font-size: 11px; font-weight: 700; }
          text.sequenceNumber { fill: ${isDark ? '#0f172a' : '#ffffff'}; }
          rect.actor { rx: 8; ry: 8; }
          .note { rx: 6; ry: 6; }
          .messageLine0, .messageLine1 { stroke-width: 1.5; }
          line.actor-line { stroke-width: 1.2; }
          .node rect, .node polygon, .node circle, .node ellipse { stroke-width: 1.5; }
          .node rect { rx: 8; ry: 8; }
          .cluster rect { rx: 10; ry: 10; stroke-dasharray: none; }
          .cluster .nodeLabel, .node .nodeLabel { font-weight: 500; }
          .edgePath .path { stroke-width: 1.5; }
          .edgeLabel {
            background-color: transparent !important;
            padding: 3px 6px;
            font-size: 12px;
            line-height: 1.35;
          }
          .edgeLabel rect { fill: transparent !important; }
          .edgeLabel foreignObject { overflow: visible; }
          .edgeLabel div, .edgeLabel p { background-color: transparent !important; }
          foreignObject div { font-family: inherit !important; }
          svg { max-width: 100%; height: auto; }
          svg a { cursor: pointer; }
          svg a text { text-decoration: underline; text-underline-offset: 2px; }
        `,
      });

      try {
        const { svg } = await mermaid.render(`m${id}`, chart);
        if (cancelled || !ref.current) return;
        if (!attachSvg(ref.current, svg)) {
          setErr('mermaid: no <svg> root in rendered output');
        }
      } catch (e) {
        if (!cancelled) setErr((e as Error).message);
      }
    });
    return () => { cancelled = true; };
  }, [chart, id, isDark]);

  // Serialise the inline SVG into state when the modal opens.
  // Keeping it in React state (instead of writing into a ref inside
  // TransformComponent) ensures the pan-zoom wrapper only mounts when
  // its content exists, so its size measurement + centerOnInit are correct.
  useEffect(() => {
    if (!zoomed) { setModalSvg(''); return; }
    const src = ref.current?.querySelector('svg');
    if (src) {
      const clone = src.cloneNode(true) as SVGElement;
      clone.removeAttribute('style');
      clone.removeAttribute('width');
      clone.removeAttribute('height');
      clone.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      setModalSvg(new XMLSerializer().serializeToString(clone));
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setZoomed(false);
    };
    window.addEventListener('keydown', onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [zoomed]);

  const onContainerClick = useCallback((e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a')) return;
    setZoomed(true);
  }, []);

  if (err) {
    return (
      <pre className="text-sm text-red-500 whitespace-pre-wrap">{err}</pre>
    );
  }

  return (
    <>
      <div
        role="button"
        tabIndex={0}
        aria-label="Zoom diagram"
        onClick={onContainerClick}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setZoomed(true);
          }
        }}
        className="my-6 overflow-x-auto rounded-lg border border-fd-border bg-fd-card/40 p-4 md:p-6 cursor-zoom-in hover:bg-fd-card/60 hover:border-fd-ring transition-colors focus:outline-none focus:ring-2 focus:ring-fd-ring"
      >
        <div ref={ref} className="flex justify-center min-w-fit" />
      </div>

      {zoomed && (
        <div
          onClick={() => setZoomed(false)}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 md:p-8 backdrop-blur-sm"
          aria-modal="true"
          role="dialog"
        >
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); setZoomed(false); }}
            className="absolute top-4 right-4 z-10 rounded-md bg-fd-card border border-fd-border px-3 py-1.5 text-sm text-fd-foreground hover:bg-fd-accent"
            aria-label="Close diagram"
          >
            Close (Esc)
          </button>
          <div
            onClick={(e) => e.stopPropagation()}
            className="relative h-full max-h-[92vh] w-full max-w-[95vw] overflow-hidden rounded-lg bg-fd-background"
          >
            {modalSvg ? (
              <TransformWrapper
                initialScale={1}
                minScale={0.75}
                maxScale={15}
                centerOnInit
                limitToBounds={false}
                doubleClick={{ mode: 'toggle', step: 1.5 }}
                wheel={{ step: 0.01 }}
                pinch={{ step: 5 }}
              >
                {({ zoomIn, zoomOut, resetTransform }) => (
                  <>
                    <div className="absolute bottom-4 left-1/2 z-10 flex -translate-x-1/2 gap-1 rounded-md border border-fd-border bg-fd-card/90 p-1 text-sm text-fd-foreground shadow-lg backdrop-blur">
                      <button
                        type="button"
                        onClick={() => zoomOut()}
                        className="rounded px-3 py-1 hover:bg-fd-accent"
                        aria-label="Zoom out"
                      >
                        −
                      </button>
                      <button
                        type="button"
                        onClick={() => resetTransform()}
                        className="rounded px-3 py-1 hover:bg-fd-accent"
                        aria-label="Reset zoom"
                      >
                        Reset
                      </button>
                      <button
                        type="button"
                        onClick={() => zoomIn()}
                        className="rounded px-3 py-1 hover:bg-fd-accent"
                        aria-label="Zoom in"
                      >
                        +
                      </button>
                    </div>
                    <TransformComponent
                      wrapperStyle={{ width: '100%', height: '100%', cursor: 'grab' }}
                      contentStyle={{
                        width: '100%',
                        height: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <ZoomedSvg svg={modalSvg} />
                    </TransformComponent>
                  </>
                )}
              </TransformWrapper>
            ) : null}
          </div>
        </div>
      )}
    </>
  );
}
