'use client';

import { useCallback, useEffect, useState } from 'react';
import { TransformWrapper, TransformComponent } from 'react-zoom-pan-pinch';

// Static snake/serpentine diagram of credman's e2e test matrix.
// Hand-authored SVG — bypasses mermaid entirely to guarantee the layout.

type Node = { id: string; row: number; col: number; label: string; note?: string };
type Edge = { from: string; to: string };

const NODES: Node[] = [
  { id: 'P',   row: 0, col: 0, label: 'Preflight',                 note: 'socket reachable + jq present' },
  { id: 'T1',  row: 0, col: 1, label: '1. happy path',             note: 'set, get, list, check, delete' },
  { id: 'T2',  row: 0, col: 2, label: '2. value round-trip',       note: 'exact bytes preserved' },
  { id: 'T3',  row: 1, col: 2, label: '3. generators',             note: 'hex / base62 / uuid / pass' },
  { id: 'T4',  row: 1, col: 1, label: '4. validate_name',          note: "rejects '/' and '.'" },
  { id: 'T5',  row: 1, col: 0, label: '5. --value overwrites',     note: 'existing cred replaced' },
  { id: 'T6',  row: 2, col: 0, label: '6. --json shape',           note: 'success + missing cred' },
  { id: 'T7',  row: 2, col: 1, label: '7. error sanitisation',     note: 'SKIP if no sudo' },
  { id: 'T8',  row: 2, col: 2, label: '8. audit log op=get',       note: 'SKIP if no journal' },
  { id: 'T9',  row: 3, col: 2, label: '9. colour opt-in',          note: 'NO_COLOR / --color' },
  { id: 'T10', row: 3, col: 1, label: '10. check output',          note: 'deterministic + sorted' },
  { id: 'T11', row: 3, col: 0, label: '11. --json mode',           note: 'zero stderr noise' },
  { id: 'T12', row: 4, col: 0, label: '12. delete --force',        note: 'skips prompt' },
  { id: 'T13', row: 4, col: 1, label: '13. aliases ls / rm',       note: 'behave as list / delete' },
];

const EDGES: Edge[] = [
  { from: 'P',   to: 'T1' }, { from: 'T1',  to: 'T2' }, { from: 'T2',  to: 'T3' },
  { from: 'T3',  to: 'T4' }, { from: 'T4',  to: 'T5' }, { from: 'T5',  to: 'T6' },
  { from: 'T6',  to: 'T7' }, { from: 'T7',  to: 'T8' }, { from: 'T8',  to: 'T9' },
  { from: 'T9',  to: 'T10' }, { from: 'T10', to: 'T11' }, { from: 'T11', to: 'T12' },
  { from: 'T12', to: 'T13' },
];

const BOX_W = 240, BOX_H = 84, COL_GAP = 60, ROW_GAP = 60, MARGIN = 20;
const colX = (c: number) => MARGIN + c * (BOX_W + COL_GAP);
const rowY = (r: number) => MARGIN + r * (BOX_H + ROW_GAP);
const VIEW_W = MARGIN * 2 + 3 * BOX_W + 2 * COL_GAP;
const VIEW_H = MARGIN * 2 + 5 * BOX_H + 4 * ROW_GAP;

const byId = (id: string) => NODES.find((x) => x.id === id)!;

function edgePath(e: Edge) {
  const a = byId(e.from), b = byId(e.to);
  const ax = colX(a.col), ay = rowY(a.row), bx = colX(b.col), by = rowY(b.row);
  if (a.row === b.row) {
    const right = b.col > a.col;
    const x1 = right ? ax + BOX_W : ax;
    const x2 = right ? bx : bx + BOX_W;
    const y = ay + BOX_H / 2;
    return `M ${x1} ${y} L ${x2} ${y}`;
  }
  const x = ax + BOX_W / 2;
  return `M ${x} ${ay + BOX_H} L ${x} ${by}`;
}

function Diagram() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
      className="block h-auto w-full min-w-[720px]"
      role="img"
      aria-label="credman e2e test matrix — serpentine flow from preflight through 13 test cases"
    >
      <defs>
        <marker id="tm-arrow" viewBox="0 0 10 10" refX="9" refY="5"
          markerUnits="strokeWidth" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" className="fill-slate-600 dark:fill-slate-400" />
        </marker>
      </defs>

      <g fill="none" strokeWidth="1.5" className="stroke-slate-600 dark:stroke-slate-400">
        {EDGES.map((e) => (
          <path key={`${e.from}->${e.to}`} d={edgePath(e)} markerEnd="url(#tm-arrow)" />
        ))}
      </g>

      <g>
        {NODES.map((n) => {
          const x = colX(n.col), y = rowY(n.row);
          return (
            <g key={n.id}>
              <rect
                x={x} y={y} width={BOX_W} height={BOX_H} rx={10} ry={10}
                strokeWidth="1.5"
                className="fill-slate-100 stroke-slate-400 dark:fill-slate-800 dark:stroke-slate-500"
              />
              <text
                x={x + BOX_W / 2} y={y + 30} textAnchor="middle"
                className="fill-slate-900 dark:fill-slate-100 text-[13px] font-semibold"
                style={{ fontFamily: 'inherit' }}
              >
                {n.label}
              </text>
              {n.note && (
                <text
                  x={x + BOX_W / 2} y={y + 54} textAnchor="middle"
                  className="fill-slate-600 dark:fill-slate-400 text-[11px]"
                  style={{ fontFamily: 'inherit' }}
                >
                  {n.note}
                </text>
              )}
            </g>
          );
        })}
      </g>
    </svg>
  );
}

export function TestMatrix() {
  const [zoomed, setZoomed] = useState(false);

  useEffect(() => {
    if (!zoomed) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setZoomed(false); };
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [zoomed]);

  const onOpen = useCallback((e: React.MouseEvent | React.KeyboardEvent) => {
    if ('key' in e && e.key !== 'Enter' && e.key !== ' ') return;
    if ('preventDefault' in e) e.preventDefault();
    setZoomed(true);
  }, []);

  return (
    <>
      <div
        role="button"
        tabIndex={0}
        aria-label="Zoom diagram"
        onClick={onOpen}
        onKeyDown={onOpen}
        className="my-6 overflow-x-auto rounded-lg border border-fd-border bg-fd-card/40 p-4 md:p-6 cursor-zoom-in hover:bg-fd-card/60 hover:border-fd-ring transition-colors focus:outline-none focus:ring-2 focus:ring-fd-ring"
      >
        <Diagram />
      </div>

      {zoomed && (
        <div
          onClick={() => setZoomed(false)}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 md:p-8 backdrop-blur-sm"
          aria-modal="true"
          role="dialog"
          aria-label="Zoomed test matrix diagram"
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
            <TransformWrapper
              initialScale={1}
              minScale={0.25}
              maxScale={2}
              centerOnInit
              limitToBounds={false}
              doubleClick={{ mode: 'toggle', step: 1.3 }}
              wheel={{ step: 0.001 }}
              pinch={{ step: 3 }}
            >
              {({ zoomIn, zoomOut, resetTransform }) => (
                <>
                  <div className="absolute bottom-4 left-1/2 z-10 flex -translate-x-1/2 gap-1 rounded-md border border-fd-border bg-fd-card/90 p-1 text-sm text-fd-foreground shadow-lg backdrop-blur">
                    <button type="button" onClick={() => zoomOut()} className="rounded px-3 py-1 hover:bg-fd-accent" aria-label="Zoom out">−</button>
                    <button type="button" onClick={() => resetTransform()} className="rounded px-3 py-1 hover:bg-fd-accent" aria-label="Reset zoom">Reset</button>
                    <button type="button" onClick={() => zoomIn()} className="rounded px-3 py-1 hover:bg-fd-accent" aria-label="Zoom in">+</button>
                  </div>
                  <TransformComponent
                    wrapperStyle={{ width: '100%', height: '100%', cursor: 'grab' }}
                    contentStyle={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                  >
                    <div className="p-4 md:p-8 inline-block" style={{ minWidth: 200, minHeight: 200 }}>
                      <Diagram />
                    </div>
                  </TransformComponent>
                </>
              )}
            </TransformWrapper>
          </div>
        </div>
      )}
    </>
  );
}
