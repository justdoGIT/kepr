"use client";

import { useEffect, useRef, useState } from "react";
import { TransformComponent, TransformWrapper } from "react-zoom-pan-pinch";
import { SecurityFlowDiagram } from "./security-flow-diagram";
import {
  coverage,
  outcome,
  scenarios,
  stages,
  type Mode,
  type ScenarioId,
} from "./security-flow-data";
import styles from "./security-flow.module.css";

export function SecurityFlow() {
  const [mode, setMode] = useState<Mode>("current");
  const [scenario, setScenario] = useState<ScenarioId>("summary");
  const [selected, setSelected] = useState("agent");
  const [approved, setApproved] = useState(false);
  const [localReady, setLocalReady] = useState(false);
  const [width, setWidth] = useState(720);
  const diagram = useRef<HTMLDivElement>(null);
  const list = stages(mode),
    active = list.find((s) => s.id === selected) ?? list[0];
  const example = scenarios.find((s) => s.id === scenario)!;
  const result = outcome(mode, scenario, approved, localReady);
  const actionExample =
    scenario === "work-mail" || scenario === "personal-mail";

  useEffect(() => {
    setApproved(false);
    setSelected("agent");
  }, [mode, scenario]);
  useEffect(() => {
    const element = diagram.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) =>
      setWidth(entry.contentRect.width),
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  function downloadSvg() {
    const svg = diagram.current?.querySelector("svg");
    if (!svg) return;
    const url = URL.createObjectURL(
      new Blob([svg.outerHTML], { type: "image/svg+xml" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `kepr-${mode}-flow.svg`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <section className={styles.app} aria-label="Kepr security flow explorer">
      <header className={styles.hero}>
        <div className={styles.brand}>
          <span className={styles.shield} aria-hidden="true">
            ◇
          </span>{" "}
          kepr <span className={styles.brandDivider} />{" "}
          <span className={styles.eyebrow}>SECURITY FLOW EXPLORER</span>
        </div>
        <p className={styles.kicker}>FOLLOW THE REQUEST. FIND THE BOUNDARY.</p>
        <h1>
          Your agent. Your data.
          <br />
          <span>A controlled exit.</span>
        </h1>
        <p className={styles.intro}>
          See where credentials stay, what reaches an external model, and which
          controls your examples would add.
        </p>
        <div className={styles.modeBar}>
          <div className={styles.segment} aria-label="Diagram scope">
            <button
              aria-pressed={mode === "current"}
              onClick={() => setMode("current")}
            >
              How Kepr works
            </button>
            <button
              aria-pressed={mode === "target"}
              onClick={() => setMode("target")}
            >
              Controls to add
            </button>
          </div>
          <p data-testid="mode-caption" className={styles.modeCaption}>
            {mode === "current"
              ? "Implemented source · protected-session boundary"
              : "Proposed design · capabilities still to implement"}
          </p>
        </div>
      </header>

      <div className={styles.layout}>
        <article className={styles.map}>
          <div className={styles.mapHead}>
            <div>
              <span className={styles.dot} />{" "}
              <strong>
                {mode === "current"
                  ? "The request & return path"
                  : "Add classification, identity & action controls"}
              </strong>
              <p>Click a stage, step through, or zoom in.</p>
            </div>
            <button
              className={styles.export}
              onClick={downloadSvg}
              aria-label="Download SVG"
            >
              ↓ <span>Download SVG</span>
            </button>
          </div>
          <div className={styles.diagram} ref={diagram} data-testid="diagram">
            <TransformWrapper
              key={`${mode}-${Math.round(width)}`}
              initialScale={Math.max(
                0.25,
                Math.min(0.66, (width / 980) * 0.98),
              )}
              minScale={0.25}
              maxScale={2}
              centerOnInit
              wheel={{ step: 0.001 }}
              doubleClick={{ mode: "zoomIn", step: 1.3 }}
              pinch={{ step: 5 }}
            >
              {({ zoomIn, zoomOut, resetTransform }) => (
                <>
                  <div className={styles.zoomTools}>
                    <button onClick={() => zoomOut(0.1)} aria-label="Zoom out">
                      −
                    </button>
                    <button
                      onClick={() => resetTransform()}
                      aria-label="Reset zoom"
                    >
                      Reset
                    </button>
                    <button onClick={() => zoomIn(0.1)} aria-label="Zoom in">
                      +
                    </button>
                    <button
                      onClick={() => {
                        const element = diagram.current;
                        if (element && !document.fullscreenElement)
                          element.requestFullscreen?.().catch(() => {});
                        else document.exitFullscreen?.().catch(() => {});
                      }}
                      aria-label="Toggle fullscreen"
                    >
                      ⛶
                    </button>
                  </div>
                  <TransformComponent
                    wrapperStyle={{ width: "100%", height: "100%" }}
                    contentStyle={{
                      width: "max-content",
                      height: "max-content",
                    }}
                  >
                    <SecurityFlowDiagram
                      mode={mode}
                      selected={active.id}
                      cloud={result.cloud}
                      localReady={localReady}
                      onSelect={setSelected}
                    />
                  </TransformComponent>
                </>
              )}
            </TransformWrapper>
          </div>
          <div className={styles.mapLegend}>
            <span>
              <i /> Current foundation
            </span>
            <span>
              <i className={styles.dashed} /> Proposed extension
            </span>
            <span>
              <i className={styles.red} /> Disclosure risk / denied route
            </span>
          </div>
          <div
            className={styles.detail}
            data-testid="step-detail"
            aria-live="polite"
          >
            <div className={styles.stepHead}>
              <span className={styles.stepNumber}>
                {String(list.indexOf(active) + 1).padStart(2, "0")}
              </span>
              <h2>{active.title}</h2>
              <button
                onClick={() =>
                  setSelected(list[(list.indexOf(active) + 1) % list.length].id)
                }
              >
                Next step →
              </button>
            </div>
            <p>{active.detail}</p>
          </div>
        </article>

        <aside className={styles.sidebar} aria-label="Data flow examples">
          <div className={styles.demo}>
            <div className={styles.cardEyebrow}>
              TRY A DATA FLOW <span>SIMULATION</span>
            </div>
            <label className={styles.label} htmlFor="kepr-flow-example">
              Example request
            </label>
            <select
              id="kepr-flow-example"
              value={scenario}
              onChange={(e) => setScenario(e.target.value as ScenarioId)}
            >
              {scenarios.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
            <div className={styles.request}>
              <span>INPUT / SYNTHETIC EXAMPLE</span>
              <p>{example.input}</p>
            </div>
            {mode === "target" && scenario === "confidential" && (
              <label className={styles.check}>
                <input
                  type="checkbox"
                  checked={localReady}
                  onChange={(e) => setLocalReady(e.target.checked)}
                />
                Local inference ready (demo)
              </label>
            )}
            <div
              className={`${styles.outcome} ${styles[result.tone]}`}
              data-testid="outcome"
              aria-live="polite"
            >
              <strong>{result.title}</strong>
              <p>{result.text}</p>
            </div>
            {actionExample && mode === "target" && (
              <button
                className={styles.approve}
                aria-pressed={approved}
                onClick={() => setApproved(true)}
              >
                Approve demo action
              </button>
            )}
            <p className={styles.demoNote}>
              Illustration only. No model, email or tool is called.
            </p>
          </div>

          <div className={styles.packet}>
            <div className={styles.cardEyebrow}>WHAT LEAVES THE DEVICE</div>
            {result.cloud === "blocked" || result.cloud === "local" ? (
              <div className={styles.nothing}>
                <span>∅</span>
                <strong>No cloud payload</strong>
                <p>
                  The proposed rule requires local processing or stops the
                  request.
                </p>
              </div>
            ) : (
              <>
                <p className={styles.packetCaption}>
                  {scenario === "browser"
                    ? "The original request bypasses the gate."
                    : "Example of request content; token names shortened."}
                </p>
                <dl>
                  <div>
                    <dt>name</dt>
                    <dd className={mode === "current" ? styles.unmasked : ""}>
                      {mode === "target" ? "<PERSON_1>" : "Maya Chen"}
                    </dd>
                  </div>
                  <div>
                    <dt>email</dt>
                    <dd>
                      {scenario === "browser" && mode === "current"
                        ? "maya@example.invalid"
                        : "<EMAIL_1>"}
                    </dd>
                  </div>
                  {scenario === "card" && (
                    <div>
                      <dt>card</dt>
                      <dd className={mode === "current" ? styles.unmasked : ""}>
                        {mode === "target"
                          ? "<CARD_1>"
                          : "Unchanged · coverage gap"}
                      </dd>
                    </div>
                  )}
                  {scenario === "confidential" && (
                    <div>
                      <dt>business text</dt>
                      <dd className={styles.unmasked}>Orion acquisition</dd>
                    </div>
                  )}
                  <div>
                    <dt>API key in prompt</dt>
                    <dd className={styles.keyValue}>Never supplied by Kepr</dd>
                  </div>
                </dl>
                <div className={styles.authNotice}>
                  <span>◇</span>
                  <p>
                    On a Kepr route, the real key is added only as provider
                    authentication. It is never restored into model text.
                  </p>
                </div>
                <p className={styles.metadata}>
                  The provider still sees its account, source IP and request
                  timing.
                </p>
              </>
            )}
          </div>
          <div className={styles.principle}>
            <span>THE KEY DISTINCTION</span>
            <h2>
              Mask fields.
              <br />
              Route meaning.
              <br />
              Authorize actions.
            </h2>
            <p>
              Removing an email does not make an acquisition plan safe to send.
              Human confirmation cannot override a prohibited destination.
            </p>
          </div>
        </aside>
      </div>

      <section
        className={styles.coverage}
        aria-label="Security control coverage"
      >
        <div className={styles.coverageHead}>
          <div>
            <p className={styles.kicker}>FROM YOUR DIAGRAMS TO KEPR</p>
            <h2>What exists. What we add next.</h2>
          </div>
          <span>Source status, not a deployment attestation.</span>
        </div>
        <div className={styles.coverageGrid}>
          {coverage.map(([name, status, text]) => (
            <article key={name}>
              <div>
                <h3>{name}</h3>
                <span
                  className={`${styles.badge} ${status === "Implemented" ? styles.implemented : status === "Partial" ? styles.partial : styles.planned}`}
                >
                  {status}
                </span>
              </div>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>
      <footer className={styles.footer}>
        <strong>Local-only means no external request.</strong>
        <p>
          Local inference and device-wide enforcement remain unfinished. Kepr
          currently refuses unsupported opaque reasoning/media under its privacy
          adapter.
        </p>
        <p>
          This explorer runs locally without external assets, analytics, models
          or network calls.
        </p>
      </footer>
    </section>
  );
}
