import { coverage } from "./security-flow-data";
import styles from "./security-flow.module.css";

export function SecurityFlowFooter() {
  return (
    <>
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
    </>
  );
}
