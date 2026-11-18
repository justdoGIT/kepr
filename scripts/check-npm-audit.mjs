#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const [reportPath, auditStatusText = "1", lockPath = "package-lock.json"] =
  process.argv.slice(2);
const auditStatus = Number(auditStatusText);
const allowedAdvisory =
  "https://github.com/advisories/GHSA-fc5q-39xc-vjpf";
const allowedPackage = "picomatch";
const allowedVersion = "4.0.7";

function fail(message) {
  console.error(`npm audit gate: ${message}`);
  process.exit(1);
}

if (!reportPath || !Number.isInteger(auditStatus)) {
  fail("usage: check-npm-audit.mjs REPORT.json AUDIT_EXIT_CODE [LOCKFILE]");
}

let report;
try {
  report = JSON.parse(readFileSync(reportPath, "utf8"));
} catch (error) {
  fail(`could not read npm audit report: ${error.message}`);
}

if (report.error) {
  fail(`npm audit returned an error: ${JSON.stringify(report.error)}`);
}

const vulnerabilities = report.vulnerabilities ?? {};
const highOrCritical = Object.entries(vulnerabilities).filter(([, finding]) =>
  ["high", "critical"].includes(String(finding.severity).toLowerCase()),
);

if (highOrCritical.length === 0) {
  if (auditStatus !== 0) {
    fail(`npm audit exited with status ${auditStatus}`);
  }
  console.log("npm audit gate: no high or critical vulnerabilities");
  process.exit(0);
}

const findingMap = new Map(highOrCritical);
const advisoryObjects = highOrCritical.flatMap(([, finding]) =>
  (finding.via ?? []).filter(
    (entry) => typeof entry === "object" && entry !== null,
  ),
);

if (
  advisoryObjects.length === 0 ||
  advisoryObjects.some((entry) => entry.url !== allowedAdvisory)
) {
  fail(
    "found a high/critical advisory outside the narrowly scoped " +
      `${allowedAdvisory} exception`,
  );
}

const root = findingMap.get(allowedPackage);
if (!root) {
  fail(`the allowed advisory is not rooted at ${allowedPackage}`);
}

// npm reports transitive effects as package names. Walk that graph so an
// allowed root cannot accidentally mask a separate high/critical finding.
const allowedFindings = new Set([allowedPackage]);
const pending = [allowedPackage];
while (pending.length > 0) {
  const name = pending.pop();
  for (const effect of vulnerabilities[name]?.effects ?? []) {
    if (vulnerabilities[effect] && !allowedFindings.has(effect)) {
      allowedFindings.add(effect);
      pending.push(effect);
    }
  }
}

const unexpected = highOrCritical
  .map(([name]) => name)
  .filter((name) => !allowedFindings.has(name));
if (unexpected.length > 0) {
  fail(`unexpected high/critical findings: ${unexpected.join(", ")}`);
}

let lockfile;
try {
  lockfile = JSON.parse(readFileSync(lockPath, "utf8"));
} catch (error) {
  fail(`could not read lockfile: ${error.message}`);
}

const vulnerableNodes = root.nodes ?? [];
const lockedVersions = vulnerableNodes.map(
  (node) => lockfile.packages?.[node]?.version,
);
if (
  vulnerableNodes.length === 0 ||
  lockedVersions.some((version) => version !== allowedVersion)
) {
  fail(
    `the exception only covers ${allowedPackage}@${allowedVersion}; ` +
      `lockfile versions were ${lockedVersions.join(", ") || "not found"}`,
  );
}

let latestVersion;
try {
  const output = execFileSync(
    "npm",
    ["view", allowedPackage, "version", "--json"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
  try {
    latestVersion = JSON.parse(output);
    if (Array.isArray(latestVersion)) {
      latestVersion = latestVersion.at(-1);
    }
  } catch {
    latestVersion = output.replace(/^"|"$/g, "");
  }
} catch (error) {
  fail(`could not verify the upstream ${allowedPackage} release: ${error.message}`);
}

if (latestVersion !== allowedVersion) {
  fail(
    `upstream ${allowedPackage} is now ${latestVersion}; remove the exception ` +
      "and update the dependency",
  );
}

console.warn(
  `npm audit gate: allowing only ${allowedAdvisory} for ` +
    `${allowedPackage}@${allowedVersion}; upstream has not published a patch`,
);
