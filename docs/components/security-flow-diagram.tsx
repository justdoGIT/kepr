"use client";

import { colors, stages, type Mode } from "./security-flow-data";

export function SecurityFlowDiagram({
  mode,
  selected,
  cloud,
  localReady,
  onSelect,
}: {
  mode: Mode;
  selected: string;
  cloud: string;
  localReady: boolean;
  onSelect: (id: string) => void;
}) {
  const list = stages(mode);
  const positions = list.map((stage, i) => ({
    ...stage,
    y:
      80 + i * 140 + (i >= list.findIndex((s) => s.id === "provider") ? 35 : 0),
  }));
  const node = (id: string) => positions.find((s) => s.id === id)!;
  const provider = node("provider"),
    response = node("response");
  const height = response.y + 190;
  const blocked = cloud === "blocked" || cloud === "local";
  const arrow = (d: string, color = colors.muted, dashed = false) => (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth="2"
      strokeDasharray={dashed ? "6 6" : undefined}
      markerEnd="url(#flow-arrow)"
      opacity=".8"
    />
  );
  const tile = (
    x: number,
    y: number,
    width: number,
    title: string,
    lines: string[],
    color: string,
    proposed = false,
  ) => (
    <g>
      <rect
        x={x}
        y={y}
        width={width}
        height={38 + lines.length * 23}
        rx="12"
        fill="#18221f"
        stroke={color}
        strokeWidth="1.5"
        strokeDasharray={proposed ? "5 5" : undefined}
      />
      <text x={x + 18} y={y + 28} fontSize="15" fontWeight="750" fill={color}>
        {title}
      </text>
      {lines.map((line, i) => (
        <text
          key={line}
          x={x + 18}
          y={y + 54 + i * 23}
          fontSize="14"
          fill="#b6c7bf"
        >
          {line}
        </text>
      ))}
    </g>
  );
  return (
    <svg
      data-testid="flow-svg"
      xmlns="http://www.w3.org/2000/svg"
      width="980"
      height={height}
      viewBox={`0 0 980 ${height}`}
      role="img"
      aria-labelledby="flow-title flow-description"
      style={{
        fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif",
        background: "#101715",
      }}
    >
      <title id="flow-title">
        {mode === "current"
          ? "How Kepr works in the current source"
          : "Proposed Kepr security controls"}
      </title>
      <desc id="flow-description">
        Local agent, authenticated gate, original-data secret screening,
        personal-data masks, host-bound credential injection, external provider
        and screened return. Dashed boxes are proposed controls. API keys never
        enter model text.
      </desc>
      <defs>
        <marker
          id="flow-arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path
            d="M 1 1 L 9 5 L 1 9"
            fill="none"
            stroke="#a5b8b0"
            strokeWidth="1.5"
          />
        </marker>
      </defs>
      <rect
        x="16"
        y="20"
        width="948"
        height={provider.y - 66}
        rx="20"
        fill="#12201a"
        stroke="#315c4b"
        strokeWidth="1"
      />
      <text
        x="36"
        y="49"
        fill="#83b69f"
        fontSize="13"
        fontWeight="700"
        letterSpacing="2"
      >
        LOCAL DEVICE · PROTECTED AGENT SESSION
      </text>
      <text x="944" y="49" textAnchor="end" fill="#adc0b5" fontSize="12">
        {mode === "current" ? "CURRENT SOURCE" : "PROPOSED DESIGN"}
      </text>
      {positions
        .slice(0, -1)
        .map((s, i) =>
          arrow(
            `M 490 ${s.y + 92} V ${positions[i + 1].y - 10}`,
            s.id === "inject" && blocked ? colors.pink : colors.muted,
            s.id === "inject" && blocked,
          ),
        )}
      {tile(
        35,
        node("admit").y + 12,
        244,
        "ENCRYPTED STORE",
        [
          "Daemon validates bindings",
          "Private resolve channel only",
          "No daemon socket for agent",
        ],
        colors.amber,
      )}
      {arrow(`M 279 ${node("admit").y + 63} H 324`, colors.amber)}
      {tile(
        690,
        node("mask").y,
        248,
        "LOCAL PII MAP",
        [
          "Original ↔ session token",
          "Memory-only, bounded map",
          mode === "target"
            ? "Approved restoration only"
            : "No automatic restoration",
        ],
        colors.teal,
        mode === "target",
      )}
      {arrow(`M 655 ${node("mask").y + 44} H 683`, colors.teal, true)}
      {tile(
        690,
        node("inspect").y - 10,
        248,
        "LOCAL AUDIT",
        mode === "current"
          ? [
              "Time · session · provider",
              "Method · path · status",
              "No prompt bodies by default",
            ]
          : [
              "Add labels + redaction types",
              "Exact approval + destination",
              "Durable evidence, no raw PII",
            ],
        colors.blue,
        mode === "target",
      )}
      {arrow(`M 655 ${node("inspect").y + 38} H 683`, colors.blue, true)}
      {mode === "target" && (
        <>
          {tile(
            35,
            node("classify").y - 10,
            244,
            "LOCAL MODEL",
            [
              "Confidential stays local",
              localReady
                ? "Ready in this demo only"
                : "Unavailable? Stop the request",
              "Never silently use cloud",
            ],
            colors.purple,
            true,
          )}
          {arrow(`M 325 ${node("classify").y + 41} H 285`, colors.purple, true)}
          {localReady &&
            arrow(
              `M 155 ${node("classify").y + 103} H 22 V ${response.y + 50} H 317`,
              colors.purple,
              true,
            )}
        </>
      )}
      <line
        x1="35"
        y1={provider.y - 27}
        x2="945"
        y2={provider.y - 27}
        stroke="#526058"
        strokeDasharray="6 6"
      />
      <text
        x="35"
        y={provider.y - 7}
        fill={colors.pink}
        fontSize="12"
        fontWeight="700"
        letterSpacing="1.3"
      >
        NETWORK BOUNDARY · CLOUD IS A THIRD PARTY
      </text>
      <line
        x1="35"
        y1={response.y - 18}
        x2="945"
        y2={response.y - 18}
        stroke="#526058"
        strokeDasharray="6 6"
      />
      <text
        x="35"
        y={response.y + 8}
        fill="#83b69f"
        fontSize="12"
        fontWeight="700"
        letterSpacing="1.3"
      >
        RETURN TO DEVICE
      </text>
      {positions.map((s) => (
        <g
          key={s.id}
          role="button"
          tabIndex={0}
          aria-label={`${s.title} details`}
          onClick={() => onSelect(s.id)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              onSelect(s.id);
            }
          }}
          style={{
            cursor: "pointer",
            opacity:
              (s.id === "provider" || s.id === "inject") && blocked ? 0.45 : 1,
          }}
        >
          <rect
            x="325"
            y={s.y}
            width="330"
            height="92"
            rx="12"
            fill={s.id === selected ? "#22372d" : "#1a2420"}
            stroke={s.color}
            strokeWidth={s.id === selected ? 3 : 1.5}
            strokeDasharray={
              s.status === "PROPOSED" || s.status === "EXTEND"
                ? "6 4"
                : undefined
            }
          />
          <circle cx="344" cy={s.y + 20} r="3" fill={s.color} />
          <text
            x="362"
            y={s.y + 25}
            fontSize="12"
            fill={s.color}
            fontWeight="650"
          >
            {String(positions.indexOf(s) + 1).padStart(2, "0")}
            {s.status ? ` / ${s.status}` : ""}
          </text>
          <text
            x="343"
            y={s.y + 50}
            fontSize="19"
            fontWeight="750"
            fill="#e9f2ed"
          >
            {s.title}
          </text>
          <text x="343" y={s.y + 73} fontSize="14" fill="#b6c7bf">
            {s.subtitle}
          </text>
        </g>
      ))}
      {tile(
        35,
        provider.y + 2,
        244,
        blocked ? "NO CLOUD REQUEST" : "PROVIDER CAN SEE",
        blocked
          ? ["Local route or refusal", "No cloud fallback"]
          : [
              "Permitted request content",
              "Its authentication account",
              "Source IP + request timing",
            ],
        blocked ? colors.pink : colors.purple,
      )}
      {tile(
        690,
        response.y,
        248,
        mode === "target" ? "TOOL ACTION GUARD" : "TOOL ACTIONS",
        mode === "target"
          ? [
              "Policy + exact recipient",
              "One-use approval for writes",
              "Consent cannot override deny",
            ]
          : [
              "Explicit MCP grants exist",
              "Universal write guard missing",
              "Other apps are outside scope",
            ],
        colors.amber,
        mode === "target",
      )}
      {arrow(`M 655 ${response.y + 48} H 683`, colors.amber, mode === "target")}
      <text
        x="490"
        y={height - 58}
        textAnchor="middle"
        fill="#a5b8b0"
        fontSize="13"
      >
        {mode === "current"
          ? "PII tokens stay in the response. General rehydration is not implemented."
          : "Restore permitted PII only at a trusted local display or approved exact sink."}
      </text>
      <text
        x="490"
        y={height - 32}
        textAnchor="middle"
        fill="#6f9681"
        fontSize="12"
      >
        Solid = current foundation · Dashed = proposed extension · Never restore
        API keys into prompts or tools
      </text>
    </svg>
  );
}
