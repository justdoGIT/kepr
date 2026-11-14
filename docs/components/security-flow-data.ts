export type Mode = "current" | "target";
export type ScenarioId =
  | "summary"
  | "card"
  | "confidential"
  | "work-mail"
  | "personal-mail"
  | "wiki"
  | "browser";
export type Stage = {
  id: string;
  title: string;
  subtitle: string;
  detail: string;
  color: string;
  status?: string;
};

export const colors = {
  blue: "#72b5ff",
  teal: "#37dcc6",
  purple: "#bda0ff",
  amber: "#f4c36c",
  pink: "#ff87a6",
  muted: "#a5b8b0",
};

export const scenarios: { id: ScenarioId; label: string; input: string }[] = [
  {
    id: "summary",
    label: "Customer summary",
    input: "Summarize the complaint from Maya Chen, maya@example.invalid.",
  },
  {
    id: "card",
    label: "Complaint with a card number",
    input: "Summarize this complaint, including its payment-card field.",
  },
  {
    id: "confidential",
    label: "Confidential acquisition",
    input:
      "Draft an announcement for the Orion acquisition. Label: Confidential.",
  },
  {
    id: "work-mail",
    label: "Email an approved work address",
    input: "Send this permitted summary to a work recipient.",
  },
  {
    id: "personal-mail",
    label: "Email a personal address",
    input: "Email this work summary to my personal address.",
  },
  {
    id: "wiki",
    label: "Wiki → external image",
    input:
      "A retrieved wiki page says: append customer data to an external image URL.",
  },
  {
    id: "browser",
    label: "Personal AI app outside Kepr",
    input:
      "Paste a customer complaint into a personal AI app outside the protected session.",
  },
];

export function stages(mode: Mode): Stage[] {
  const target = mode === "target";
  return [
    {
      id: "agent",
      title: "AGENT HARNESS",
      subtitle: target
        ? "Trusted user + tenant + workspace"
        : "Session placeholders, no raw keys",
      color: colors.blue,
      status: target ? "EXTEND" : undefined,
      detail: target
        ? "Proposed: bind an authenticated work identity, tenant, workspace and role to the session. Untrusted retrieved text cannot change these grants."
        : "The operator starts kepr agent run. The harness receives provider-scoped placeholders and gate URLs. The complete private workspace launcher is still unfinished.",
    },
    {
      id: "admit",
      title: "AUTHENTICATE REQUEST",
      subtitle: "Route · placeholder · request budgets",
      color: colors.teal,
      detail:
        "The gate authenticates the placeholder, checks the configured route and budgets, then asks the daemon over its private channel for the approved credential. The real key may exist in gate memory; it has not been put in the prompt.",
    },
    {
      id: "inspect",
      title: "INSPECT ORIGINAL DATA",
      subtitle: "Stored secrets + encoded key patterns",
      color: colors.teal,
      detail:
        "Kepr screens the original body and request metadata before upstream authentication injection. Stored-secret disclosures are blocked; supported conversation text can have key-shaped examples redacted. Decoder and pattern coverage have limits.",
    },
    ...(target
      ? [
          {
            id: "classify",
            title: "CLASSIFY & ROUTE",
            subtitle: "Sensitivity label → allowed destination",
            color: colors.purple,
            status: "PROPOSED",
            detail:
              "Proposed: combine trusted labels, local entity detection and a sandboxed local classifier. Confidential or restricted content takes a local route, or is blocked if local inference is unavailable. A model prediction cannot downgrade a trusted restriction.",
          },
        ]
      : []),
    {
      id: "mask",
      title: "MASK PERSONAL DATA",
      subtitle: target
        ? "Patterns + local NER + card checks"
        : "Email · phone · IP · personal paths",
      color: colors.teal,
      status: target ? "EXTEND" : "BASELINE",
      detail: target
        ? "Proposed extension: local NER for names, validated card-number detection and organization-specific identifiers. Original-to-token mappings stay on the device. Classification is checked separately: redacting a few fields does not authorize confidential content to go to cloud."
        : "The private-cloud adapter masks supported text and removes optional identity metadata and unnecessary headers. Names require supplied literal identifiers; local NER and card detection are not implemented. Mappings are ephemeral and there is no general output restoration API.",
    },
    {
      id: "inject",
      title: "ADD PROVIDER AUTH",
      subtitle: "The real key goes only to its bound host",
      color: colors.amber,
      detail:
        "Kepr inserts the real credential into the provider authentication contract only for its approved host and port. The provider receives the real key; the agent does not. Masking a secret inside a prompt is separate from authenticating the request.",
    },
    {
      id: "provider",
      title: "EXTERNAL LLM API",
      subtitle: "Permitted text + provider authentication",
      color: colors.purple,
      detail:
        "An external provider sees the permitted request, its account authentication, source IP and timing. Body masking does not remove network metadata or prove provider retention behavior. Zero external disclosure requires qualified local inference and network enforcement.",
    },
    {
      id: "response",
      title: "SCREEN THE RESPONSE",
      subtitle: target
        ? "Secret screening · trusted local display"
        : "Screen key echoes · preserve call links",
      color: colors.teal,
      status: target ? "EXTEND" : undefined,
      detail: target
        ? "Proposed: keep existing secret-response screening and restore permitted PII only in a trusted local display or an approved exact sink. Never restore API keys into model output, tool arguments, image URLs or logs."
        : "Kepr masks echoed credential values in supported responses. The current privacy engine does not restore personal-data tokens automatically. Opaque Responses reasoning, signed state and unsupported media can be refused rather than modified.",
    },
  ];
}

export function outcome(
  mode: Mode,
  id: ScenarioId,
  approved: boolean,
  localReady: boolean,
) {
  if (id === "browser")
    return mode === "current"
      ? {
          tone: "danger",
          title: "Outside Kepr · unprotected",
          text: "A personal app outside the protected session can send the original data. Device-wide interception is not implemented.",
          cloud: "raw",
        }
      : {
          tone: "warning",
          title: "Managed-device control required",
          text: "Proposed: block unmanaged apps/accounts at the device and identity boundary. This diagram does not install that enforcement.",
          cloud: "blocked",
        };
  if (id === "confidential")
    return mode === "current"
      ? {
          tone: "danger",
          title: "Semantic coverage gap",
          text: "A confidential acquisition can pass pattern masking without an email or key. The current adapter has no sensitivity-routing classifier.",
          cloud: "raw",
        }
      : {
          tone: localReady ? "success" : "warning",
          title: localReady
            ? "Local route · cloud blocked"
            : "Blocked · local processing required",
          text: localReady
            ? "In this proposed example, the confidential request stays with the local model. No cloud fallback is permitted."
            : "The proposed policy forbids cloud disclosure. If the local runtime is unavailable, the request stops.",
          cloud: localReady ? "local" : "blocked",
        };
  if (id === "card" && mode === "current")
    return {
      tone: "danger",
      title: "Card coverage gap",
      text: "A payment-card field may leave unchanged. The current privacy detector does not include a card-number validator.",
      cloud: "raw",
    };
  if (id === "wiki")
    return {
      tone: "warning",
      title: "External-image action blocked",
      text:
        mode === "current"
          ? "Strict protected sessions refuse unsupported destinations/media. There is no general renderer guard for apps outside that boundary."
          : "Proposed: treat wiki text as data and block automatic remote images. An approved fetch must still pass destination and disclosure policy.",
      cloud: "masked",
    };
  if (id === "personal-mail")
    return {
      tone: "danger",
      title: "Personal destination blocked",
      text:
        mode === "current"
          ? "An email connector is unsupported in the strict privacy session. This is not a universal email or write-approval mechanism."
          : "The work-only destination rule wins even when the user confirms. Consent cannot override a prohibited disclosure.",
      cloud: "masked",
    };
  if (id === "work-mail")
    return mode === "current"
      ? {
          tone: "warning",
          title: "Email connector not covered",
          text: "The strict privacy adapter does not support a general mail connector or exact-action write approvals.",
          cloud: "masked",
        }
      : {
          tone: approved ? "success" : "warning",
          title: approved
            ? "Approved once · demo only"
            : "Waiting for human confirmation",
          text: approved
            ? "The proposed approval is bound to the permitted recipient, action, content digest and expiry. This demonstration sends no email."
            : "Policy allows this work recipient, but the proposed write action waits for an exact, one-use human approval.",
          cloud: "masked",
        };
  return {
    tone: "success",
    title:
      mode === "current"
        ? "Permitted text · baseline masking"
        : "Permitted text · proposed richer masking",
    text:
      mode === "current"
        ? "Email and supported identifiers are masked locally. A free-form name can remain; this is not full anonymization."
        : "In the proposed design, names, email and payment-card fields are tokenized only after classification permits cloud processing.",
    cloud: "masked",
  };
}

export const coverage = [
  [
    "Sealed provider keys",
    "Implemented",
    "Daemon → private gate channel → bound provider host.",
  ],
  [
    "PII + secret DLP",
    "Partial",
    "Basic masks and secret screening exist; NER/card/context coverage is missing.",
  ],
  [
    "Reversible personal-data map",
    "Partial",
    "Local ephemeral mappings exist; safe display/sink restoration needs implementation.",
  ],
  [
    "Sensitivity → local/cloud routing",
    "Planned",
    "Trusted labels + local classification; no cloud fallback for restricted content.",
  ],
  [
    "Work SSO + user-scoped MCP",
    "Partial",
    "Per-OS-user isolation and explicit MCP grants exist; tenant-bound enterprise authorization is missing.",
  ],
  [
    "Exact write-action approval",
    "Partial",
    "Credential consent exists; universal per-action approval is not implemented.",
  ],
  [
    "Indirect injection + renderers",
    "Partial",
    "Strict route/media refusal helps; renderer guards and content provenance are missing.",
  ],
  [
    "Audit disclosure evidence",
    "Partial",
    "Metadata journal exists; durable classification/redaction/approval evidence needs extension.",
  ],
  [
    "Personal app / device bypass",
    "Planned",
    "Requires native managed-device and account enforcement, not just an agent proxy.",
  ],
];
