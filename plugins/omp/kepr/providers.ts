import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

interface Route { credential: string; host: string; route: string; variable: string }
const DEFAULTS: Record<string, [string, string]> = {
    anthropic: ["ANTHROPIC_API_KEY", "https://api.anthropic.com"],
    openai: ["OPENAI_API_KEY", "https://api.openai.com/v1"],
    xai: ["XAI_API_KEY", "https://api.x.ai/v1"],
    google: ["GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta"],
    groq: ["GROQ_API_KEY", "https://api.groq.com/openai/v1"],
    openrouter: ["OPENROUTER_API_KEY", "https://openrouter.ai/api/v1"],
    deepseek: ["DEEPSEEK_API_KEY", "https://api.deepseek.com/v1"],
    mistral: ["MISTRAL_API_KEY", "https://api.mistral.ai/v1"],
    cerebras: ["CEREBRAS_API_KEY", "https://api.cerebras.ai/v1"],
    "cloudflare-ai-gateway": ["CLOUDFLARE_AI_GATEWAY_API_KEY", "https://gateway.ai.cloudflare.com/compat"],
    "kktoken": ["KKTOKEN_API_KEY", "https://kktoken.cc/v1"],
    hcnsec: ["HCNSEC_API_KEY", "https://api.hcnsec.com/v1"],
};

function credentialRef(value: unknown): string | undefined {
    if (typeof value !== "string") return;
    if (/^[A-Z][A-Z0-9_]{0,127}$/.test(value)) return value;
    // Recognize only the documented lookup; never run a command or interpret a shell pipeline.
    return /^!kepr\s+get\s+([A-Z][A-Z0-9_]{0,127})(?:\s+--quiet)?\s*$/.exec(value)?.[1];
}

export function registerProviders(pi: ExtensionAPI, gate: string, metadata: unknown, config: any, env: Record<string, string | undefined>) {
    if (!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(gate) || !Array.isArray(metadata) || metadata.length > 64) {
        throw new Error("kepr: invalid OMP route metadata; restart with kepr agent run omp");
    }
    const routes: Route[] = metadata;
    const seen = new Set<string>();
    for (const r of routes) {
        if (!r || !/^[a-z0-9.-]+$/.test(r.host) || !/^[A-Z0-9_]{1,128}$/.test(r.credential)
            || r.route !== `https+${r.host}+${r.credential}` || !/^KEPR_OMP_KEY_[0-9]+$/.test(r.variable)
            || !env[r.variable]?.startsWith("kepr-ph-") || seen.has(r.route)) {
            throw new Error("kepr: invalid OMP route metadata; restart with kepr agent run omp");
        }
        seen.add(r.route);
    }
    const routed: string[] = [], unavailable: string[] = [];
    const providers = config?.providers ?? {};
    if (typeof providers !== "object" || Array.isArray(providers)) throw new Error("kepr: invalid OMP provider configuration");
    const names = new Set([...Object.keys(DEFAULTS), ...Object.keys(providers)]);
    for (const name of names) {
        const cfg = providers[name];
        if (cfg && (cfg.auth === "oauth" || cfg.auth === "none" || cfg.oauth)) continue;
        const defaults = DEFAULTS[name];
        // Explicit config wins, including unrecognized subscription helpers.
        const credential = cfg?.apiKey !== undefined ? credentialRef(cfg.apiKey) : defaults?.[0];
        if (!credential) continue;
        const candidates = routes.filter(r => r.credential === credential);
        if (!cfg && candidates.length === 0) continue;
        let url: URL | undefined;
        try {
            url = new URL(cfg?.baseUrl ?? defaults?.[1]);
            if (url.protocol !== "https:" || url.port || url.username || url.password || url.search || url.hash) url = undefined;
        } catch { /* Invalid endpoints are made unavailable without printing their contents. */ }
        const route = url && candidates.find(r => r.host === url!.hostname);
        if (!route) {
            env.KEPR_OMP_UNAVAILABLE = "kepr-ph-unavailable";
            pi.registerProvider(name, { baseUrl: gate + "/__kepr/unavailable", apiKey: "KEPR_OMP_UNAVAILABLE" });
            unavailable.push(`${name} (${credential}: no sealed binding for its HTTPS endpoint)`);
            continue;
        }
        pi.registerProvider(name, { baseUrl: `${gate}/${route.route}${url!.pathname.replace(/\/$/, "")}`, apiKey: route.variable });
        routed.push(name);
    }
    return { routed, unavailable };
}
