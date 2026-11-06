import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

interface Route { credential: string; host: string; route: string; variable: string }
type RecordValue = Record<string, unknown>;

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
    yzmao: ["YZMAO_API_KEY", "https://api.yzmao.cn"],
    qianxing: ["QIANXING_API_KEY", "https://fast.qianxing.pro"],
    foundable: ["FOUNDBABLE_API_KEY", "https://foundable.com"],
    zcode: ["ZCODE_API_KEY", "https://zcode.z.ai"],
    museai: ["MUSEAI_API_KEY", "https://muse.ai"],
    bluesminds: ["BLUESMINDS_API_KEY", "https://api.bluesminds.com"],
    emtf: ["EMTF_API_KEY", "https://emtf.aipm9527.online"],
    freemodel: ["FREEMODEL_API_KEY", "https://freemodel.dev"],
    geminiapi: ["GEMINIAPI_API_KEY", "https://gemini-api.online"],
    justdowork: ["JUSTDOWORK_API_KEY", "https://api.justwoker.icu"],
    seekai: ["SEEKAI_API_KEY", "https://seekai.cc"],
    aerolink: ["AEROLINK_API_KEY", "https://aerolink.lat"],
    apimaster: ["APIMASTER_API_KEY", "https://apimaster.ai"],
    artbloom: ["ARTBLOOM_API_KEY", "https://api.artbloom.tech"],
    ashna: ["ASHNA_API_KEY", "https://app.ashna.ai"],
    bearlab: ["BEARLAB_API_KEY", "https://bearlab.ai"],
    budsai: ["BUDSAI_API_KEY", "https://apichat.budsin.dev"],
    cleanapis: ["CLEANAPIS_API_KEY", "https://cleanapis.com"],
    codecraft: ["CODECRAFT_API_KEY", "https://codecraftapi.com"],
    codexrelay: ["CODEXRELAY_API_KEY", "https://codex-relay.codes"],
    directrouter: ["DIRECTROUTER_API_KEY", "https://directrouter.pages.dev"],
    flushai: ["FLUSHAI_API_KEY", "https://flushapi.fun"],
    freemodelin: ["FREEMODELIN_API_KEY", "https://freemodel.in"],
    geaix: ["GEAIX_API_KEY", "https://geaix.com"],
    helyx: ["HELYX_API_KEY", "https://helyxai.space"],
    ireze: ["IREZE_API_KEY", "https://ireze.site"],
    jasper: ["JASPER_API_KEY", "https://api.yjs.im"],
    llmsrelay: ["LLMSRELAY_API_KEY", "https://llmsrelay.com"],
    lmzero: ["LMZERO_API_KEY", "https://17.wtf"],
    localai: ["LOCALAI_API_KEY", "https://local.ai"],
    marsai: ["MARSAI_API_KEY", "https://marsai.click"],
    miarouter: ["MIAROUTER_API_KEY", "https://www.miarouter.online"],
    omnirush: ["OMNIRUSH_API_KEY", "https://omnirush.ai"],
    onomeo: ["ONOMEO_API_KEY", "https://onomeo.com"],
    orbelis: ["ORBELIS_API_KEY", "https://nova.vcrauo.com"],
    odyssey: ["ODYSSEY_API_KEY", "https://odysseyapi.tech"],
    orvapi: ["ORVAPI_API_KEY", "https://www.orvapi.com"],
    synterolink: ["SYNTEROLINK_API_KEY", "https://synterolink.com"],
    tokenbom: ["TOKENBOM_API_KEY", "https://tokenbom.com"],
    tokenforge: ["TOKENFORGE_API_KEY", "https://tokenforge.ai.studio"],
    tokenlayer: ["TOKENLAYER_API_KEY", "https://tokenlayer.net"],
    tokenreply: ["TOKENREPLY_API_KEY", "https://www.tokenreply.com"],
    toptools: ["TOPTOOLS_API_KEY", "https://top-tools-ai.com"],
    unorouter: ["UNROUTER_API_KEY", "https://unorouter.com"],
    utim: ["UTIM_API_KEY", "https://utim.dev"],
    vyceai: ["VYCEAI_API_KEY", "https://vyceai.com"],
    vsllm: ["VSLLM_API_KEY", "https://vsllm.cc"],
    zerocat: ["ZEROCAT_API_KEY", "https://zero.cat"],
    qronos: ["QRONOS_API_KEY", "https://qronos.me"],
    pixrouter: ["PIXROUTER_API_KEY", "https://pixrouter.com"],
    kvotum: ["KVOTUM_API_KEY", "https://myapi.buzz"],
    moyuu: ["MOYUUI_API_KEY", "https://moyuu.cc"],
    freepi: ["FREEPI_API_KEY", "https://freepi.ai"],
    floodgate: ["FLOODGATE_API_KEY", "https://floodgate.dev"],
    fxqidian: ["FXQIDIAN_API_KEY", "https://fxqidian.de5.net"],
    kiosapi: ["KIOSAPI_API_KEY", "https://kiosapi.com"],
    hyxapi: ["HYXAPI_API_KEY", "https://hyxware.com"],
    xkiro: ["XKIRO_API_KEY", "https://xkiro.com"],
    threerouter: ["THREEROUTER_API_KEY", "https://www.threerouter.com"],
    goroutine: ["GOROUTINE_API_KEY", ""],
    selora: ["SELORA_API_KEY", "https://api.selora.lol/v1"],
    hcnsec: ["HCNSEC_API_KEY", "https://api.hcnsec.com/v1"],
    kktoken: ["KKTOKEN_API_KEY", "https://kktoken.cc/v1"],
};

function isRecord(value: unknown): value is RecordValue {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function credentialRef(value: unknown): string | undefined {
    if (typeof value !== "string") return;
    if (/^[A-Z][A-Z0-9_]{0,127}$/.test(value)) return value;
    return /^!kepr\s+get\s+([A-Z][A-Z0-9_]{0,127})(?:\s+--quiet)?\s*$/.exec(value)?.[1];
}

function invalid(): never {
    throw new Error("kepr: invalid OMP route metadata; restart with kepr agent run omp");
}

export function registerProviders(
    pi: ExtensionAPI,
    gate: string,
    metadata: unknown,
    config: unknown,
    env: Record<string, string | undefined>,
) {
    if (!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(gate) || !Array.isArray(metadata) || metadata.length > 64) invalid();
    const routes: Route[] = [];
    const seen = new Set<string>();
    for (const candidate of metadata) {
        if (!isRecord(candidate)) invalid();
        const host = candidate.host;
        const credential = candidate.credential;
        const route = candidate.route;
        const variable = candidate.variable;
        if (typeof host !== "string" || !/^[a-z0-9.-]+$/.test(host)
            || typeof credential !== "string" || !/^[A-Z0-9_]{1,128}$/.test(credential)
            || route !== `https+${host}+${credential}`
            || typeof variable !== "string" || !/^KEPR_OMP_KEY_[0-9]+$/.test(variable)
            || !env[variable]?.startsWith("kepr-ph-") || seen.has(route)) invalid();
        routes.push({ host, credential, route, variable });
        seen.add(route);
    }

    const root = isRecord(config) ? config : {};
    const configured = root.providers;
    if (configured !== undefined && !isRecord(configured)) throw new Error("kepr: invalid OMP provider configuration");
    const providers = isRecord(configured) ? configured : {};
    const routed: string[] = [];
    const unavailable: string[] = [];
    const names = new Set([...Object.keys(DEFAULTS), ...Object.keys(providers)]);
    for (const name of names) {
        const raw = providers[name];
        if (raw !== undefined && !isRecord(raw)) throw new Error("kepr: invalid OMP provider configuration");
        const cfg = isRecord(raw) ? raw : undefined;
        const auth = cfg?.auth;
        if (auth === "oauth" || auth === "none" || cfg?.oauth) continue;
        const defaults = DEFAULTS[name];
        const credential = cfg?.apiKey !== undefined ? credentialRef(cfg.apiKey) : defaults?.[0];
        if (!credential) continue;
        const candidates = routes.filter(r => r.credential === credential);
        if (!cfg && candidates.length === 0) continue;
        const endpoint = cfg?.baseUrl !== undefined && typeof cfg.baseUrl !== "string" ? undefined : cfg?.baseUrl ?? defaults?.[1];
        let url: URL | undefined;
        try {
            url = new URL(endpoint ?? "");
            if (url.protocol !== "https:" || url.port || url.username || url.password || url.search || url.hash) url = undefined;
        } catch { /* Invalid endpoints are made unavailable without printing their contents. */ }
        const route = url ? candidates.find(r => r.host === url.hostname) : undefined;
        if (!route || !url) {
            env.KEPR_OMP_UNAVAILABLE = "kepr-ph-unavailable";
            pi.registerProvider(name, { baseUrl: gate + "/__kepr/unavailable", apiKey: "KEPR_OMP_UNAVAILABLE" });
            unavailable.push(`${name} (${credential}: no sealed binding for its HTTPS endpoint)`);
            continue;
        }
        pi.registerProvider(name, { baseUrl: `${gate}/${route.route}${url.pathname.replace(/\/$/, "")}`, apiKey: route.variable });
        routed.push(name);
    }
    return { routed, unavailable };
}
