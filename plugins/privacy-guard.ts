import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface PrivacyPolicy {
	strict: boolean;
	allowed_providers: string[];
	restricted_repos: string[];
}

export interface AgentModelInfo {
	provider?: string;
	baseUrl?: string;
}

export interface AgentHookContext {
	cwd?: string;
	workspace?: string;
	provider?: string;
	baseUrl?: string;
	model?: AgentModelInfo;
	ui?: {
		notify?: (message: string, level?: "info" | "warning" | "error") => void;
	};
}

export interface AgentEvent {
	provider?: string;
	baseUrl?: string;
	model?: AgentModelInfo;
	toolName?: string;
	input?: Record<string, unknown>;
	text?: string;
	prompt?: string;
}

export interface AgentExtensionAPI {
	on?: (
		event: string,
		handler: (
			event: AgentEvent,
			ctx?: AgentHookContext,
		) => unknown | Promise<unknown>,
	) => void;
}

export const DEFAULT_ALLOWED_PROVIDERS = [
	"anthropic",
	"claude-waddhwaa",
	"codex-waddhwaa",
	"openai",
	"openai-codex",
	"google",
	"google-antigravity",
	"google-vertex",
	"groq",
	"mistral",
	"nvidia",
	"xai",
	"deepseek",
	"ollama",
	"ollama-cloud",
	"local-decider",
];

export const DEFAULT_RESTRICTED_REPOS: string[] = [];

const STRICT_MARKERS = [
	".kepr-strict",
	".privacy-strict",
	".agent-strict",
	".omp-strict",
	".git/kepr-strict",
	".git/privacy-strict",
	".git/agent-strict",
	".git/omp-strict",
];

const FIRST_PARTY_HOST_MAP: Record<string, string> = {
	"api.anthropic.com": "anthropic",
	"api.openai.com": "openai",
	"chatgpt.com": "openai",
	"generativelanguage.googleapis.com": "google",
	"aiplatform.googleapis.com": "google-vertex",
	"api.x.ai": "xai",
	"api.deepseek.com": "deepseek",
	"api.groq.com": "groq",
	"api.mistral.ai": "mistral",
	"integrate.api.nvidia.com": "nvidia",
	"ollama.com": "ollama-cloud",
};

function cleanScalar(raw: string): string {
	let s = raw.trim();
	const hash = s.indexOf("#");
	if (hash !== -1 && !s.startsWith('"') && !s.startsWith("'")) {
		s = s.slice(0, hash);
	}
	return s.trim().replace(/^["']|["']$/g, "").trim().toLowerCase();
}

export function parsePolicyYaml(content: string): PrivacyPolicy {
	let strict = true;
	const allowed: string[] = [];
	const repos: string[] = [];
	let sec = "";

	for (const rawLine of content.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) continue;
		if (line.startsWith("strict:")) {
			const val = cleanScalar(line.slice("strict:".length));
			strict = val !== "false" && val !== "0" && val !== "no";
			sec = "";
		} else if (line.startsWith("allowed_providers:")) {
			sec = "allowed";
		} else if (line.startsWith("restricted_repos:")) {
			sec = "repos";
		} else if (line.startsWith("-")) {
			const val = cleanScalar(line.slice(1));
			if (!val) continue;
			if (sec === "allowed" && !allowed.includes(val)) allowed.push(val);
			else if (sec === "repos" && !repos.includes(val)) repos.push(val);
		} else if (line.includes(":")) {
			sec = "";
		}
	}

	return {
		strict,
		allowed_providers: allowed.length > 0 ? allowed : [...DEFAULT_ALLOWED_PROVIDERS],
		restricted_repos: repos.length > 0 ? repos : [...DEFAULT_RESTRICTED_REPOS],
	};
}

export function policySearchPaths(
	env: Record<string, string | undefined> = process.env,
	homeDir: string = homedir(),
): string[] {
	const paths: string[] = [];
	if (env.KEPR_PRIVACY_POLICY) paths.push(env.KEPR_PRIVACY_POLICY);
	try {
		paths.push(join(dirname(fileURLToPath(import.meta.url)), "privacy-policy.yaml"));
	} catch {}
	if (env.XDG_CONFIG_HOME) {
		paths.push(
			join(env.XDG_CONFIG_HOME, "kepr", "privacy-policy.yaml"),
			join(env.XDG_CONFIG_HOME, "omp", "agent", "privacy-policy.yaml"),
		);
	}
	for (const key of ["PI_CODING_AGENT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME"]) {
		if (env[key]) paths.push(join(env[key] as string, "privacy-policy.yaml"));
	}
	if (homeDir) {
		for (const rel of [
			".config/kepr/privacy-policy.yaml",
			".config/omp/agent/privacy-policy.yaml",
			".config/pi/agent/privacy-policy.yaml",
			".pi/agent/privacy-policy.yaml",
			".claude/privacy-policy.yaml",
			".codex/privacy-policy.yaml",
		]) {
			paths.push(join(homeDir, rel));
		}
	}
	return paths;
}

export function loadPrivacyPolicy(
	env: Record<string, string | undefined> = process.env,
	homeDir: string = homedir(),
): PrivacyPolicy {
	for (const p of policySearchPaths(env, homeDir)) {
		try {
			if (existsSync(p)) return parsePolicyYaml(readFileSync(p, "utf-8"));
		} catch {}
	}
	return {
		strict: true,
		allowed_providers: [...DEFAULT_ALLOWED_PROVIDERS],
		restricted_repos: [...DEFAULT_RESTRICTED_REPOS],
	};
}

function inspectGitConfig(repoRoot: string, policy: PrivacyPolicy): boolean {
	try {
		const dotGit = join(repoRoot, ".git");
		let cfgPath = join(dotGit, "config");
		try {
			const text = readFileSync(dotGit, "utf-8").trim();
			if (text.startsWith("gitdir:")) {
				const rel = text.slice("gitdir:".length).trim();
				cfgPath = join(isAbsolute(rel) ? rel : resolve(repoRoot, rel), "config");
			}
		} catch {}
		if (!existsSync(cfgPath)) return false;
		let section = "";
		for (const raw of readFileSync(cfgPath, "utf-8").split(/\r?\n/)) {
			const line = raw.trim();
			if (!line || line.startsWith("#") || line.startsWith(";")) continue;
			if (line.startsWith("[") && line.endsWith("]")) {
				section = line.slice(1, -1).trim().toLowerCase();
				continue;
			}
			const eq = line.indexOf("=");
			if (eq === -1) continue;
			const key = line.slice(0, eq).trim().toLowerCase();
			const val = cleanScalar(line.slice(eq + 1));
			if (
				["kepr", "privacy", "agent", "omp"].includes(section) &&
				["privacy", "strict"].includes(key) &&
				["strict", "true", "1", "yes"].includes(val)
			) {
				return true;
			}
			if (section.startsWith("remote ") && key === "url") {
				const parts = val.replace(/\/+$/, "").replace(/\.git$/, "").split(/[/:]/);
				const slug = (parts[parts.length - 1] || "").toLowerCase();
				if (slug && policy.restricted_repos.includes(slug)) return true;
			}
		}
	} catch {}
	return false;
}

export function isRestrictedRepo(
	cwd: string,
	policy: PrivacyPolicy = loadPrivacyPolicy(),
): boolean {
	if (!policy.strict) return false;
	let dir = resolve(cwd);
	while (true) {
		if (STRICT_MARKERS.some((m) => existsSync(join(dir, m)))) return true;
		const folder = basename(dir).toLowerCase();
		const full = dir.toLowerCase();
		for (const restricted of policy.restricted_repos) {
			const r = restricted.replace(/\/+$/, "").toLowerCase();
			if (r && (folder === r || full === r || full.endsWith(`/${r}`))) return true;
		}
		if (existsSync(join(dir, ".git"))) return inspectGitConfig(dir, policy);
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return false;
}

function canonicalProviderForHost(host: string): string | undefined {
	const h = host.trim().split(":")[0].toLowerCase();
	if (FIRST_PARTY_HOST_MAP[h]) return FIRST_PARTY_HOST_MAP[h];
	if (h.endsWith("-aiplatform.googleapis.com")) return "google-vertex";
	return undefined;
}

export function isProviderAllowed(
	providerOrUrl: string | undefined | null,
	policy: PrivacyPolicy = loadPrivacyPolicy(),
): boolean {
	if (!providerOrUrl) return false;
	const s = providerOrUrl.trim().toLowerCase();
	if (!s) return false;
	if (["db:", "aws:", "kube:", "cf:", "ssh:", "tcp:"].some((p) => s.startsWith(p))) return true;
	const allowed = new Set(policy.allowed_providers.map((p) => p.toLowerCase()));
	if (s.startsWith("https+") || s.startsWith("http+")) {
		const host = s.split("+")[1] || "";
		const mapped = canonicalProviderForHost(host);
		return (mapped !== undefined && allowed.has(mapped)) || allowed.has(host);
	}
	if (s.startsWith("https://") || s.startsWith("http://")) {
		try {
			const host = new URL(s).hostname.toLowerCase();
			if (host === "127.0.0.1" || host === "localhost" || host === "::1") return true;
			const mapped = canonicalProviderForHost(host);
			return (mapped !== undefined && allowed.has(mapped)) || allowed.has(host);
		} catch {
			return false;
		}
	}
	if (allowed.has(s)) return true;
	if (s.includes("/") && allowed.has(s.split("/")[0])) return true;
	const mapped = canonicalProviderForHost(s);
	return mapped !== undefined && allowed.has(mapped);
}

export function filterEligibleProviders<T extends { provider: string }>(
	routes: readonly T[],
	cwd: string = process.cwd(),
	policy: PrivacyPolicy = loadPrivacyPolicy(),
): T[] {
	if (!isRestrictedRepo(cwd, policy)) return [...routes];
	return routes.filter((r) => isProviderAllowed(r.provider, policy));
}

export function evaluatePrivacyGuard(params: {
	cwd?: string;
	provider?: string;
	baseUrl?: string;
	policy?: PrivacyPolicy;
	env?: Record<string, string | undefined>;
}): { restricted: boolean; allowed: boolean; provider?: string; reason?: string } {
	const env = params.env ?? process.env;
	const policy = params.policy ?? loadPrivacyPolicy(env);
	const cwd = params.cwd || process.cwd();
	const restricted = isRestrictedRepo(cwd, policy);
	const provider =
		params.provider ||
		env.KEPR_AGENT_PROVIDER ||
		env.AGENT_PROVIDER ||
		env.OMP_PROVIDER ||
		env.PI_PROVIDER ||
		env.LLM_PROVIDER;
	const baseUrl = params.baseUrl || env.ANTHROPIC_BASE_URL || env.OPENAI_BASE_URL;

	if (!restricted) return { restricted: false, allowed: true, provider };
	if (provider && !isProviderAllowed(provider, policy)) {
		return {
			restricted: true,
			allowed: false,
			provider,
			reason: `[PRIVACY GUARD BLOCKED] Third-party provider '${provider}' is forbidden in this restricted repository. Only approved first-party/local providers are eligible. Allowed providers: ${policy.allowed_providers.join(", ")}`,
		};
	}
	if (baseUrl && !isProviderAllowed(baseUrl, policy)) {
		return {
			restricted: true,
			allowed: false,
			provider: baseUrl,
			reason: `[PRIVACY GUARD BLOCKED] Third-party endpoint '${baseUrl}' is forbidden in this restricted repository. Allowed providers: ${policy.allowed_providers.join(", ")}`,
		};
	}
	return { restricted: true, allowed: true, provider };
}

function resolveContext(event?: AgentEvent, ctx?: AgentHookContext) {
	return {
		cwd: ctx?.cwd || ctx?.workspace || process.cwd(),
		provider: ctx?.model?.provider || ctx?.provider || event?.model?.provider || event?.provider,
		baseUrl: ctx?.model?.baseUrl || ctx?.baseUrl || event?.model?.baseUrl || event?.baseUrl,
	};
}

export function registerPrivacyGuard(
	agent: AgentExtensionAPI,
	options?: { policy?: PrivacyPolicy },
) {
	const getPolicy = () => options?.policy ?? loadPrivacyPolicy();
	if (typeof agent?.on === "function") {
		agent.on("session_start", async (event, ctx) => {
			const policy = getPolicy();
			const { cwd, provider, baseUrl } = resolveContext(event, ctx);
			const res = evaluatePrivacyGuard({ cwd, provider, baseUrl, policy });
			if (!res.restricted) return;
			if (!res.allowed) {
				ctx?.ui?.notify?.(
					`Privacy Guard ACTIVE: Restricted repo detected (${basename(cwd)}). Current provider '${res.provider}' is NOT allowed! Switch to an eligible first-party provider (${policy.allowed_providers.join(", ")}).`,
					"error",
				);
			} else {
				ctx?.ui?.notify?.(
					`Privacy Guard: Active repository (${basename(cwd)}) enforces first-party/local provider eligibility.`,
					"info",
				);
			}
		});
		agent.on("tool_call", async (event, ctx) => {
			const res = evaluatePrivacyGuard({ ...resolveContext(event, ctx), policy: getPolicy() });
			if (!res.allowed) return { block: true, reason: res.reason };
		});
		agent.on("before_agent_start", async (event, ctx) => {
			const res = evaluatePrivacyGuard({ ...resolveContext(event, ctx), policy: getPolicy() });
			if (!res.allowed && res.reason) {
				ctx?.ui?.notify?.(res.reason, "error");
				throw new Error(res.reason);
			}
		});
		agent.on("input", async (event, ctx) => {
			const policy = getPolicy();
			const { cwd, provider, baseUrl } = resolveContext(event, ctx);
			if (!isRestrictedRepo(cwd, policy) || (event?.text || "").trim().startsWith("/")) {
				return { action: "continue" };
			}
			const res = evaluatePrivacyGuard({ cwd, provider, baseUrl, policy });
			if (!res.allowed && res.reason) {
				ctx?.ui?.notify?.(res.reason, "error");
				return { action: "handled" };
			}
			return { action: "continue" };
		});
	}
	return {
		name: "kepr-privacy-guard",
		evaluatePrivacyGuard,
		isRestrictedRepo,
		isProviderAllowed,
		filterEligibleProviders,
		loadPrivacyPolicy,
	};
}

export default function privacyGuardPlugin(agent: AgentExtensionAPI) {
	return registerPrivacyGuard(agent);
}
