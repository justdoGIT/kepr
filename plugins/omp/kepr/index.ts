// kepr extension for oh-my-pi (omp).
//
// Protected sessions route configured providers through the local kepr gate.
// Conversation text is checked before every model request; signed reasoning is
// never edited, and structured tool arguments keep their JSON shape.

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { registerProviders } from "./providers.ts";

const KEPR = process.env.KEPR_BIN || "kepr";
const GATE = process.env.KEPR_GATE_URL;

// Legacy fallback for sessions started with only the original adapter env.
const ROUTES: Record<string, [string, string]> = {
	anthropic: ["/anthropic", "KEPR_PH_ANTHROPIC"],
	openai: ["/openai/v1", "KEPR_PH_OPENAI"],
	xai: ["/xai/v1", "KEPR_PH_XAI"],
	"cloudflare-ai-gateway": ["/cloudflare/compat", "KEPR_PH_CLOUDFLARE"],
	hcnsec: ["/hcnsec/v1", "KEPR_PH_HCNSEC"],
	kktoken: ["/kktoken/v1", "KEPR_PH_KKTOKEN"],
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string | undefined {
	if (!isRecord(error) || typeof error.code !== "string") return;
	return error.code;
}

interface HookResult {
	code: number;
	message: string;
}

interface CheckedText {
	text: string;
	ok: boolean;
}

const TIMED_OUT: HookResult = { code: 2, message: "kepr: the safety check timed out; blocked" };

/** Run `kepr hook EVENT` with payload on stdin (never in argv). */
function hook(event: string, payload: unknown): Promise<HookResult> {
	return new Promise(resolve => {
		let stdout = "";
		let stderr = "";
		let child: ChildProcess | undefined;
		try {
			child = spawn(KEPR, ["hook", event], { stdio: ["pipe", "pipe", "pipe"] });
		} catch {
			resolve({ code: 0, message: "" });
			return;
		}
		if (!child) return resolve({ code: 0, message: "" });
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child?.kill("SIGKILL");
		}, 5000);
		child.stdout.on("data", (d: Buffer) => (stdout += d));
		child.stderr.on("data", (d: Buffer) => (stderr += d));
		child.on("error", () => resolve({ code: 0, message: "" }));
		child.stdin.on("error", () => {});
		child.on("close", (code: number | null) => {
			clearTimeout(timer);
			if (timedOut || code === null) return resolve(TIMED_OUT);
			resolve({ code, message: (stderr || stdout).trim() });
		});
		child.stdin.end(JSON.stringify(payload));
	});
}

function loadProviderConfig(): unknown {
	const directory = process.env.PI_CODING_AGENT_DIR;
	if (!directory) throw new Error("kepr: missing OMP agent directory");
	try {
		const raw = readFileSync(join(directory, "models.yml"), "utf8");
		const bun = (globalThis as unknown as { Bun?: { YAML?: { parse(source: string): unknown } } }).Bun;
		if (!bun?.YAML?.parse) throw new Error("Bun YAML parser unavailable");
		return bun.YAML.parse(raw);
	} catch (error: unknown) {
		if (errorCode(error) === "ENOENT") return {};
		throw new Error("kepr: could not load OMP models.yml; provider setup stopped");
	}
}

function registerAllProviders(pi: ExtensionAPI): { routed: string[]; unavailable: string[] } {
	if (!GATE) return { routed: [], unavailable: [] };
	if (process.env.KEPR_OMP_ROUTES) {
		let metadata: unknown;
		try {
			metadata = JSON.parse(process.env.KEPR_OMP_ROUTES);
		} catch {
			throw new Error("kepr: invalid OMP route metadata; restart with kepr agent run omp");
		}
		return registerProviders(pi, GATE, metadata, loadProviderConfig(), process.env);
	}
	const routed: string[] = [];
	for (const [provider, [path, variable]] of Object.entries(ROUTES)) {
		if (!process.env[variable]) continue;
		pi.registerProvider(provider, { baseUrl: GATE + path, apiKey: variable });
		routed.push(provider);
	}
	return { routed, unavailable: [] };
}

// A bounded queue prevents a long resumed history from starting one child per
// message. The promise map separately coalesces identical text in flight.
const MAX_REDACTION_CHILDREN = 8;
let activeRedactions = 0;
const redactionQueue: (() => void)[] = [];

async function withRedactionSlot<T>(work: () => Promise<T>): Promise<T> {
	if (activeRedactions >= MAX_REDACTION_CHILDREN) {
		await new Promise<void>(resolve => redactionQueue.push(resolve));
	}
	activeRedactions++;
	try {
		return await work();
	} finally {
		activeRedactions--;
		redactionQueue.shift()?.();
	}
}

export default function kepr(pi: ExtensionAPI) {
	const routed: string[] = [];
	const unavailable: string[] = [];
	process.stdout?.on("error", (err: unknown) => {
		if (err && typeof err === "object" && "code" in err && err.code === "EPIPE") return;
	});
	process.stderr?.on("error", (err: unknown) => {
		if (err && typeof err === "object" && "code" in err && err.code === "EPIPE") return;
	});

	const origEmit = process.emit;
	type EmitFn = (event: string | symbol, ...args: unknown[]) => boolean;
	process.emit = function (event: string | symbol, ...args: unknown[]): boolean {
		if (event === "uncaughtException") {
			const err = args[0];
			if (err && typeof err === "object") {
				if ("code" in err && err.code === "EPIPE") return true;
				if ("message" in err && typeof err.message === "string" && err.message.includes("EPIPE")) return true;
			}
		}
		return (origEmit as unknown as EmitFn).apply(this, [event, ...args]);
	};

	if (GATE) {
		const result = registerAllProviders(pi);
		routed.push(...result.routed);
		unavailable.push(...result.unavailable);
	}

	pi.on("session_start", async (_event, ctx) => {
		if (!ctx.hasUI) return;
		if (GATE) {
			ctx.ui.notify(`kepr: keys stay in the vault (${routed.join(", ") || "no providers"} via the gate)`, "info");
			if (unavailable.length) ctx.ui.notify(`kepr: unavailable providers: ${unavailable.join(", ")}`, "warning");
		} else {
			ctx.ui.notify("kepr: not started with `kepr agent run omp`; real keys may be in the environment", "warning");
		}
	});

	pi.on("before_agent_start", async event => {
		const r = await hook("session-start", {});
		try {
			const text = JSON.parse(r.message).hookSpecificOutput?.additionalContext;
			if (typeof text === "string") return { systemPrompt: [...event.systemPrompt, text] };
		} catch {}
	});

	pi.on("tool_call", async event => {
		const r = await hook("pre-tool", { tool_name: event.toolName, tool_input: event.input });
		if (r.code === 2) return { block: true, reason: r.message };
	});

	pi.on("input", async (event, ctx) => {
		const r = await hook("prompt", { prompt: event.text });
		if (r.code !== 2) return;
		if (ctx.hasUI) ctx.ui.notify(r.message, "error");
		return { handled: true };
	});

	const redacted = new Map<string, string>();
	const pending = new Map<string, Promise<CheckedText>>();
	const checkText = (text: string): Promise<CheckedText> => {
		const hit = redacted.get(text);
		if (hit !== undefined) return Promise.resolve({ text: hit, ok: true });
		const inFlight = pending.get(text);
		if (inFlight) return inFlight;
		const work = withRedactionSlot(async () => {
			const r = await hook("redact", { text });
			if (r.code === 0 && r.message === "") return { text, ok: true };
			try {
				const result: unknown = JSON.parse(r.message);
				if (r.code !== 0 || !isRecord(result) || typeof result.text !== "string") throw new Error("invalid redaction");
				const oldest = redacted.keys().next().value;
				if (redacted.size >= 256 && oldest !== undefined) redacted.delete(oldest);
				redacted.set(text, result.text);
				return { text: result.text, ok: true };
			} catch {
				return { text: "[message withheld by kepr: the secret check did not answer]", ok: false };
			}
		});
		pending.set(text, work);
		void work.finally(() => pending.delete(text));
		return work;
	};

	type StructuredResult = { value: unknown; changed: boolean; ok: boolean };
	const redactStructured = async (value: unknown): Promise<StructuredResult> => {
		if (typeof value === "string") {
			const result = await checkText(value);
			return { value: result.text, changed: result.text !== value, ok: result.ok };
		}
		if (Array.isArray(value)) {
			const out: unknown[] = [];
			let changed = false;
			for (const item of value) {
				const result = await redactStructured(item);
				out.push(result.value);
				changed ||= result.changed;
				if (!result.ok) return { value: out, changed: true, ok: false };
			}
			return { value: out, changed, ok: true };
		}
		if (isRecord(value)) {
			const out: Record<string, unknown> = {};
			let changed = false;
			for (const [key, item] of Object.entries(value)) {
				const result = await redactStructured(item);
				out[key] = result.value;
				changed ||= result.changed;
				if (!result.ok) return { value: out, changed: true, ok: false };
			}
			return { value: out, changed, ok: true };
		}
		return { value, changed: false, ok: true };
	};

	const redactToolArguments = async (value: unknown): Promise<{ value: unknown; changed: boolean }> => {
		let parsed = value;
		if (typeof value === "string") {
			try { parsed = JSON.parse(value); }
			catch { throw new Error("kepr: tool arguments withheld because they are not valid JSON"); }
		}
		const result = await redactStructured(parsed);
		if (!result.ok) throw new Error("kepr: tool arguments withheld because the secret check did not answer");
		if (typeof value === "string" && result.changed) return { value: JSON.stringify(result.value), changed: true };
		return { value: result.value, changed: result.changed };
	};

	pi.on("context", async event => {
		let changed = false;
		const messages = await Promise.all(event.messages.map(async (m: unknown) => {
			if (!isRecord(m)) return m;
			const content = m.content;
			if (typeof content === "string") {
				const result = await checkText(content);
				if (result.text === content) return m;
				changed = true;
				return { ...m, content: result.text };
			}
			if (!Array.isArray(content)) return m;
			let touched = false;
			const parts = await Promise.all(content.map(async (p: unknown) => {
				if (!isRecord(p)) return p;
				const args = p.arguments;
				if (p.type === "toolCall" && args !== undefined && args !== null && (typeof args === "object" || typeof args === "string")) {
					const result = await redactToolArguments(args);
					if (!result.changed) return p;
					touched = changed = true;
					return { ...p, arguments: result.value };
				}
				const field: "text" | "thinking" | undefined = p.type === "text" ? "text" : p.type === "thinking" ? "thinking" : undefined;
				const fieldValue = field ? p[field] : undefined;
				if (!field || typeof fieldValue !== "string") return p;
				const result = await checkText(fieldValue);
				if (result.text === fieldValue) return p;
				if (field === "thinking" && (p.thinkingSignature || p.signature)) {
					throw new Error("kepr: signed reasoning contains key-shaped text and cannot be safely edited");
				}
				touched = changed = true;
				return { ...p, [field]: result.text };
			}));
			return touched ? { ...m, content: parts } : m;
		}));
		if (changed) return { messages };
	});

	pi.registerCommand("kepr", {
		description: "Show kepr protection for this session",
		handler: async (_args, ctx) => {
			const lines = GATE
				? [`gate: ${GATE}`, `providers via the gate: ${routed.join(", ") || "none"}`, ...unavailable.map(p => `unavailable: ${p}`)]
				: ["not started with `kepr agent run omp`"];
			ctx.ui.notify(lines.join("\n"), GATE ? "info" : "warning");
		},
	});
}
