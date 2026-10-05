// kepr extension for oh-my-pi (omp).
//
// - Inside `kepr agent run omp`: points omp's built-in providers at the
//   local kepr gate, with the session placeholder as the API key. No
//   models.yml edit is needed; the real key never enters omp.
// - Blocks tool calls that would reveal a stored secret (`kepr get`,
//   `kepr env`, `kepr exec`, ...) or that carry a real key, and prompts
//   that contain a key, using `kepr hook` (the same policy as the Grok
//   Build plugin).
// - `/kepr` shows whether this session is protected.
//
// Requires the `kepr` binary on PATH (or KEPR_BIN). No network access, no
// dependencies; types only.

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { spawn } from "node:child_process";

const KEPR = process.env.KEPR_BIN || "kepr";
const GATE = process.env.KEPR_GATE_URL;

// omp provider id -> [gate path, placeholder variable set by kepr agent run]
const ROUTES: Record<string, [string, string]> = {
	anthropic: ["/anthropic", "KEPR_PH_ANTHROPIC"],
	openai: ["/openai/v1", "KEPR_PH_OPENAI"],
	xai: ["/xai/v1", "KEPR_PH_XAI"],
};

interface HookResult {
	code: number;
	message: string;
}

// kepr was found but didn't answer in time: treated as a block, never as
// an allow (a slow machine must not let `kepr get` through). A missing
// kepr binary still allows: the gate and sandbox are the boundary.
const TIMED_OUT: HookResult = { code: 2, message: "kepr: the safety check timed out; blocked" };

/** Run `kepr hook EVENT` with `payload` on stdin (never in argv). */
function hook(event: string, payload: unknown): Promise<HookResult> {
	return new Promise(resolve => {
		let stdout = "";
		let stderr = "";
		let child;
		try {
			child = spawn(KEPR, ["hook", event], { stdio: ["pipe", "pipe", "pipe"] });
		} catch {
			resolve({ code: 0, message: "" });
			return;
		}
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
		}, 5000);
		child.stdout.on("data", (d: Buffer) => (stdout += d));
		child.stderr.on("data", (d: Buffer) => (stderr += d));
		// kepr missing: allow. The gate and sandbox are the boundary.
		child.on("error", () => resolve({ code: 0, message: "" }));
		child.on("close", (code: number | null) => {
			clearTimeout(timer);
			if (timedOut || code === null) return resolve(TIMED_OUT);
			resolve({ code, message: (stderr || stdout).trim() });
		});
		child.stdin.end(JSON.stringify(payload));
	});
}

export default function kepr(pi: ExtensionAPI) {
	const routed: string[] = [];
	if (GATE) {
		for (const [provider, [path, variable]] of Object.entries(ROUTES)) {
			if (!process.env[variable]) continue;
			// Override-only registration: same models, gate URL, and the
			// placeholder (an env var name) as the key.
			pi.registerProvider(provider, { baseUrl: GATE + path, apiKey: variable });
			routed.push(provider);
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		if (!ctx.hasUI) return;
		if (GATE) {
			ctx.ui.notify(`kepr: keys stay in the vault (${routed.join(", ") || "no providers"} via the gate)`, "info");
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

	// Backstop for non-interactive runs (`omp -p`, RPC), where `input`
	// does not fire: remove key-shaped text from user messages before
	// every model request.
	// Bounded memo of texts already checked; failures are not cached, so
	// a timed-out redaction is retried on the next request.
	const redacted = new Map<string, string>();
	const clean = async (text: string): Promise<string> => {
		const hit = redacted.get(text);
		if (hit !== undefined) return hit;
		const r = await hook("redact", { text });
		let out: string;
		try {
			out = String(JSON.parse(r.message).text);
		} catch {
			// No answer: send nothing rather than an unchecked message.
			return "[message withheld by kepr: the secret check did not answer]";
		}
		if (redacted.size >= 256) redacted.delete(redacted.keys().next().value as string);
		redacted.set(text, out);
		return out;
	};
	pi.on("context", async event => {
		let changed = false;
		const messages = await Promise.all(
			event.messages.map(async (m: any) => {
				if (m?.role !== "user") return m;
				if (typeof m.content === "string") {
					const c = await clean(m.content);
					if (c === m.content) return m;
					changed = true;
					return { ...m, content: c };
				}
				if (!Array.isArray(m.content)) return m;
				let touched = false;
				const parts = await Promise.all(
					m.content.map(async (p: any) => {
						if (p?.type !== "text" || typeof p.text !== "string") return p;
						const c = await clean(p.text);
						if (c === p.text) return p;
						touched = changed = true;
						return { ...p, text: c };
					}),
				);
				return touched ? { ...m, content: parts } : m;
			}),
		);
		if (changed) return { messages };
	});

	pi.registerCommand("kepr", {
		description: "Show kepr protection for this session",
		handler: async (_args, ctx) => {
			const lines = GATE
				? [`gate: ${GATE}`, `providers via the gate: ${routed.join(", ") || "none"}`]
				: ["not started with `kepr agent run omp`"];
			ctx.ui.notify(lines.join("\n"), GATE ? "info" : "warning");
		},
	});
}
