(function (global) {
	function normalizeDomain(value) {
		if (typeof value !== "string") {
			return null;
		}
		const input = value.trim().toLowerCase().replace(/\.$/, "");
		if (!input || input.length > 253 || /[\/\\?#@%\s]/.test(input) || (input.includes(":") && !/^\[[\da-f:]+\]$/i.test(input))) {
			return null;
		}
		try {
			const url = new URL(`https://${input}`);
			if (!url.hostname || url.username || url.password || url.port || url.pathname !== "/" || url.search || url.hash) {
				return null;
			}
			const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
			if (!hostname.startsWith("[") && hostname.split(".").some((label) => (
				!label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
			))) {
				return null;
			}
			return hostname;
		} catch {
			return null;
		}
	}

	function validateRule(rule) {
		if (!rule || typeof rule !== "object") {
			return { error: "Enter a domain and choose an action." };
		}
		const hostname = normalizeDomain(rule.hostname);
		if (!hostname) {
			return { error: "Enter a valid hostname only, without a scheme, port, path, or wildcard." };
		}
		if (!["allow", "warn", "block"].includes(rule.action)) {
			return { error: "Choose allow, warn, or block." };
		}
		const reason = typeof rule.reason === "string" ? rule.reason.trim() : "";
		if (!reason || reason.length > 200) {
			return { error: "Add a reason up to 200 characters." };
		}
		return { rule: { hostname, action: rule.action, reason } };
	}

	function findRule(hostname, rules) {
		const normalizedHostname = normalizeDomain(hostname);
		if (!normalizedHostname || !Array.isArray(rules)) {
			return undefined;
		}
		return rules.find((rule) => rule && rule.hostname === normalizedHostname);
	}

	function sanitizeRules(rules) {
		const normalizedRules = new Map();
		if (!Array.isArray(rules)) {
			return [];
		}
		rules.forEach((rule) => {
			const validation = validateRule(rule);
			if (validation.rule) {
				normalizedRules.set(validation.rule.hostname, validation.rule);
			}
		});
		return Array.from(normalizedRules.values());
	}

	global.LinkInterceptorPolicy = { findRule, normalizeDomain, sanitizeRules, validateRule };
})(globalThis);
