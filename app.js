const form = document.querySelector("#check-form");
const input = document.querySelector("#url-input");
const error = document.querySelector("#input-error");
const results = document.querySelector("#results");
const warningToggle = document.querySelector("#page-warning-toggle");
const settingError = document.querySelector("#setting-error");
const extensionApi = globalThis.browser || globalThis.chrome;
const policyForm = document.querySelector("#policy-form");
const policyHostname = document.querySelector("#policy-hostname");
const policyAction = document.querySelector("#policy-action");
const policyReason = document.querySelector("#policy-reason");
const policyStatus = document.querySelector("#policy-status");
const policyList = document.querySelector("#policy-list");
const policyResult = document.querySelector("#policy-result");
const policySaveButton = policyForm.querySelector(".policy-save");
const policyCancelButton = document.querySelector("#policy-cancel");
let accessRules = [];
let editingHostname = null;

function setPolicyStatus(message, isError = false) {
	policyStatus.textContent = message;
	policyStatus.dataset.error = String(isError);
}

async function loadAccessRules() {
	if (extensionApi?.storage?.local) {
		const stored = await extensionApi.storage.local.get("accessRules");
		return Array.isArray(stored.accessRules) ? stored.accessRules : [];
	}
	const stored = localStorage.getItem("accessRules");
	const parsed = stored ? JSON.parse(stored) : [];
	if (!Array.isArray(parsed)) {
		throw new Error("Saved rules are not in a valid format.");
	}
	return parsed;
}

async function saveAccessRules() {
	if (extensionApi?.storage?.local) {
		await extensionApi.storage.local.set({ accessRules });
		return;
	}
	localStorage.setItem("accessRules", JSON.stringify(accessRules));
}

function renderAccessRules() {
	if (!accessRules.length) {
		const empty = document.createElement("li");
		empty.className = "policy-item";
		empty.textContent = "No local rules yet. Add a test hostname above.";
		policyList.replaceChildren(empty);
		return;
	}

	policyList.replaceChildren(...accessRules.map((rule) => {
		const item = document.createElement("li");
		item.className = "policy-item";
		const copy = document.createElement("div");
		copy.className = "policy-item-copy";
		const heading = document.createElement("strong");
		heading.textContent = rule.hostname;
		const badge = document.createElement("span");
		badge.className = "policy-badge";
		badge.dataset.action = rule.action;
		badge.textContent = rule.action;
		heading.append(badge);
		const reason = document.createElement("p");
		reason.textContent = rule.reason;
		copy.append(heading, reason);
		const actions = document.createElement("div");
		actions.className = "policy-item-actions";
		const edit = document.createElement("button");
		edit.className = "policy-edit";
		edit.type = "button";
		edit.textContent = "Edit";
		edit.setAttribute("aria-label", `Edit rule for ${rule.hostname}`);
		edit.addEventListener("click", () => {
			editingHostname = rule.hostname;
			policyHostname.value = rule.hostname;
			policyAction.value = rule.action;
			policyReason.value = rule.reason;
			policySaveButton.textContent = "Save changes";
			policyCancelButton.hidden = false;
			setPolicyStatus(`Editing rule for ${rule.hostname}.`);
			policyHostname.focus();
		});
		const remove = document.createElement("button");
		remove.className = "policy-remove";
		remove.type = "button";
		remove.textContent = "Remove";
		remove.setAttribute("aria-label", `Remove rule for ${rule.hostname}`);
		remove.addEventListener("click", async () => {
			remove.disabled = true;
			setPolicyStatus("");
			const wasEditing = editingHostname === rule.hostname;
			const previousRules = accessRules;
			accessRules = accessRules.filter((entry) => entry.hostname !== rule.hostname);
			try {
				await saveAccessRules();
				if (wasEditing) {
					resetPolicyForm();
				}
				renderAccessRules();
				setPolicyStatus(`Removed rule for ${rule.hostname}.`);
			} catch (storageError) {
				accessRules = previousRules;
				renderAccessRules();
				setPolicyStatus("Couldn't remove the rule. Please try again.", true);
				console.error("Unable to remove a Link Interceptor access rule.", storageError);
			}
		});
		actions.append(edit, remove);
		item.append(copy, actions);
		return item;
	}));
}

function resetPolicyForm() {
	editingHostname = null;
	policyForm.reset();
	policySaveButton.textContent = "Add rule";
	policyCancelButton.hidden = true;
}

const accessRulesReady = loadAccessRules().then((rules) => {
	accessRules = LinkInterceptorPolicy.sanitizeRules(rules);
	renderAccessRules();
	return true;
}).catch((storageError) => {
	setPolicyStatus("Couldn't load local rules. Check browser storage and reload this page.", true);
	console.error("Unable to load Link Interceptor access rules.", storageError);
	return false;
});

policyForm.addEventListener("submit", async (event) => {
	event.preventDefault();
	if (!await accessRulesReady) {
		return;
	}
	setPolicyStatus("");
	const validation = LinkInterceptorPolicy.validateRule({
		hostname: policyHostname.value,
		action: policyAction.value,
		reason: policyReason.value
	});
	if (validation.error) {
		setPolicyStatus(validation.error, true);
		return;
	}

	const rule = validation.rule;
	const conflictingRule = accessRules.find((entry) => (
		entry.hostname === rule.hostname && entry.hostname !== editingHostname
	));
	if (conflictingRule) {
		setPolicyStatus(`A rule already exists for ${rule.hostname}. Edit that rule instead.`, true);
		return;
	}
	const previousRules = accessRules;
	const wasEditing = editingHostname !== null;
	const previousHostname = editingHostname;
	accessRules = accessRules.filter((entry) => (
		entry.hostname !== rule.hostname && entry.hostname !== previousHostname
	));
	accessRules.push(rule);
	policySaveButton.disabled = true;
	try {
		await saveAccessRules();
		resetPolicyForm();
		renderAccessRules();
		setPolicyStatus(`${wasEditing ? "Updated" : "Saved"} ${rule.action} rule for ${rule.hostname}.`);
	} catch (storageError) {
		accessRules = previousRules;
		renderAccessRules();
		setPolicyStatus("Couldn't save the rule. Please try again.", true);
		console.error("Unable to save a Link Interceptor access rule.", storageError);
	} finally {
		policySaveButton.disabled = false;
	}
});

policyCancelButton.addEventListener("click", () => {
	resetPolicyForm();
	setPolicyStatus("Edit cancelled.");
});

async function loadWarningSetting() {
	try {
		if (extensionApi?.storage?.local) {
			const settings = await extensionApi.storage.local.get("warnOnPage");
			warningToggle.checked = settings.warnOnPage !== false;
		} else {
			warningToggle.checked = localStorage.getItem("warnOnPage") !== "false";
		}
	} catch (storageError) {
		settingError.textContent = "Couldn't load this setting. In-page warnings remain enabled.";
		console.error("Unable to load the Link Interceptor warning setting.", storageError);
	}
}

warningToggle.addEventListener("change", async () => {
	settingError.textContent = "";
	warningToggle.disabled = true;
	try {
		if (extensionApi?.storage?.local) {
			await extensionApi.storage.local.set({ warnOnPage: warningToggle.checked });
		} else {
			localStorage.setItem("warnOnPage", String(warningToggle.checked));
		}
	} catch (storageError) {
		warningToggle.checked = !warningToggle.checked;
		settingError.textContent = "Couldn't save this setting. Please try again.";
		console.error("Unable to save the Link Interceptor warning setting.", storageError);
	} finally {
		warningToggle.disabled = false;
	}
});

loadWarningSetting();

function showResults(analysis, rule) {
	const score = analysis.score;
	const flagged = analysis.checks.filter((check) => check.state === "bad" || check.state === "warn").length;
	const isHigh = score >= 45;
	const isCaution = score >= 15;
	document.querySelector("#verdict-label").textContent = isHigh ? "Strong warning" : isCaution ? "Use caution" : "No obvious red flags";
	document.querySelector("#verdict-title").textContent = isHigh ? "Don't open this link." : isCaution ? "Take a closer look." : "Stay alert anyway.";
	document.querySelector("#verdict-description").textContent = isHigh
		? `We found ${flagged} concerning signal${flagged === 1 ? "" : "s"} for ${analysis.hostname}. Do not enter personal information.`
		: isCaution
			? `We found ${flagged} signal${flagged === 1 ? "" : "s"} worth checking for ${analysis.hostname}. Verify the address independently.`
			: `No common warning signs were detected for ${analysis.hostname}. That is not a guarantee that it is legitimate.`;
	document.querySelector("#score-value").textContent = String(score);
	document.querySelector("#score-fill").style.width = `${score}%`;
	document.querySelector("#score-fill").style.background = isHigh ? "var(--red)" : isCaution ? "var(--amber)" : "var(--green)";
	document.querySelector("#check-summary").textContent = `${flagged} signal${flagged === 1 ? "" : "s"} to review`;
	if (rule) {
		policyResult.hidden = false;
		policyResult.dataset.action = rule.action;
		policyResult.textContent = `Local policy for browser link clicks: ${rule.action.toUpperCase()} ${rule.hostname}. ${rule.reason} This is the configured browser action, not a threat-intelligence verdict.`;
	} else {
		policyResult.hidden = true;
		policyResult.textContent = "";
		policyResult.removeAttribute("data-action");
	}

	const list = document.querySelector("#check-list");
	list.replaceChildren(...analysis.checks.map((check) => {
		const row = document.createElement("div");
		row.className = "check-row";
		const name = document.createElement("div");
		name.className = "check-name";
		name.textContent = check.name;
		const detail = document.createElement("div");
		detail.className = "check-detail";
		detail.textContent = check.detail;
		const state = document.createElement("span");
		state.className = `check-state state-${check.state}`;
		state.textContent = check.state === "bad" ? "Flagged" : check.state === "warn" ? "Caution" : check.state === "good" ? "No issue" : "Sample only";
		row.append(name, detail, state);
		return row;
	}));
	results.hidden = false;
	results.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

form.addEventListener("submit", async (event) => {
	event.preventDefault();
	error.textContent = "";
	await accessRulesReady;
	const analysis = LinkInterceptor.inspectUrl(input.value);
	if (analysis.error) {
		error.textContent = analysis.error;
		results.hidden = true;
		input.focus();
		return;
	}
	showResults(analysis, LinkInterceptorPolicy.findRule(analysis.hostname, accessRules));
});

document.querySelector("#paste-button").addEventListener("click", async () => {
	error.textContent = "";
	try {
		input.value = await navigator.clipboard.readText();
		input.focus();
	} catch {
		error.textContent = "Clipboard access isn't available here. Paste into the box directly instead.";
	}
});

document.querySelector("#clear-button").addEventListener("click", () => {
	input.value = "";
	error.textContent = "";
	results.hidden = true;
	input.focus();
});

document.querySelectorAll("[data-example]").forEach((button) => {
	button.addEventListener("click", () => {
		input.value = button.dataset.example;
		error.textContent = "";
		form.requestSubmit();
	});
});
