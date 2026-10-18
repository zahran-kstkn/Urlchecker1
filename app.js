const form = document.querySelector("#check-form");
const input = document.querySelector("#url-input");
const error = document.querySelector("#input-error");
const results = document.querySelector("#results");
const warningToggle = document.querySelector("#page-warning-toggle");
const settingError = document.querySelector("#setting-error");
const extensionApi = globalThis.browser || globalThis.chrome;

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

function showResults(analysis) {
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

form.addEventListener("submit", (event) => {
	event.preventDefault();
	error.textContent = "";
	const analysis = LinkInterceptor.inspectUrl(input.value);
	if (analysis.error) {
		error.textContent = analysis.error;
		results.hidden = true;
		input.focus();
		return;
	}
	showResults(analysis);
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
