(function () {
	"use strict";

	const extensionApi = globalThis.browser || globalThis.chrome;
	if (!extensionApi) {
		return;
	}

	/* ============================================================
	 * Settings
	 * ============================================================ */
	const POPUP_ID = "link-interceptor-warning";
	const WHATSAPP_WEB_HOST = "web.whatsapp.com";
	const LOG_WHATSAPP_ONLY = false; // true = Watcher only records links clicked in WhatsApp Web

	// Every text the Watcher can store in the "action" field.
	const ACTION = Object.freeze({
		ALLOWED_RULE: "allowed (allow rule)",
		ALLOWED_OFF: "allowed (warnings off)",
		OPENED: "opened (no warning signs)",
		BLOCKED: "blocked (block rule)",
		WARNED: "warning shown",
		PROCEEDED: "user proceeded",
		CANCELLED: "user cancelled",
		DISMISSED: "warning dismissed"
	});

	/* ============================================================
	 * State
	 * ============================================================ */
	let warningsEnabled = true;
	let accessRules = [];
	let stateReady = false;
	let pendingLink; // { url, target, openSeparately, analysis, rule, logPromise }
	let popupHost;
	let popup;

	/* ============================================================
	 * URL helpers
	 * ============================================================ */
	function isWhatsAppHost(hostname) {
		return hostname === "whatsapp.com"
			|| hostname.endsWith(".whatsapp.com")
			|| hostname === "wa.me";
	}

	// WhatsApp wraps outgoing links in l.whatsapp.com/?u=<real link>. Return the real link.
	function getDestinationUrl(href) {
		let url;
		try {
			url = new URL(href);
		} catch {
			return href;
		}
		if (url.hostname !== "l.whatsapp.com") {
			return url.href;
		}
		const redirectedUrl = url.searchParams.get("u") || url.searchParams.get("url");
		if (!redirectedUrl) {
			return url.href;
		}
		try {
			const destination = new URL(redirectedUrl);
			return ["http:", "https:"].includes(destination.protocol) ? destination.href : url.href;
		} catch {
			return url.href;
		}
	}

	function navigate({ url, target, openSeparately }) {
		if (openSeparately) {
			window.open(url, target || "_blank", "noopener,noreferrer");
		} else {
			window.location.assign(url);
		}
	}

	/* ============================================================
	 * Watcher: send records to background.js
	 * ============================================================ */
	function sendMessageSafely(message) {
		try {
			return Promise.resolve(extensionApi.runtime.sendMessage(message)).catch(() => undefined);
		} catch {
			// The extension was reloaded while this page was open. Refresh the page.
			return Promise.resolve(undefined);
		}
	}

	// Returns a promise that resolves to the record id (or undefined if logging failed).
	function sendLog(entry) {
		if (LOG_WHATSAPP_ONLY && location.hostname !== WHATSAPP_WEB_HOST) {
			return Promise.resolve(undefined);
		}
		return sendMessageSafely({ type: "log", entry: { ...entry, source: location.hostname } })
			.then((response) => response?.id);
	}

	function updateLog(logPromise, action) {
		if (!logPromise) {
			return;
		}
		logPromise.then((id) => {
			if (id) {
				sendMessageSafely({ type: "update", id, action });
			}
		});
	}

	// A "blocked" record must stay "blocked", so only non-block links get a decision update.
	function logDecision(link, action) {
		if (link.rule?.action !== "block") {
			updateLog(link.logPromise, action);
		}
	}

	/* ============================================================
	 * Warning popup (UI)
	 * ============================================================ */
	const POPUP_TEMPLATE = `
		<style>
			:host { all: initial; }
			* { box-sizing: border-box; }
			.card {
				width: min(410px, calc(100vw - 32px));
				max-height: min(78vh, 680px);
				overflow-y: auto;
				padding: 20px;
				border: 1px solid #d8ded7;
				border-top: 4px solid #b93d2c;
				background: #fff;
				box-shadow: 0 12px 38px rgba(15, 30, 22, .24);
				color: #17251f;
				font: 14px/1.5 "Segoe UI", Arial, sans-serif;
			}
			.card[data-action="block"] { border-top-color: #b93d2c; }
			.card[data-action="warn"] { border-top-color: #a3650b; }
			h2 { margin: 0 0 5px; font: 700 18px/1.25 "Segoe UI", Arial, sans-serif; }
			p { margin: 8px 0; }
			.muted { color: #58675e; font-size: 12px; }
			.destination {
				margin: 12px 0;
				padding: 9px 10px;
				overflow-wrap: anywhere;
				background: #f2f5ef;
				color: #33433a;
				font: 12px/1.45 Consolas, monospace;
			}
			.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 15px; }
			button {
				min-height: 38px;
				padding: 8px 12px;
				border: 1px solid #cbd5cc;
				border-radius: 3px;
				background: #fff;
				color: #17251f;
				font: 650 13px/1.2 "Segoe UI", Arial, sans-serif;
				cursor: pointer;
			}
			button:focus-visible { outline: 3px solid #9cbd47; outline-offset: 2px; }
			.primary { border-color: #17684e; background: #17684e; color: #fff; }
			.proceed { border-color: #b93d2c; color: #9c3325; }
			.lesson { margin-top: 14px; padding-top: 12px; border-top: 1px solid #d8ded7; }
			.lesson h3 { margin: 0 0 4px; font-size: 13px; }
			.scan-summary { margin: 0 0 8px; color: #33483a; font-size: 12px; font-weight: 650; }
			.point { padding: 10px 0; border-top: 1px solid #e6eae6; }
			.point:first-child { border-top: 0; }
			.point p { margin: 4px 0; font-size: 12px; }
			@media (max-width: 480px) {
				:host { right: 8px !important; bottom: 8px !important; }
				.card { width: calc(100vw - 16px); }
			}
		</style>
		<section class="card" role="dialog" aria-labelledby="warning-title" aria-describedby="warning-description">
			<h2 id="warning-title"></h2>
			<p id="warning-description"></p>
			<div class="destination"></div>
			<p class="policy-reason muted" hidden></p>
			<div class="lesson" hidden>
				<h3>What the scan found</h3>
				<p class="scan-summary"></p>
				<div class="points"></div>
				<p class="muted">This scan uses a bundled URLhaus snapshot and local heuristics; it does not contact URLhaus or follow redirects. The snapshot may be outdated, and no link is guaranteed safe.</p>
			</div>
			<div class="actions">
				<button class="primary scan" type="button">Scan link</button>
				<button class="proceed" type="button">Proceed anyway</button>
				<button class="stay" type="button">Don't proceed</button>
			</div>
		</section>
	`;

	function createPopup() {
		if (popupHost) {
			return;
		}
		popupHost = document.createElement("div");
		popupHost.id = POPUP_ID;
		popupHost.style.cssText = "all:initial!important;position:fixed!important;z-index:2147483647!important;right:16px!important;bottom:16px!important;pointer-events:auto!important;";
		popup = popupHost.attachShadow({ mode: "closed" });
		popup.innerHTML = POPUP_TEMPLATE;

		popup.querySelector(".scan").addEventListener("click", showScan);
		popup.querySelector(".proceed").addEventListener("click", proceed);
		popup.querySelector(".stay").addEventListener("click", cancel);
		popup.addEventListener("keydown", (event) => {
			if (event.key === "Escape") {
				event.preventDefault();
				cancel();
			}
		});
	}

	function showWarning(link) {
		// A newer link replaces an older warning that is still open.
		if (pendingLink) {
			logDecision(pendingLink, ACTION.DISMISSED);
		}
		pendingLink = link;
		createPopup();

		const { url, analysis, rule } = link;
		const isBlocked = rule?.action === "block";
		const card = popup.querySelector(".card");
		const title = popup.querySelector("#warning-title");
		const description = popup.querySelector("#warning-description");
		const scanButton = popup.querySelector(".scan");
		const proceedButton = popup.querySelector(".proceed");
		const stayButton = popup.querySelector(".stay");
		const policyReason = popup.querySelector(".policy-reason");

		card.removeAttribute("data-action");
		policyReason.hidden = !rule;
		policyReason.textContent = rule ? `Local policy: ${rule.action.toUpperCase()} — ${rule.reason}` : "";

		if (isBlocked) {
			card.dataset.action = "block";
			title.textContent = "This link is blocked by policy";
			description.textContent = `The local access rule for ${rule.hostname} stops this link from opening.`;
			scanButton.hidden = true;
			proceedButton.hidden = true;
			stayButton.textContent = "Close";
		} else {
			if (rule) {
				card.dataset.action = "warn";
				title.textContent = "Review this link before opening";
				description.textContent = `A local policy requires review before opening ${analysis.hostname}. Scan the link or choose whether to continue.`;
			} else if (LinkInterceptor.shouldWarn(analysis)) {
				title.textContent = "This link may be suspicious";
				description.textContent = `A quick local check found signs worth reviewing on ${analysis.hostname}. Scan to see what they mean, or choose whether to continue.`;
			} else {
				title.textContent = "Review this link before opening";
				description.textContent = `No common warning signs were detected for ${analysis.hostname}. Scan for details or choose whether to continue.`;
			}
			scanButton.hidden = false;
			proceedButton.hidden = false;
			stayButton.textContent = "Don't proceed";
		}

		popup.querySelector(".destination").textContent = url;
		popup.querySelector(".lesson").hidden = true;
		popup.querySelector(".scan-summary").textContent = "";
		popup.querySelector(".points").replaceChildren();
		document.documentElement.append(popupHost);
		(isBlocked ? stayButton : scanButton).focus();
	}

	function showScan() {
		if (!pendingLink) {
			return;
		}
		const education = LinkInterceptor.getEducation(pendingLink.analysis);
		const score = pendingLink.analysis.score;
		popup.querySelector(".scan-summary").textContent = education.length
			? `Risk indicators: ${score}/100. This is a heuristic score, not proof of harm.`
			: `No common warning signs found (${score}/100). This does not prove the site is safe.`;
		popup.querySelector(".points").replaceChildren(...education.map((item) => {
			const point = document.createElement("div");
			point.className = "point";
			const title = document.createElement("h3");
			title.textContent = item.name;
			const detail = document.createElement("p");
			detail.textContent = item.detail;
			const explanation = document.createElement("p");
			explanation.textContent = item.lesson;
			point.append(title, detail, explanation);
			return point;
		}));
		popup.querySelector(".lesson").hidden = false;
		popup.querySelector(".scan").hidden = true;
		popup.querySelector(".stay").focus();
	}

	// Close the popup. If an action is given, it is saved in the Watcher record.
	function closeWarning(action) {
		if (pendingLink && action) {
			logDecision(pendingLink, action);
		}
		pendingLink = undefined;
		popupHost?.remove();
	}

	function proceed() {
		if (!pendingLink) {
			return;
		}
		const link = pendingLink;
		closeWarning(ACTION.PROCEEDED);
		navigate(link);
	}

	function cancel() {
		closeWarning(ACTION.CANCELLED);
	}

	/* ============================================================
	 * Guard: decide what to do with a clicked link
	 * ============================================================ */
	// Returns { warn: false } or { warn: true, analysis, rule }. Also writes the Watcher record
	// for links that are opened without a warning.
	function reviewLink(url) {
		let destination;
		try {
			destination = new URL(url);
		} catch {
			return { warn: false };
		}

		const rule = LinkInterceptorPolicy.findRule(destination.hostname, accessRules);
		if (rule?.action === "allow" || (!rule && !warningsEnabled)) {
			sendLog({
				url,
				hostname: destination.hostname,
				score: null,
				action: rule ? ACTION.ALLOWED_RULE : ACTION.ALLOWED_OFF
			});
			return { warn: false };
		}

		const analysis = LinkInterceptor.inspectUrl(url);
		if (analysis.error) {
			return { warn: false };
		}

		const isExternalWhatsAppLink = location.hostname === WHATSAPP_WEB_HOST && !isWhatsAppHost(destination.hostname);
		if (!rule && !LinkInterceptor.shouldWarn(analysis) && !isExternalWhatsAppLink) {
			sendLog({ url, hostname: analysis.hostname, score: analysis.score, action: ACTION.OPENED });
			return { warn: false };
		}
		return { warn: true, analysis, rule };
	}

	// event = the click event, or undefined when the click was held back while settings loaded.
	function processLink(link, event) {
		const review = reviewLink(link.url);
		if (!review.warn) {
			if (!event) {
				navigate(link); // the click was stopped earlier, so open the link now
			}
			return;
		}
		if (event) {
			event.preventDefault();
			event.stopImmediatePropagation();
		}
		const logPromise = sendLog({
			url: link.url,
			hostname: review.analysis.hostname,
			score: review.analysis.score,
			action: review.rule?.action === "block" ? ACTION.BLOCKED : ACTION.WARNED
		});
		showWarning({ ...link, ...review, logPromise });
	}

	function findAnchor(event) {
		const path = typeof event.composedPath === "function" ? event.composedPath() : [];
		const anchor = path.find((node) => node && node.nodeType === 1 && node.localName?.toLowerCase() === "a");
		if (anchor) {
			return anchor;
		}

		const target = event.target;
		const element = target?.nodeType === 1 ? target : target?.parentElement;
		return element?.closest?.("a") || null;
	}

	function handleActivation(event) {
		const expectedButton = event.type === "auxclick" ? 1 : 0;
		if (event.defaultPrevented || event.button !== expectedButton) {
			return;
		}

		const anchor = findAnchor(event);
		if (!anchor || anchor.hasAttribute("download")) {
			return;
		}

		const url = getDestinationUrl(anchor.href);
		let destination;
		try {
			destination = new URL(url);
		} catch {
			return;
		}
		if (!["http:", "https:"].includes(destination.protocol)) {
			return;
		}
		// Links inside the same site are not "outside" links, so the Guard ignores them.
		if (destination.origin === location.origin) {
			return;
		}

		const target = anchor.target || document.querySelector("base[target]")?.target || "_self";
		const normalizedTarget = target.toLowerCase();
		const openSeparately = event.type === "auxclick"
			|| event.ctrlKey
			|| event.metaKey
			|| event.shiftKey
			|| !["_self", "_top", "_parent"].includes(normalizedTarget);
		const link = {
			url,
			target: openSeparately && normalizedTarget === "_self" ? "_blank" : target,
			openSeparately
		};

		if (!stateReady) {
			// Settings are still loading: hold the click, then decide.
			event.preventDefault();
			event.stopImmediatePropagation();
			stateReadyPromise.then(() => processLink(link, undefined));
			return;
		}
		processLink(link, event);
	}

	/* ============================================================
	 * Start
	 * ============================================================ */
	async function loadSettings() {
		try {
			const settings = await extensionApi.storage.local.get(["warnOnPage", "accessRules"]);
			warningsEnabled = settings.warnOnPage !== false;
			accessRules = LinkInterceptorPolicy.sanitizeRules(settings.accessRules);
		} catch (error) {
			console.error("Link Interceptor could not load its settings; warnings stay on.", error);
		} finally {
			stateReady = true;
		}
	}

	const stateReadyPromise = loadSettings();

	document.addEventListener("click", handleActivation, true);
	document.addEventListener("auxclick", handleActivation, true);

	extensionApi.storage.onChanged.addListener((changes, areaName) => {
		if (areaName !== "local") {
			return;
		}
		if (changes.warnOnPage) {
			warningsEnabled = changes.warnOnPage.newValue !== false;
			if (!warningsEnabled && pendingLink && !pendingLink.rule) {
				closeWarning(ACTION.DISMISSED);
			}
		}
		if (changes.accessRules) {
			accessRules = LinkInterceptorPolicy.sanitizeRules(changes.accessRules.newValue);
		}
	});
})();