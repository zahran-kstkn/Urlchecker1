(function () {
	const extensionApi = globalThis.browser || globalThis.chrome;
	if (!extensionApi) {
		return;
	}

	const popupId = "link-interceptor-warning";
	let popupHost;
	let popup;
	let pendingLink;
	let warningsEnabled = true;

	function createPopup() {
		if (popupHost) {
			return;
		}

		popupHost = document.createElement("div");
		popupHost.id = popupId;
		popupHost.style.cssText = "all:initial!important;position:fixed!important;z-index:2147483647!important;right:16px!important;bottom:16px!important;pointer-events:auto!important;";
		popup = popupHost.attachShadow({ mode: "closed" });
		popup.innerHTML = `
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
				<div class="lesson" hidden>
					<h3>What the scan found</h3>
					<div class="points"></div>
					<p class="muted">This is a local heuristic check, not a live threat lookup. No link is guaranteed safe.</p>
				</div>
				<div class="actions">
					<button class="primary scan" type="button">Scan link</button>
					<button class="proceed" type="button">Proceed anyway</button>
					<button class="stay" type="button">Don't proceed</button>
				</div>
			</section>
		`;

		popup.querySelector(".scan").addEventListener("click", showScan);
		popup.querySelector(".proceed").addEventListener("click", proceed);
		popup.querySelector(".stay").addEventListener("click", dismiss);
		popup.addEventListener("keydown", (event) => {
			if (event.key === "Escape") {
				event.preventDefault();
				dismiss();
			}
		});
	}

	function showWarning(url, analysis, target, openSeparately) {
		pendingLink = { url, analysis, target, openSeparately };
		createPopup();
		popup.querySelector("#warning-title").textContent = "This link may be suspicious";
		popup.querySelector("#warning-description").textContent = `A quick local check found signs worth reviewing on ${analysis.hostname}. Scan to see what they mean, or choose whether to continue.`;
		popup.querySelector(".destination").textContent = url;
		popup.querySelector(".lesson").hidden = true;
		popup.querySelector(".points").replaceChildren();
		popup.querySelector(".scan").hidden = false;
		document.documentElement.append(popupHost);
		popup.querySelector(".scan").focus();
	}

	function showScan() {
		if (!pendingLink) {
			return;
		}
		const lesson = popup.querySelector(".lesson");
		const points = popup.querySelector(".points");
		points.replaceChildren(...LinkInterceptor.getEducation(pendingLink.analysis).map((item) => {
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
		lesson.hidden = false;
		popup.querySelector(".scan").hidden = true;
		popup.querySelector(".stay").focus();
	}

	function proceed() {
		if (!pendingLink) {
			return;
		}
		const { url, target, openSeparately } = pendingLink;
		if (openSeparately) {
			window.open(url, target || "_blank", "noopener,noreferrer");
			dismiss();
			return;
		}
		window.location.assign(url);
	}

	function dismiss() {
		pendingLink = undefined;
		if (popupHost) {
			popupHost.remove();
		}
	}

	function handleActivation(event) {
		if (!warningsEnabled || event.defaultPrevented || event.button !== (event.type === "auxclick" ? 1 : 0)) {
			return;
		}
		const anchor = event.composedPath().find((node) => node instanceof HTMLAnchorElement);
		if (!anchor || anchor.hasAttribute("download")) {
			return;
		}

		const analysis = LinkInterceptor.inspectUrl(anchor.href);
		if (analysis.error || !LinkInterceptor.shouldWarn(analysis)) {
			return;
		}

		event.preventDefault();
		event.stopImmediatePropagation();
		const target = anchor.target || document.querySelector("base[target]")?.target || "_self";
		const normalizedTarget = target.toLowerCase();
		const openSeparately = event.type === "auxclick"
			|| event.ctrlKey
			|| event.metaKey
			|| event.shiftKey
			|| (normalizedTarget !== "_self" && normalizedTarget !== "_top" && normalizedTarget !== "_parent");
		const destinationTarget = openSeparately && normalizedTarget === "_self" ? "_blank" : target;
		showWarning(anchor.href, analysis, destinationTarget, openSeparately);
	}

	document.addEventListener("click", handleActivation, true);
	document.addEventListener("auxclick", handleActivation, true);

	extensionApi.storage.local.get("warnOnPage").then((settings) => {
		warningsEnabled = settings.warnOnPage !== false;
	}).catch((error) => {
		console.error("Unable to load the Link Interceptor warning setting; warnings stay enabled.", error);
	});
	extensionApi.storage.onChanged.addListener((changes, areaName) => {
		if (areaName === "local" && changes.warnOnPage) {
			warningsEnabled = changes.warnOnPage.newValue !== false;
			if (!warningsEnabled) {
				dismiss();
			}
		}
	});
})();
