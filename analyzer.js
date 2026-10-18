(function (global) {
	const demoDomains = new Set(["paypa1-secure.test", "account-verify.test", "parcel-track.test"]);
	const officialDomains = {
		paypal: ["paypal.com"],
		google: ["google.com", "google.co.uk"],
		amazon: ["amazon.com", "amazon.co.uk"],
		microsoft: ["microsoft.com"],
		apple: ["apple.com"],
		chase: ["chase.com"],
		fedex: ["fedex.com"],
		dhl: ["dhl.com"]
	};

	function normalizedLabel(label) {
		return label.toLowerCase().replace(/[0]/g, "o").replace(/[1|!]/g, "l").replace(/[3]/g, "e").replace(/[5]/g, "s").replace(/[8]/g, "b").replace(/[^a-z]/g, "");
	}

	function editDistance(left, right) {
		const row = Array.from({ length: right.length + 1 }, (_, index) => index);
		for (let i = 1; i <= left.length; i += 1) {
			let diagonal = row[0];
			row[0] = i;
			for (let j = 1; j <= right.length; j += 1) {
				const above = row[j];
				row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diagonal + (left[i - 1] === right[j - 1] ? 0 : 1));
				diagonal = above;
			}
		}
		return row[right.length];
	}

	function inspectUrl(rawValue) {
		const raw = rawValue.trim();
		const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
		let url;
		try {
			url = new URL(candidate);
		} catch {
			return { error: "That doesn't look like a complete URL. Check for missing or extra characters." };
		}
		if (!["http:", "https:"].includes(url.protocol) || !url.hostname) {
			return { error: "Enter a web address that starts with http:// or https://." };
		}

		const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
		const labels = hostname.split(".");
		const hostLabels = labels.slice(0, -1);
		const normalizedHost = normalizedLabel(hostname);
		const brands = Object.keys(officialDomains);
		const isOfficialDomain = (brand) => officialDomains[brand].some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
		const matchingBrand = brands.find((brand) => normalizedHost.includes(brand) && !isOfficialDomain(brand));
		const nearBrand = brands.find((brand) => hostLabels.some((label) => {
			const normalized = normalizedLabel(label);
			return normalized.length >= 4 && editDistance(normalized, brand) === 1;
		}) && !isOfficialDomain(brand));
		const suspectedBrand = matchingBrand || nearBrand;
		const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith("[");
		const subdomainCount = Math.max(0, labels.length - 2);
		const encodedHost = labels.some((label) => label.startsWith("xn--"));
		const suspiciousPunctuation = /-{2,}|[_]/.test(hostname);
		const knownDemoDomain = demoDomains.has(hostname);
		const longUrl = raw.length > 120;
		const credentials = Boolean(url.username || url.password);
		const checks = [
			{ name: "Demo reputation", detail: knownDemoDomain ? "This exact domain is a built-in demonstration entry, not a verified threat report." : "No match in the small built-in demonstration list; this is not a live reputation lookup.", state: knownDemoDomain ? "bad" : "neutral", weight: knownDemoDomain ? 100 : 0 },
			{ name: "Brand lookalike", detail: suspectedBrand ? `The hostname may be imitating ${suspectedBrand}. Verify its registered domain independently.` : "No common brand imitation was detected by these simple checks.", state: suspectedBrand ? "bad" : "good", weight: suspectedBrand ? 45 : 0 },
			{ name: "Connection", detail: url.protocol === "https:" ? "HTTPS is present, but encryption alone does not establish trust." : "This address uses HTTP, so the connection is not encrypted.", state: url.protocol === "https:" ? "good" : "warn", weight: url.protocol === "https:" ? 0 : 20 },
			{ name: "Host structure", detail: isIp ? "The hostname is an IP address rather than a familiar domain." : `${subdomainCount} subdomain${subdomainCount === 1 ? "" : "s"}${subdomainCount >= 3 ? "; unusually deep nesting can hide the actual domain." : "."}`, state: isIp ? "warn" : subdomainCount >= 3 ? "warn" : "good", weight: isIp ? 20 : subdomainCount >= 3 ? 15 : 0 },
			{ name: "Address format", detail: credentials ? "The URL contains user information before the host, a common deception tactic." : encodedHost ? "The hostname uses punycode encoding; verify each character carefully." : suspiciousPunctuation ? "The hostname contains unusual repeated punctuation or underscores." : "No user information or obvious hostname encoding was found.", state: credentials || encodedHost || suspiciousPunctuation ? "warn" : "good", weight: credentials ? 30 : encodedHost || suspiciousPunctuation ? 15 : 0 },
			{ name: "URL length", detail: longUrl ? `This address is ${raw.length} characters long; long links can obscure their destination.` : `This address is ${raw.length} characters long.`, state: longUrl ? "warn" : "good", weight: longUrl ? 10 : 0 }
		];
		const score = Math.min(100, Math.max(...checks.map((check) => check.weight), checks.reduce((total, check) => total + check.weight, 0)));
		return { hostname, score, checks };
	}

	function getEducation(analysis) {
		return analysis.checks
			.filter((check) => check.state === "bad" || check.state === "warn")
			.map((check) => {
				let lesson;
				if (check.name === "Demo reputation") {
					lesson = "Scammers often impersonate services people already trust. This built-in match is only a demonstration entry, not a real threat report.";
				} else if (check.name === "Brand lookalike") {
					lesson = "Phishing messages often use a slightly altered brand name to make a fake sign-in or payment page look familiar. Check the actual domain, not just the logo or page design.";
				} else if (check.name === "Connection") {
					lesson = "An unencrypted connection can expose or allow changes to data in transit. HTTPS protects the connection, but scammers also use HTTPS, so it does not prove a site is genuine.";
				} else if (check.name === "Host structure" && check.detail.startsWith("The hostname is an IP")) {
					lesson = "A raw IP address hides the recognizable registered domain. Some phishing pages use short-lived servers this way; legitimate sites can use IP addresses too.";
				} else if (check.name === "Host structure") {
					lesson = "Attackers can put a trusted-looking name in a subdomain while the real registered domain belongs to someone else. Read the hostname from right to left to find its actual domain.";
				} else if (check.name === "Address format" && check.detail.includes("user information")) {
					lesson = "Text before an @ sign in a URL can make a fake brand appear prominent, while the browser connects to the hostname after the @ sign.";
				} else if (check.name === "Address format" && check.detail.includes("punycode")) {
					lesson = "Some international characters look almost identical to Latin letters. A lookalike domain can use those characters to imitate a familiar site.";
				} else if (check.name === "Address format") {
					lesson = "Extra punctuation can make a domain resemble a familiar name at a glance. Compare it carefully with the service's official address.";
				} else {
					lesson = "Long links can hide tracking parameters or redirect destinations. If you did not expect the message, visit the service using its official app or a saved address instead.";
				}
				return { name: check.name, detail: check.detail, lesson };
			});
	}

	global.LinkInterceptor = { inspectUrl, getEducation, shouldWarn: (analysis) => analysis.score >= 15 };
})(globalThis);
