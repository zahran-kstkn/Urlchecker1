const extensionApi = globalThis.browser || globalThis.chrome;
const MAX_LOG = 500;
let busy = Promise.resolve();
const queue = (job) => (busy = busy.then(job, job));

extensionApi.runtime.onMessage.addListener((msg, sender, sendResponse) => {
	if (msg.type === "log") {
		queue(() => addLog(msg.entry)).then((id) => sendResponse({ id }));
		return true;
	}
	if (msg.type === "update") {
		queue(() => updateLog(msg.id, msg.action)).then(() => sendResponse({ ok: true }));
		return true;
	}
});

async function addLog(entry) {
	const { watcherLog = [] } = await extensionApi.storage.local.get("watcherLog");
	const id = Date.now() + "-" + Math.random().toString(36).slice(2, 6);
	const item = { id, time: new Date().toISOString(), ...entry };
	await extensionApi.storage.local.set({ watcherLog: [item, ...watcherLog].slice(0, MAX_LOG) });
	return id;
}

async function updateLog(id, action) {
	const { watcherLog = [] } = await extensionApi.storage.local.get("watcherLog");
	const updated = watcherLog.map((e) => (e.id === id ? { ...e, action } : e));
	await extensionApi.storage.local.set({ watcherLog: updated });
}

extensionApi.storage.onChanged.addListener((changes, area) => {
	if (area === "local" && changes.watcherLog) {
		const total = (changes.watcherLog.newValue || []).length;
		extensionApi.action.setBadgeText({ text: total ? String(total) : "" });
	}
});