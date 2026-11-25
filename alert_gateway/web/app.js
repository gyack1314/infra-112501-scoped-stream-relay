const $ = (id) => document.getElementById(id);

function config() {
  const principal = $("principal").value.trim();
  const client = $("client").value.trim();
  const baseUrl = $("baseUrl").value.trim().replace(/\/$/, "") || window.location.origin;
  const storageKey = `alert-gateway-cursor:${baseUrl}:${principal}:${client}`;
  return { baseUrl, principal, client, storageKey };
}

function savedCursor() {
  const { storageKey } = config();
  return localStorage.getItem(storageKey) || undefined;
}

function saveCursor(progress) {
  if (!progress) return;
  const { storageKey } = config();
  localStorage.setItem(storageKey, progress);
}

async function api(path, body) {
  const { baseUrl } = config();
  const response = await fetch(baseUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return response.json();
}

function renderStatus(data) {
  saveCursor(data.progress);
  $("raw").textContent = JSON.stringify(data, null, 2);
  $("progress").innerHTML = `
    <div>state: <strong>${data.state || "unknown"}</strong></div>
    <div>resumable: <strong>${data.resumable}</strong></div>
    <div>connected: <strong>${data.connected}</strong></div>
    <div>progress: <span class="ref">${data.progress || ""}</span></div>
    ${data.reset_reason ? `<div>reset reason: ${data.reset_reason}</div>` : ""}
  `;

  const evict = $("evictions");
  evict.innerHTML = "";
  for (const ref of data.evict_refs || []) {
    const li = document.createElement("li");
    li.className = "ref";
    li.textContent = ref;
    evict.appendChild(li);
  }
  if (!evict.children.length) evict.innerHTML = "<li>无</li>";

  const revocations = $("revocations");
  revocations.innerHTML = "";
  const batchRevocations = (data.messages || []).filter((m) => m.kind === "revocation");
  const visibleRevocations = batchRevocations.length
    ? batchRevocations
    : (data.pending_evictions || []);
  for (const message of visibleRevocations) {
    const div = document.createElement("div");
    div.className = "revocation";
    div.innerHTML = `
      <div>撤回通知 <span class="ref">${message.delivery_ref}</span></div>
      <div>清除缓存标识：<span class="ref">${message.clear_ref}</span></div>
      <div>原因：${message.reason}</div>
      <button data-ack="${message.delivery_ref}">确认该撤回</button>
    `;
    div.querySelector("button").onclick = () => ack(message.delivery_ref);
    revocations.appendChild(div);
  }
  if (!visibleRevocations.length) {
    revocations.textContent = "没有未确认的撤回通知。";
  }

  const events = $("events");
  events.innerHTML = "";
  let renderedEventCount = 0;
  for (const message of data.messages || []) {
    if (message.kind !== "event") continue;
    renderedEventCount += 1;
    const e = message.event;
    const div = document.createElement("div");
    div.className = "event";
    div.innerHTML = `
      <div><strong>${e.site}/${e.device} #${e.alarm} rev${e.rev}</strong> ${e.status}</div>
      <div>${e.body || ""}</div>
      <div class="ref">delivery_ref=${message.delivery_ref}
        ${message.replaces_delivery_ref ? ` replaces=${message.replaces_delivery_ref}` : ""}
      </div>
      <button data-ack="${message.delivery_ref}">确认交付</button>
    `;
    div.querySelector("button").onclick = () => ack(message.delivery_ref);
    events.appendChild(div);
  }

  if (data.state === "rebuild_pending" && Array.isArray(data.snapshot)) {
    for (const item of data.snapshot) {
      renderedEventCount += 1;
      const div = document.createElement("div");
      div.className = "event";
      div.innerHTML = `
        <div><strong>[重建快照] ${item.site}/${item.device} #${item.alarm} rev${item.rev}</strong> ${item.status}</div>
        <div>${item.body || ""}</div>
        <div class="ref">latest_seq=${item.latest_seq}</div>
      `;
      events.appendChild(div);
    }
  }

  if (!renderedEventCount) {
    events.textContent = data.state === "reset_required"
      ? "进度已不可安全续读，请按当前授权重建。"
      : data.state === "rebuild_pending"
        ? "当前授权范围为空快照；请确认重建。确认前撤回仍会送达。"
        : "本批没有新的正常告警。";
  }
}

async function open(local_state) {
  const { principal, client } = config();
  const cursor = savedCursor();
  const data = await api("/api/subscriptions/open", {
    principal, client, local_state, ...(cursor ? { cursor } : {}),
  });
  renderStatus(data);
}

async function fetchBatch() {
  const { principal, client } = config();
  const cursor = savedCursor();
  const data = await api("/api/subscriptions/fetch", {
    principal, client, ...(cursor ? { cursor } : {}),
  });
  renderStatus(data);
}

let eventSource = null;

function watch() {
  const { baseUrl, principal, client } = config();
  const params = new URLSearchParams({ principal, client, local_state: "resume" });
  const cursor = savedCursor();
  if (cursor) params.set("cursor", cursor);
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`${baseUrl}/api/stream?${params}`);
  eventSource.addEventListener("status", (event) => {
    renderStatus(JSON.parse(event.data));
  });
  eventSource.addEventListener("batch", (event) => {
    renderStatus(JSON.parse(event.data));
  });
  eventSource.onerror = () => {
    $("raw").textContent += "\n[SSE disconnected; use 握手并续读 to recover]\n";
  };
}

async function ack(ref) {
  const { principal, client } = config();
  const data = await api("/api/subscriptions/ack", { principal, client, ref });
  $("raw").textContent = JSON.stringify(data, null, 2);
  await refresh();
}

async function rebuildAck() {
  const { principal, client } = config();
  const data = await api("/api/subscriptions/rebuild-ack", { principal, client });
  $("raw").textContent = JSON.stringify(data, null, 2);
  await refresh();
}

async function disconnect() {
  const { principal, client } = config();
  const data = await api("/api/subscriptions/disconnect", { principal, client });
  $("raw").textContent = JSON.stringify(data, null, 2);
}

async function refresh() {
  const { baseUrl, principal, client } = config();
  const q = new URLSearchParams({ principal, client });
  const data = await (await fetch(`${baseUrl}/api/status?${q}`)).json();
  renderStatus(data);
}

$("openResume").onclick = () => open("resume");
$("openRebuild").onclick = () => open("rebuild");
$("fetch").onclick = fetchBatch;
$("watch").onclick = watch;
$("disconnect").onclick = disconnect;
$("rebuildAck").onclick = rebuildAck;
$("status").onclick = refresh;
