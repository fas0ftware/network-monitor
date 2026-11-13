// Home Network Monitor dashboard. Every value from the API is written with
// textContent (never innerHTML), so device names and vendors cannot inject HTML.
"use strict";

const params = new URLSearchParams(location.search);
const maskBox = document.getElementById("mask");
maskBox.checked = params.has("mask") || params.has("demo");

let devices = [];
let filter = "all";
let editing = false; // pause auto-refresh while a row is being edited
let drawerTarget = null; // {device, port} shown in the advice panel

const $ = (id) => document.getElementById(id);
const fmt = (iso) => iso.replace("T", " ");
const mask = (mac) => (maskBox.checked ? mac.slice(0, 8) + ":xx:xx:xx" : mac);
const RISK_TEXT = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function cell(text) {
  return el("td", "", text);
}

function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 172800) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " days ago";
}

async function api(path, options) {
  const res = await fetch(path, { credentials: "same-origin", ...options });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function postJson(path, body) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

// Small per-browser memory for the checklist and the open tab. Storage can be
// missing or blocked (private windows), so every access is guarded.
const store = {
  get(key, fallback) {
    try {
      const raw = localStorage.getItem("netmon." + key);
      return raw === null ? fallback : JSON.parse(raw);
    } catch (e) {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem("netmon." + key, JSON.stringify(value));
    } catch (e) {
      /* not saved; the page still works */
    }
  },
};

/* ---------- devices ---------- */

async function save(mac, name, trusted, button) {
  try {
    await postJson("/api/devices/" + encodeURIComponent(mac), { name, trusted });
    button.textContent = "Saved";
    editing = false;
    setTimeout(load, 500);
  } catch (e) {
    button.textContent = "Error!";
  }
}

async function forget(device) {
  const label = device.name || device.ip;
  if (!confirm(`Forget ${label}? It will be reported as a new device if it comes back.`)) return;
  try {
    await api("/api/devices/" + encodeURIComponent(device.mac), { method: "DELETE" });
    load();
  } catch (e) {
    alert("Could not remove the device: " + e.message);
  }
}

const openRisky = (d) => d.ports.filter((p) => p.risky && !p.accepted);

function matches(d) {
  if (filter === "online" && !d.online) return false;
  if (filter === "untrusted" && d.trusted) return false;
  if (filter === "risky" && openRisky(d).length === 0) return false;
  const q = $("search").value.trim().toLowerCase();
  if (!q) return true;
  const hay = [d.name, d.ip, d.mac, d.vendor, ...d.ports.map((p) => p.port + "/" + p.service + " " + p.name)]
    .join(" ")
    .toLowerCase();
  return hay.includes(q);
}

function portChip(d, p) {
  const chip = el("button", "port risk-" + p.risk + (p.accepted ? " accepted" : ""), p.port + "/" + p.service);
  chip.title = `${p.name} · ${RISK_TEXT[p.risk]} risk${p.accepted ? " · acknowledged" : ""} · click for advice`;
  chip.addEventListener("click", () => openAdvice(d, p));
  return chip;
}

function renderDevices() {
  const body = $("devices");
  body.replaceChildren();
  for (const d of devices.filter(matches)) {
    const tr = el("tr", d.trusted ? "" : "untrusted");

    const statusTd = el("td");
    statusTd.appendChild(el("span", "status " + (d.online ? "online" : "offline"), d.online ? "Online" : "Offline"));
    tr.appendChild(statusTd);

    const nameTd = el("td");
    const nameBox = el("input");
    nameBox.type = "text";
    nameBox.maxLength = 50;
    nameBox.placeholder = "Give it a name";
    nameBox.value = d.name;
    nameBox.addEventListener("input", () => (editing = true));
    nameTd.appendChild(nameBox);
    tr.appendChild(nameTd);

    const trustTd = el("td");
    const trustBox = el("input");
    trustBox.type = "checkbox";
    trustBox.checked = d.trusted;
    trustBox.setAttribute("aria-label", "Trusted");
    trustBox.addEventListener("change", () => (editing = true));
    trustTd.appendChild(trustBox);
    tr.appendChild(trustTd);

    tr.appendChild(cell(d.ip));
    tr.appendChild(cell(mask(d.mac)));
    tr.appendChild(cell(d.vendor));

    const portTd = el("td", "ports");
    if (d.ports.length === 0) portTd.textContent = "–";
    for (const p of d.ports) portTd.appendChild(portChip(d, p));
    tr.appendChild(portTd);

    tr.appendChild(cell(fmt(d.first_seen)));
    const lastTd = cell(ago(d.last_seen));
    lastTd.title = fmt(d.last_seen);
    tr.appendChild(lastTd);

    const actions = el("td");
    const saveBtn = el("button", "", "Save");
    saveBtn.addEventListener("click", () => save(d.mac, nameBox.value.trim(), trustBox.checked, saveBtn));
    const delBtn = el("button", "danger", "✕");
    delBtn.title = "Forget this device";
    delBtn.addEventListener("click", () => forget(d));
    actions.append(saveBtn, delBtn);
    tr.appendChild(actions);

    body.appendChild(tr);
  }
}

/* ---------- activity ---------- */

const EVENT_TEXT = {
  new_device: "New device",
  ip_changed: "IP changed",
  back_online: "Back online",
  port_opened: "Port opened",
  port_closed: "Port closed",
  device_removed: "Removed",
};

function renderEvents(events) {
  const list = $("events");
  list.replaceChildren();
  if (events.length === 0) list.appendChild(el("li", "", "No activity yet."));
  for (const e of events) {
    const risky = e.kind === "port_opened" && (e.risk === "high" || e.risk === "critical");
    const li = el("li", e.kind + (risky ? " risky" : ""));
    const who = (e.name || e.ip || mask(e.mac || "")) + (e.detail ? " · " + e.detail : "");
    const when = el("div", "when", ago(e.ts));
    when.title = fmt(e.ts);
    li.append(el("strong", "", (EVENT_TEXT[e.kind] || e.kind) + " "), el("span", "", who), when);
    list.appendChild(li);
  }
}

/* ---------- summary, score, top actions ---------- */

function renderSummary(summary) {
  const online = devices.filter((d) => d.online).length;
  const untrusted = devices.filter((d) => !d.trusted).length;
  const risky = devices.reduce((n, d) => n + openRisky(d).length, 0);
  $("c-total").textContent = devices.length;
  $("c-online").textContent = online;
  $("c-untrusted").textContent = untrusted;
  $("c-risky").textContent = risky;
  $("summary").textContent = `${devices.length} devices known, ${online} online, ${untrusted} not marked as trusted`;

  $("c-score").textContent = summary.score;
  $("c-score-label").textContent = summary.label;
  const level = summary.score >= 90 ? "ok" : summary.score >= 70 ? "good" : summary.score >= 50 ? "warn" : "bad";
  $("score-card").className = "card score-card score-" + level;
  const pen = summary.penalties;
  $("score-card").title =
    `${summary.penalty_points} penalty points. Each open port you have not acknowledged adds points by risk (` +
    Object.entries(pen.per_port).map(([k, v]) => `${k} ${v}`).join(", ") +
    `), each untrusted device ${pen.per_untrusted_device} (at most ${pen.untrusted_cap}). ` +
    `Score = 100 × e^(−points/${pen.scale}); an open critical port caps it at ${pen.caps.critical}, a high one at ${pen.caps.high}.`;

  const list = $("top-actions");
  list.replaceChildren();
  for (const a of summary.top_actions) {
    const li = el("li");
    const btn = el("button", "action");
    btn.append(
      el("span", "risk-badge small risk-" + a.risk, RISK_TEXT[a.risk]),
      el("span", "", ` ${a.name} on ${a.device_name || a.ip} (port ${a.port})`)
    );
    btn.addEventListener("click", () => {
      const d = devices.find((x) => x.mac === a.mac);
      const p = d && d.ports.find((x) => x.port === a.port);
      if (d && p) openAdvice(d, p);
    });
    li.appendChild(btn);
    list.appendChild(li);
  }
  $("todo").hidden = summary.top_actions.length === 0;
}

/* ---------- advice drawer ---------- */

function subnetOf(ip) {
  const parts = ip.split(".");
  return parts.length === 4 ? parts.slice(0, 3).join(".") + ".0/24" : ip;
}

function fill(text, d, p) {
  return text.replaceAll("{ip}", d.ip).replaceAll("{port}", String(p.port)).replaceAll("{subnet}", subnetOf(d.ip));
}

function stepNode(line) {
  if (!line.startsWith("$ ")) return el("p", "", line);
  const box = el("div", "cmd");
  const code = el("code", "", line.slice(2));
  const copy = el("button", "copy", "Copy");
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      copy.textContent = "Copied";
    } catch (e) {
      const range = document.createRange();
      range.selectNodeContents(code);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      copy.textContent = "Selected";
    }
    setTimeout(() => (copy.textContent = "Copy"), 1500);
  });
  box.append(code, copy);
  return box;
}

function renderAcceptButton() {
  const { p } = drawerTarget;
  $("drawer-accept").textContent = p.accepted ? "Undo: count this port again" : "I know about this";
  $("drawer-accept-note").textContent = p.accepted
    ? "Acknowledged: it no longer lowers your score."
    : "Only if you use this service on purpose and have secured it.";
}

async function openAdvice(d, p) {
  drawerTarget = { d, p };
  try {
    const advice = await api(`/api/advice/${p.port}?service=${encodeURIComponent(p.service)}`);
    $("drawer-risk").className = "risk-badge risk-" + advice.risk;
    $("drawer-risk").textContent = RISK_TEXT[advice.risk] + " risk";
    $("drawer-title").textContent = `Port ${p.port} · ${advice.name}`;
    $("drawer-device").textContent = `on ${d.name || d.vendor || "unnamed device"} (${d.ip})`;
    $("drawer-what").textContent = advice.what;
    $("drawer-why").textContent = advice.why;
    const fix = $("drawer-fix");
    fix.replaceChildren();
    for (const group of advice.fix) {
      const box = el("details", "fix-group");
      if (fix.children.length === 0) box.open = true;
      box.appendChild(el("summary", "", group.where));
      for (const line of group.steps) box.appendChild(stepNode(fill(line, d, p)));
      fix.appendChild(box);
    }
    const verify = $("drawer-verify");
    verify.replaceChildren(...advice.verify.map((line) => stepNode(fill(line, d, p))));
    renderAcceptButton();
    $("drawer").hidden = false;
    $("drawer-backdrop").hidden = false;
    $("drawer-close").focus();
  } catch (e) {
    alert("Could not load the advice: " + e.message);
  }
}

function closeAdvice() {
  $("drawer").hidden = true;
  $("drawer-backdrop").hidden = true;
  drawerTarget = null;
}

$("drawer-accept").addEventListener("click", async () => {
  if (!drawerTarget) return;
  const { d, p } = drawerTarget;
  try {
    await postJson(`/api/devices/${encodeURIComponent(d.mac)}/ports/${p.port}/accept`, { accepted: !p.accepted });
    p.accepted = !p.accepted;
    renderAcceptButton();
    load();
  } catch (e) {
    $("drawer-accept-note").textContent = "Could not save: " + e.message;
  }
});
$("drawer-close").addEventListener("click", closeAdvice);
$("drawer-backdrop").addEventListener("click", closeAdvice);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("drawer").hidden) closeAdvice();
});

/* ---------- defend tab ---------- */

let guideLoaded = false;

async function loadGuide() {
  if (guideLoaded) return;
  try {
    const guide = await api("/api/defense-guide");
    guideLoaded = true;
    const ticks = store.get("checklist", {});
    const root = $("checklist");
    root.replaceChildren();
    const all = [];
    const progress = () => {
      const done = all.filter((id) => ticks[id]).length;
      $("check-progress").textContent = `${done} / ${all.length} done`;
    };
    for (const section of guide.checklist) {
      const box = el("div", "check-section");
      box.appendChild(el("h3", "", section.title));
      for (const item of section.items) {
        all.push(item.id);
        const row = el("details", "check-item");
        const summary = el("summary");
        const tick = el("input");
        tick.type = "checkbox";
        tick.checked = Boolean(ticks[item.id]);
        tick.setAttribute("aria-label", item.text);
        tick.addEventListener("click", (e) => e.stopPropagation());
        tick.addEventListener("change", () => {
          ticks[item.id] = tick.checked;
          store.set("checklist", ticks);
          row.classList.toggle("done", tick.checked);
          progress();
        });
        row.classList.toggle("done", tick.checked);
        summary.append(tick, el("span", "", " " + item.text));
        row.append(summary, el("p", "muted", item.detail));
        box.appendChild(row);
      }
      root.appendChild(box);
    }
    progress();
    const pb = guide.unknown_device_playbook;
    $("playbook-title").textContent = pb.title;
    $("playbook-intro").textContent = pb.intro;
    $("playbook-steps").replaceChildren(
      ...pb.steps.map((s) => {
        const li = el("li");
        li.append(el("strong", "", s.title), el("p", "muted", s.text));
        return li;
      })
    );
  } catch (e) {
    $("checklist").textContent = "Could not load the guide: " + e.message;
  }
}

function showTab(name) {
  const defend = name === "defend";
  $("view-devices").hidden = defend;
  $("view-defend").hidden = !defend;
  $("tab-devices").classList.toggle("active", !defend);
  $("tab-defend").classList.toggle("active", defend);
  $("tab-devices").setAttribute("aria-selected", String(!defend));
  $("tab-defend").setAttribute("aria-selected", String(defend));
  store.set("tab", name);
  if (defend) loadGuide();
}

$("tab-devices").addEventListener("click", () => showTab("devices"));
$("tab-defend").addEventListener("click", () => showTab("defend"));

/* ---------- refresh loop ---------- */

async function load() {
  if (editing) return;
  try {
    const [devs, events, summary] = await Promise.all([
      api("/api/devices"),
      api("/api/events?limit=40"),
      api("/api/summary"),
    ]);
    devices = devs;
    renderSummary(summary);
    renderDevices();
    renderEvents(events);
  } catch (e) {
    $("summary").textContent = "Could not load data: " + e.message;
  }
}

$("search").addEventListener("input", renderDevices);
maskBox.addEventListener("change", () => { renderDevices(); load(); });
document.querySelectorAll(".filters button").forEach((b) =>
  b.addEventListener("click", () => {
    filter = b.dataset.filter;
    document.querySelectorAll(".filters button").forEach((x) => x.classList.toggle("active", x === b));
    renderDevices();
  })
);

showTab(params.get("tab") === "defend" ? "defend" : store.get("tab", "devices"));
load();
setInterval(load, 10000);
