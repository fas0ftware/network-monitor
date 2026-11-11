// Home Network Monitor dashboard. Every value from the API is written with
// textContent (never innerHTML), so device names and vendors cannot inject HTML.
"use strict";

const RISKY = new Set([21, 23, 445, 3389, 5900]);
const params = new URLSearchParams(location.search);
const maskBox = document.getElementById("mask");
maskBox.checked = params.has("mask") || params.has("demo");

let devices = [];
let filter = "all";
let editing = false; // pause auto-refresh while a row is being edited

const $ = (id) => document.getElementById(id);
const fmt = (iso) => iso.replace("T", " ");
const mask = (mac) => (maskBox.checked ? mac.slice(0, 8) + ":xx:xx:xx" : mac);

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
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

async function save(mac, name, trusted, button) {
  try {
    await api("/api/devices/" + encodeURIComponent(mac), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, trusted }),
    });
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

function matches(d) {
  if (filter === "online" && !d.online) return false;
  if (filter === "untrusted" && d.trusted) return false;
  if (filter === "risky" && !d.ports.some((p) => p.risky)) return false;
  const q = $("search").value.trim().toLowerCase();
  if (!q) return true;
  const hay = [d.name, d.ip, d.mac, d.vendor, ...d.ports.map((p) => p.port + "/" + p.service)]
    .join(" ")
    .toLowerCase();
  return hay.includes(q);
}

function renderDevices() {
  const body = $("devices");
  body.replaceChildren();
  for (const d of devices.filter(matches)) {
    const tr = document.createElement("tr");
    if (!d.trusted) tr.className = "untrusted";

    const statusTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "status " + (d.online ? "online" : "offline");
    badge.textContent = d.online ? "Online" : "Offline";
    statusTd.appendChild(badge);
    tr.appendChild(statusTd);

    const nameTd = document.createElement("td");
    const nameBox = document.createElement("input");
    nameBox.type = "text";
    nameBox.maxLength = 50;
    nameBox.placeholder = "Give it a name";
    nameBox.value = d.name;
    nameBox.addEventListener("input", () => (editing = true));
    nameTd.appendChild(nameBox);
    tr.appendChild(nameTd);

    const trustTd = document.createElement("td");
    const trustBox = document.createElement("input");
    trustBox.type = "checkbox";
    trustBox.checked = d.trusted;
    trustBox.addEventListener("change", () => (editing = true));
    trustTd.appendChild(trustBox);
    tr.appendChild(trustTd);

    tr.appendChild(cell(d.ip));
    tr.appendChild(cell(mask(d.mac)));
    tr.appendChild(cell(d.vendor));

    const portTd = document.createElement("td");
    if (d.ports.length === 0) portTd.textContent = "–";
    for (const p of d.ports) {
      const tag = document.createElement("span");
      tag.className = "port" + (p.risky ? " risky" : "");
      tag.textContent = p.port + "/" + p.service;
      portTd.appendChild(tag);
    }
    tr.appendChild(portTd);

    tr.appendChild(cell(fmt(d.first_seen)));
    const lastTd = cell(ago(d.last_seen));
    lastTd.title = fmt(d.last_seen);
    tr.appendChild(lastTd);

    const actions = document.createElement("td");
    const saveBtn = document.createElement("button");
    saveBtn.textContent = "Save";
    saveBtn.addEventListener("click", () => save(d.mac, nameBox.value.trim(), trustBox.checked, saveBtn));
    const delBtn = document.createElement("button");
    delBtn.className = "danger";
    delBtn.textContent = "✕";
    delBtn.title = "Forget this device";
    delBtn.addEventListener("click", () => forget(d));
    actions.append(saveBtn, delBtn);
    tr.appendChild(actions);

    body.appendChild(tr);
  }
}

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
  if (events.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No activity yet.";
    list.appendChild(li);
  }
  for (const e of events) {
    const li = document.createElement("li");
    const port = parseInt(e.detail, 10);
    li.className = e.kind + (e.kind === "port_opened" && RISKY.has(port) ? " risky" : "");
    const title = document.createElement("strong");
    title.textContent = (EVENT_TEXT[e.kind] || e.kind) + " ";
    const who = document.createElement("span");
    who.textContent = (e.name || e.ip || mask(e.mac || "")) + (e.detail ? " · " + e.detail : "");
    const when = document.createElement("div");
    when.className = "when";
    when.textContent = ago(e.ts);
    when.title = fmt(e.ts);
    li.append(title, who, when);
    list.appendChild(li);
  }
}

function renderSummary() {
  const online = devices.filter((d) => d.online).length;
  const untrusted = devices.filter((d) => !d.trusted).length;
  const risky = devices.reduce((n, d) => n + d.ports.filter((p) => p.risky).length, 0);
  $("c-total").textContent = devices.length;
  $("c-online").textContent = online;
  $("c-untrusted").textContent = untrusted;
  $("c-risky").textContent = risky;
  $("summary").textContent = `${devices.length} devices known, ${online} online, ${untrusted} not marked as trusted`;
}

async function load() {
  if (editing) return;
  try {
    const [devs, events] = await Promise.all([api("/api/devices"), api("/api/events?limit=40")]);
    devices = devs;
    renderSummary();
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

load();
setInterval(load, 10000);
