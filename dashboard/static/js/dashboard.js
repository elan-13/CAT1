/* Network Security Assessment - dashboard client
 *
 * Vanilla JS, no dependencies (offline-safe). Fetches the /api/* endpoints,
 * renders each phase, polls every few seconds so the page stays live, and
 * drives the Phase 3/4 scripts through /api/run.
 */
"use strict";

const POLL_MS = 5000;
const SEV = ["Critical", "High", "Medium", "Low", "Info"];
const INSECURE = new Set(["HTTP", "FTP", "TELNET", "POP", "IMAP", "SMTP", "SNMP",
  "TFTP", "DNS", "NBNS", "LLMNR", "MDNS", "ARP", "NTLMSSP"]);

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => (Number(n) || 0).toLocaleString();
const sevColor = (s) => `var(--sev-${String(s)})`;

function timeAgo(iso) {
  if (!iso) return "never";
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

async function getJSON(url) {
  const r = await fetch(url, { headers: { "Cache-Control": "no-cache" } });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}

function toast(title, body, kind = "") {
  const wrap = $("#toasts");
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.innerHTML = `<div class="th">${esc(title)}</div>${body ? `<div class="tb">${esc(body)}</div>` : ""}`;
  wrap.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s";
    setTimeout(() => t.remove(), 300); }, kind === "err" ? 8000 : 4500);
}

/* ---- charts (pure DOM) ------------------------------------------------ */
function barChart(rows, { color, max } = {}) {
  const top = max || Math.max(1, ...rows.map((r) => r.value));
  return `<div class="bars">${rows.map((r) => {
    const pct = Math.max(2, (r.value / top) * 100);
    const fill = r.color || color || "var(--primary)";
    return `<div class="bar-row">
      <div class="lbl" title="${esc(r.label)}">${esc(r.label)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${fill}"></div></div>
      <div class="val">${esc(r.display ?? num(r.value))}</div>
    </div>`;
  }).join("")}</div>`;
}

function emptyState(title, cmd) {
  return `<div class="empty"><div class="big">${esc(title)}</div>
    ${cmd ? `Waiting for <code>${esc(cmd)}</code>` : ""}</div>`;
}

/* ---- overview --------------------------------------------------------- */
function renderKpis(k) {
  const cards = [
    { label: "Hosts up", value: num(k.hosts_up), sub: "Phase 1" },
    { label: "Open ports", value: num(k.open_ports), sub: "Phase 1", alert: k.open_ports > 0 },
    { label: "Packets analysed", value: num(k.packets), sub: "Phase 2", mono: true },
    { label: "Protocols seen", value: num(k.protocols), sub: "Phase 2" },
    { label: "Findings", value: num(k.findings_total), sub: "Phase 4" },
    { label: "Critical + High", value: num(k.findings_critical_high), sub: "Phase 4", alert: k.findings_critical_high > 0 },
    { label: "MAC spoof", value: k.mac_spoof_demonstrated ? "shown" : "—", sub: "Phase 3" },
  ];
  $("#kpis").innerHTML = cards.map((c) => `<div class="kpi ${c.alert ? "alert" : ""}">
    <div class="label">${esc(c.label)}</div>
    <div class="value ${c.mono ? "mono" : ""}">${esc(c.value)}</div>
    <div class="sub">${esc(c.sub)}</div></div>`).join("");
}

function renderStatus(sources) {
  const names = { phase1: "Phase 1 · Discovery", phase2: "Phase 2 · Capture",
    phase3: "Phase 3 · Spoofing", phase4: "Phase 4 · Findings" };
  const rows = Object.entries(names).map(([key, name]) => {
    const s = sources[key] || {};
    const on = s.exists;
    return `<tr><td>${esc(name)}</td>
      <td>${on ? '<span class="badge ok">ready</span>' : '<span class="badge muted">waiting</span>'}</td>
      <td class="mono small muted-text">${esc(s.path || "")}</td>
      <td class="small muted-text">${on ? esc(timeAgo(s.updated)) : "—"}</td></tr>`;
  });
  $("#status-table").innerHTML =
    `<thead><tr><th>Phase</th><th>Data</th><th>Source file</th><th>Updated</th></tr></thead>
     <tbody>${rows.join("")}</tbody>`;
}

/* ---- phase 1 ---------------------------------------------------------- */
async function loadPhase1() {
  const d = await getJSON("/api/phase1");
  setMeta("phase1", d.source);
  if (!d.available) {
    $("#p1-body").innerHTML = emptyState("No discovery results yet.", "phase1_discovery/scan.py");
    $("#p1-chart").innerHTML = emptyState("Nothing to chart yet.");
    return;
  }
  const rows = d.hosts.map((h) => {
    const open = (h.ports || []).filter((p) => p.state === "open");
    const ports = open.map((p) => `<span class="badge state-open">${esc(p.port)}${p.service ? "·" + esc(p.service) : ""}</span>`).join(" ") || '<span class="muted-text small">none</span>';
    return `<tr>
      <td class="mono">${esc(h.ip || "?")}</td>
      <td>${h.label ? esc(h.label) : `<span class="muted-text">${esc(h.hostname || "unknown")}</span>`}</td>
      <td class="mono small">${esc(h.mac || "—")}</td>
      <td class="small">${esc(h.os || "—")}</td>
      <td>${ports}</td></tr>`;
  });
  $("#p1-body").innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr><th>IP</th><th>Host</th><th>MAC</th><th>OS</th><th>Open ports</th></tr></thead>
    <tbody>${rows.join("")}</tbody></table></div>`;

  const chart = d.hosts.map((h) => ({
    label: (h.label || h.ip || "?"),
    value: (h.ports || []).filter((p) => p.state === "open").length,
  })).sort((a, b) => b.value - a.value);
  $("#p1-chart").innerHTML = chart.some((r) => r.value)
    ? barChart(chart, { color: "var(--primary)" })
    : emptyState("No open ports found on the scanned hosts.");
}

/* ---- phase 2 ---------------------------------------------------------- */
async function loadPhase2() {
  const d = await getJSON("/api/phase2");
  setMeta("phase2", d.source);
  if (!d.available) {
    $("#p2-proto").innerHTML = emptyState("No capture analysed yet.", "phase2_capture/analyze.py");
    $("#p2-talkers").innerHTML = emptyState("No traffic yet.");
    $("#p2-evidence").innerHTML = emptyState("No handshake / DNS evidence yet.");
    return;
  }
  const s = d.stats;
  const counts = Object.entries(s.protocol_counts || {}).slice(0, 9);
  const total = s.total_packets || counts.reduce((a, [, v]) => a + v, 0) || 1;
  $("#p2-proto").innerHTML = counts.length ? barChart(counts.map(([p, v]) => ({
    label: p, value: v, display: `${((v / total) * 100).toFixed(1)}%`,
    color: INSECURE.has(p.toUpperCase()) ? "var(--accent)" : "var(--primary)",
  }))) + `<p class="small muted-text" style="margin-top:12px">
    <span style="color:var(--accent)">■</span> amber = cleartext / spoofable protocol</p>`
    : emptyState("No protocols recorded.");

  const talkers = (s.top_talkers || []).slice(0, 8);
  $("#p2-talkers").innerHTML = talkers.length ? `<div class="table-wrap"><table class="data">
    <thead><tr><th>Host</th><th>Team</th><th>Sent</th><th>Bytes</th></tr></thead><tbody>${
    talkers.map((t) => `<tr><td class="mono">${esc(t.ip)}</td>
      <td class="small">${esc(t.label || "—")}</td>
      <td class="num">${num(t.packets_sent)}</td>
      <td class="num small">${num(t.bytes_sent)}</td></tr>`).join("")}</tbody></table></div>`
    : emptyState("No talkers recorded.");

  const hs = (s.tcp_handshakes || [])[0];
  const dns = (s.dns_lookups || [])[0];
  const ev = [];
  if (hs) ev.push({ t: `TCP three-way handshake · ${s.tcp_handshakes_total || 1} found`,
    d: `${hs.client}:${hs.client_port} → ${hs.server}:${hs.server_port} (${hs.service || ""})  ·  SYN #${hs.syn?.frame} → SYN/ACK #${hs.syn_ack?.frame} → ACK #${hs.ack?.frame}` });
  if (dns) ev.push({ t: `DNS lookup · ${s.dns_lookups_total || 1} queries`,
    d: `${dns.client} asked ${dns.server} for ${dns.query}  (frame #${dns.frame}, ${dns.transport || "UDP/53"})` });
  $("#p2-evidence").innerHTML = ev.length
    ? `<div class="evi">${ev.map((e) => `<div class="row"><div class="t">${esc(e.t)}</div><div class="d">${esc(e.d)}</div></div>`).join("")}</div>`
    : emptyState("Capture contained no new TCP handshake or DNS lookup.");
}

/* ---- phase 3 ---------------------------------------------------------- */
async function loadPhase3() {
  const d = await getJSON("/api/phase3");
  setMeta("phase3", d.source);
  const controls = $(".meta.row-actions"); // keep buttons; render log below
  if (!d.available) {
    $("#p3-body").innerHTML = emptyState(
      "No MAC log yet — use the buttons above, or run the guided demo in a terminal.",
      "phase3_spoofing/mac_control.py demo");
    return;
  }
  const stageBadge = (st) => {
    const cls = { before: "muted", after: "state-open", restored: "ok" }[st] || "muted";
    return `<span class="badge ${cls}">${esc(st)}</span>`;
  };
  const rows = d.entries.map((e) => `<tr>
    <td>${stageBadge(e.stage)}</td>
    <td class="small muted-text">${esc((e.timestamp || "").replace("T", " ").slice(0, 19))}</td>
    <td class="small">${esc(e.interface || "")}</td>
    <td class="mono">${esc(e.mac || "—")}</td>
    <td class="mono small">${esc(e.ipv4 || "—")}</td>
    <td class="small muted-text">${esc(e.note || "")}</td></tr>`);

  const before = d.entries.find((e) => e.stage === "before");
  const after = [...d.entries].reverse().find((e) => e.stage === "after");
  let verdict = "";
  if (before && after) {
    const changed = (before.mac || "").toLowerCase() !== (after.mac || "").toLowerCase();
    verdict = `<div class="banner" style="margin-bottom:16px">${changed
      ? `MAC changed <b>&nbsp;${esc(before.mac)} → ${esc(after.mac)}&nbsp;</b> — the laptop rejoined under a new identity. This is the Phase 3 point: a MAC is not an access control.`
      : `Snapshots recorded but the MAC has not changed yet.`}</div>`;
  }
  $("#p3-body").innerHTML = verdict + `<div class="table-wrap"><table class="data">
    <thead><tr><th>Stage</th><th>Time</th><th>Interface</th><th>MAC</th><th>IPv4</th><th>Note</th></tr></thead>
    <tbody>${rows.join("")}</tbody></table></div>`;
}

/* ---- phase 4 ---------------------------------------------------------- */
let sevFilter = null;
async function loadPhase4() {
  const d = await getJSON("/api/phase4");
  setMeta("phase4", d.source);
  if (!d.available) {
    $("#p4-sev").innerHTML = emptyState("No findings yet.", "phase4_analysis/analyze_security.py");
    $("#p4-firewall").innerHTML = emptyState("No firewall recommendations yet.");
    $("#p4-body").innerHTML = "";
    $("#p4-filter").innerHTML = "";
    return;
  }
  const bySev = d.summary?.findings_by_severity || {};
  $("#p4-sev").innerHTML = barChart(SEV.map((s) => ({
    label: s, value: bySev[s] || 0, color: sevColor(s),
  })), { max: Math.max(1, ...SEV.map((s) => bySev[s] || 0)) });

  $("#p4-firewall").innerHTML = d.firewall_rules
    ? `<pre class="code">${esc(d.firewall_rules)}</pre>`
    : emptyState("No firewall rules generated.");

  // severity filter chips
  $("#p4-filter").innerHTML = `<div class="row-actions">
    <button class="btn sm ${sevFilter === null ? "primary" : ""}" data-sev="">All</button>
    ${SEV.map((s) => `<button class="btn sm ${sevFilter === s ? "primary" : ""}" data-sev="${s}">${s} ${bySev[s] || 0}</button>`).join("")}</div>`;

  const items = d.findings.filter((f) => !sevFilter || f.severity === sevFilter);
  $("#p4-body").innerHTML = `<div class="table-wrap"><table class="data">
    <thead><tr><th>ID</th><th>Sev</th><th>Phase</th><th>Asset</th><th>Finding</th><th>Recommendation</th></tr></thead>
    <tbody>${items.map((f) => `<tr>
      <td class="mono small">${esc(f.id)}</td>
      <td><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td class="small muted-text">${esc(f.phase)}</td>
      <td class="small mono">${esc(f.asset)}</td>
      <td>${esc(f.title)}<div class="small muted-text" style="margin-top:3px">${esc(f.evidence || "")}</div></td>
      <td class="small muted-text">${esc(f.recommendation || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ---- meta line + nav dots -------------------------------------------- */
function setMeta(phase, source) {
  const el = $(`[data-meta="${phase}"]`);
  if (el && source) el.textContent = source.exists ? `updated ${timeAgo(source.updated)}` : "no data yet";
}

const LOADERS = { phase1: loadPhase1, phase2: loadPhase2, phase3: loadPhase3, phase4: loadPhase4 };
const SUBTITLES = {
  overview: "Live status across all four assessment phases",
  phase1: "Nmap host discovery, services and OS — read from Member 1's output",
  phase2: "Traffic capture parsed with PyShark — read from Member 2's output",
  phase3: "MAC spoofing log — runs on this laptop",
  phase4: "Synthesis, findings and hardening — runs on this laptop",
};
let current = "overview";

function showSection(name) {
  current = name;
  $$("[data-section]").forEach((s) => s.classList.toggle("hidden", s.dataset.section !== name));
  $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === name));
  $("#section-title").textContent = name === "overview" ? "Overview" : `Phase ${name.slice(-1)}`;
  $("#section-sub").textContent = SUBTITLES[name] || "";
  if (LOADERS[name]) LOADERS[name]().catch((e) => toast("Load failed", e.message, "err"));
}

/* ---- run actions ------------------------------------------------------ */
async function runAction(action, btn) {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> running`;
  try {
    const r = await fetch("/api/run", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    const data = await r.json();
    if (data.ok) {
      toast(`Done · ${action}`, lastLine(data.stdout), "ok");
    } else {
      toast(`Failed · ${action}`, data.error || lastLine(data.stderr) || `exit ${data.returncode}`, "err");
    }
  } catch (e) {
    toast(`Error · ${action}`, e.message, "err");
  } finally {
    btn.disabled = false;
    btn.innerHTML = original;
    await refreshActive(true);
    await poll();
  }
}
const lastLine = (s) => (s || "").trim().split("\n").filter(Boolean).pop() || "";

async function refreshActive(force) {
  if (LOADERS[current]) await LOADERS[current]().catch(() => {});
}

/* ---- polling ---------------------------------------------------------- */
const lastUpdated = {};
async function poll() {
  try {
    const o = await getJSON("/api/overview");
    renderKpis(o.kpis);
    renderStatus(o.sources);
    $("#sample-banner").classList.toggle("hidden", !o.is_sample);
    // nav dots + flash-on-change
    for (const [phase, s] of Object.entries(o.sources)) {
      const dot = $(`[data-dot="${phase}"]`);
      if (dot) dot.className = `dot ${s.exists ? "on" : "off"}`;
      if (s.exists && lastUpdated[phase] && s.updated !== lastUpdated[phase]) {
        flash(phase);
        if (current === phase) LOADERS[phase]?.().catch(() => {});
      }
      lastUpdated[phase] = s.updated;
    }
    $("#live-text").textContent = "live · just now";
  } catch (e) {
    $("#live-text").textContent = "reconnecting…";
  }
}
function flash(phase) {
  const nav = $(`.nav a[data-nav="${phase}"]`);
  if (nav) { nav.classList.add("flash"); setTimeout(() => nav.classList.remove("flash"), 1300); }
  if (current === phase) {
    const panel = $(`[data-section="${phase}"] .panel`);
    if (panel) { panel.classList.add("flash"); setTimeout(() => panel.classList.remove("flash"), 1300); }
  }
  toast(`${phase} updated`, "new data arrived", "ok");
}

/* ---- config / theme --------------------------------------------------- */
async function loadConfig() {
  try {
    const c = await getJSON("/api/config");
    $('[data-ctx="network"]').textContent = c.network || "—";
    $('[data-ctx="host"]').textContent = c.this_host || "—";
    $('[data-ctx="ip"]').textContent = c.local_ip || "—";
  } catch (_) { /* header just stays as … */ }
}
function initTheme() {
  const saved = localStorage.getItem("nsa-theme") || "dark";
  document.documentElement.dataset.theme = saved;
  $("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("nsa-theme", next);
  });
}

/* ---- wire up ---------------------------------------------------------- */
function init() {
  initTheme();
  $$(".nav a").forEach((a) => a.addEventListener("click", () => showSection(a.dataset.nav)));
  // event delegation for run buttons + severity filter
  document.addEventListener("click", (e) => {
    const run = e.target.closest("[data-run]");
    if (run) { runAction(run.dataset.run, run); return; }
    const sev = e.target.closest("[data-sev]");
    if (sev) { sevFilter = sev.dataset.sev || null; loadPhase4(); }
  });
  loadConfig();
  poll();
  showSection("overview");
  setInterval(poll, POLL_MS);
}
document.addEventListener("DOMContentLoaded", init);
