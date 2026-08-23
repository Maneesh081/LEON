"use strict";

/* ---------- state ---------- */
const state = {
  events: [],
  blocked: [],
  trend: null,
  modelsChart: null,
  perClassChart: null,
  opsChart: null,
  classChart: null,
};

const $ = (id) => document.getElementById(id);

const chartOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { labels: { color: "#8b949e", boxWidth: 10, usePointStyle: true, font: { size: 11 } } },
    tooltip: {
      backgroundColor: "#1c222b",
      borderColor: "#2d333b",
      borderWidth: 1,
      titleColor: "#e6edf3",
      bodyColor: "#c9d1d9",
      padding: 10,
      cornerRadius: 8,
      boxPadding: 4,
    },
  },
};

/* ---------- tabs ---------- */
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "models") loadModels();
    if (btn.dataset.tab === "dataset") loadDataset();
    if (btn.dataset.tab === "blocks") { loadBlocks(); renderLogs(); }
  });
});

/* ---------- connection ---------- */
const proto = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${proto}://${location.host}/ws`);

ws.onopen = () => {
  $("conn").className = "dot on";
  $("connText").textContent = "live";
};

ws.onclose = () => {
  $("conn").className = "dot off";
  $("connText").textContent = "disconnected - start run_ips to see live traffic";
};

ws.onmessage = (msg) => {
  const data = JSON.parse(msg.data);
  if (data.type === "snapshot") {
    state.events = data.events || [];
    state.events.forEach(ingest);
    render();
    return;
  }
  ingest(data);
  render();
};

/* ---------- ingest + render ---------- */
function ingest(ev) {
  state.events.push(ev);
  if (state.events.length > 2000) state.events.splice(0, state.events.length - 2000);
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString();
}

function count(kind) {
  return state.events.filter((e) => {
    if (kind === "flows") return e.type === "flow.features";
    if (kind === "alerts") return e.type === "decision" && e.action === "alert";
    if (kind === "blocks") return e.type === "decision" && e.action === "block";
    if (kind === "probes") return e.type === "honeypot.probe";
    return false;
  }).length;
}

function render() {
  $("cFlows").textContent = count("flows");
  $("cAlerts").textContent = count("alerts");
  $("cBlocks").textContent = count("blocks");
  $("cProbes").textContent = count("probes");
  renderFeed();
  renderProbes();
  renderTrend();
}

function actionPill(action) {
  return `<span class="pill ${action}">${action}</span>`;
}

function renderFeed() {
  const rows = state.events
    .filter((e) => e.type === "decision")
    .slice(-40)
    .reverse();
  const tbody = $("feed").querySelector("tbody");
  tbody.innerHTML = rows
    .map((e) => {
      const conf = e.confidence != null ? e.confidence.toFixed(3) : "—";
      const label = e.label || (e.source === "honeypot" ? "ANOMALY" : "—");
      const flow = e.flow || {};
      const endpoint = `${flow.src_ip || "?"}:${flow.src_port ?? ""} → ${flow.dst_ip || "?"}:${flow.dst_port ?? ""}`;
      const proto = flow.protocol === 6 ? "TCP" : flow.protocol === 17 ? "UDP" : flow.protocol || "—";
      return `<tr>
        <td>${fmtTime(e.ts)}</td>
        <td>${proto}</td>
        <td title="${e.attacker_ip}">${endpoint}</td>
        <td class="pill ${label === "ANOMALY" ? "anomaly" : "benign"}">${label}</td>
        <td>${conf}</td>
        <td>${e.novelty ? '<span class="pill novel">YES</span>' : "no"}</td>
        <td>${actionPill(e.action)}</td>
        <td style="color:var(--muted)">${e.reason || ""}</td>
        <td class="why" title="${e.explanation ? e.explanation.replace(/"/g, "&quot;") : ""}">${e.explanation || "—"}</td>
      </tr>`;
    })
    .join("") || '<tr><td colspan="9" class="muted">no decisions yet — run: sudo ./run_ips.sh --live -i wlan0 -d 30</td></tr>';
}

function renderProbes() {
  const rows = state.events.filter((e) => e.type === "honeypot.probe").slice(-15).reverse();
  $("probeTable").querySelector("tbody").innerHTML = rows
    .map((e) => `<tr><td>${fmtTime(e.ts)}</td><td style="color:var(--red)">${e.ip}</td><td>${e.port ?? ""}</td></tr>`)
    .join("") || '<tr><td colspan="3" class="muted">no probes yet</td></tr>';
}

/* ---------- trend chart (cumulative lines) ---------- */
function renderTrend() {
  const decisions = state.events.filter((e) => e.type === "decision").slice(-60);
  if (!state.trend) {
    state.trend = new Chart($("trend"), {
      type: "line",
      data: {
        labels: [],
        datasets: [
          { label: "ALLOW", data: [], borderColor: "#3fb950", backgroundColor: "rgba(63,185,80,.06)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
          { label: "ALERT", data: [], borderColor: "#d29922", backgroundColor: "rgba(210,153,34,.10)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
          { label: "BLOCK", data: [], borderColor: "#f85149", backgroundColor: "rgba(248,81,73,.10)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
        ],
      },
      options: {
        ...chartOpts,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { ticks: { color: "#8b949e", maxTicksLimit: 8, maxRotation: 0 }, grid: { color: "rgba(45,51,59,.5)" } },
          y: { beginAtZero: true, ticks: { color: "#8b949e", precision: 0 }, grid: { color: "rgba(45,51,59,.5)" } },
        },
      },
    });
  }
  const labels = decisions.map((d) => fmtTime(d.ts));
  let a = 0, b = 0, w = 0;
  state.trend.data.labels = labels;
  state.trend.data.datasets[0].data = decisions.map((d) => { if (d.action === "allow") w++; return w; });
  state.trend.data.datasets[1].data = decisions.map((d) => { if (d.action === "alert") a++; return a; });
  state.trend.data.datasets[2].data = decisions.map((d) => { if (d.action === "block") b++; return b; });
  state.trend.update("none");
}

/* ---------- models tab ---------- */
async function loadModels() {
  const res = await fetch("/api/models");
  const data = await res.json();
  if (data.error) { $("modelsError").textContent = data.error; return; }
  $("modelsError").textContent = "";
  const results = data.results || {};
  const names = Object.keys(results);

  const top = names.filter((n) => results[n].kind === "supervised")
    .sort((x, y) => results[y].macro_f1 - results[x].macro_f1)[0];
  $("winnerBadge").classList.remove("hidden");
  $("winnerBadge").textContent = `Winner: ${top} (macroF1 ${results[top].macro_f1.toFixed(4)}) · live artifact: model/models/best_model.joblib`;

  function kindBadge(kind) {
    const cls = kind === "supervised" ? "badge-sup" : "badge-nov";
    return `<span class="pill ${cls}">${kind}</span>`;
  }

  const tbody = $("modelsTable").querySelector("tbody");
  tbody.innerHTML = names.map((n) => {
    const m = results[n];
    const isWinner = n === top;
    return `<tr class="${isWinner ? "winner-row" : ""}">
      <td>${n}${isWinner ? ' <span class="trophy">🏆</span>' : ""}</td>
      <td>${kindBadge(m.kind)}</td>
      <td>${m.accuracy.toFixed(4)}</td>
      <td class="f1-cell">${m.macro_f1.toFixed(4)}</td>
      <td>${m.weighted_f1.toFixed(4)}</td>
      <td>${(m.benign_false_alert_rate * 100).toFixed(2)}%</td>
      <td>${(m.attack_alert_recall * 100).toFixed(2)}%</td>
    </tr>`;
  }).join("");

  const barColors = names.map((n) => {
    if (n === top) return "#3fb950";
    if (results[n].kind === "supervised") return "#58a6ff";
    return "#d29922";
  });

  if (!state.modelsChart) {
    state.modelsChart = new Chart($("modelsChart"), {
      type: "bar",
      data: {
        labels: names,
        datasets: [
          { label: "accuracy", data: names.map((n) => results[n].accuracy), backgroundColor: barColors, borderRadius: 4 },
          { label: "macro F1", data: names.map((n) => results[n].macro_f1), backgroundColor: barColors.map((c) => c + "99"), borderRadius: 4 },
          { label: "weighted F1", data: names.map((n) => results[n].weighted_f1), backgroundColor: barColors.map((c) => c + "55"), borderRadius: 4 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#8b949e", usePointStyle: true, boxWidth: 10 } } },
        scales: {
          x: { ticks: { color: "#8b949e" }, grid: { display: false } },
          y: { beginAtZero: true, max: 1, ticks: { color: "#8b949e" }, grid: { color: "rgba(45,51,59,.5)" } },
        },
      },
    });
  } else {
    state.modelsChart.data.labels = names;
    state.modelsChart.data.datasets[0].data = names.map((n) => results[n].accuracy);
    state.modelsChart.data.datasets[1].data = names.map((n) => results[n].macro_f1);
    state.modelsChart.data.datasets[2].data = names.map((n) => results[n].weighted_f1);
    state.modelsChart.data.datasets[0].backgroundColor = barColors;
    state.modelsChart.data.datasets[1].backgroundColor = barColors.map((c) => c + "99");
    state.modelsChart.data.datasets[2].backgroundColor = barColors.map((c) => c + "55");
    state.modelsChart.update();
  }

  const topModel = results[top];
  const classes = Object.keys(topModel.per_class || {});
  const metricOf = (m) => classes.map((c) => topModel.per_class[c][m]);
  if (!state.perClassChart) {
    state.perClassChart = new Chart($("perClassChart"), {
      type: "bar",
      data: {
        labels: classes,
        datasets: [
          { label: "precision", data: metricOf("precision"), backgroundColor: "#58a6ff", borderRadius: 4 },
          { label: "recall", data: metricOf("recall"), backgroundColor: "#3fb950", borderRadius: 4 },
          { label: "F1", data: metricOf("f1"), backgroundColor: "#d29922", borderRadius: 4 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#8b949e", usePointStyle: true, boxWidth: 10 } }, title: { display: true, text: `${top} per-class scores`, color: "#8b949e" } },
        scales: { x: { ticks: { color: "#8b949e" }, grid: { display: false } }, y: { beginAtZero: true, max: 1, ticks: { color: "#8b949e" }, grid: { color: "rgba(45,51,59,.5)" } } },
      },
    });
  } else {
    state.perClassChart.data.labels = classes;
    state.perClassChart.data.datasets.forEach((ds, i) => { ds.data = metricOf(["precision", "recall", "f1"][i]); });
    state.perClassChart.update();
  }

  const ops = ["benign_false_alert_rate", "attack_alert_recall", "safe_flow_rate"];
  const opsColors = ["#f85149", "#3fb950", "#58a6ff"];
  if (!state.opsChart) {
    state.opsChart = new Chart($("opsChart"), {
      type: "bar",
      data: {
        labels: ops.map((o) => o.replace(/_/g, " ")),
        datasets: [{
          label: top,
          data: ops.map((o) => topModel[o] != null ? topModel[o] : 0),
          backgroundColor: opsColors,
          borderRadius: 4,
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, title: { display: true, text: "operational rates", color: "#8b949e" } },
        scales: { x: { beginAtZero: true, max: 1, ticks: { color: "#8b949e" }, grid: { color: "rgba(45,51,59,.5)" } }, y: { ticks: { color: "#8b949e" }, grid: { display: false } } },
      },
    });
  } else {
    state.opsChart.data.datasets[0].data = ops.map((o) => topModel[o] != null ? topModel[o] : 0);
    state.opsChart.update();
  }
}

/* ---------- dataset tab ---------- */
function fmtVal(v) {
  if (v == null) return "—";
  if (typeof v === "number" && !Number.isInteger(v)) return v.toFixed(4);
  return String(v);
}

async function loadDataset() {
  try {
    const res = await fetch("/api/dataset");
    const data = await res.json();
    if (data.error) { $("datasetError").textContent = data.error; return; }
    $("datasetError").textContent = "";
    $("dRows").textContent = data.total_rows.toLocaleString();
    $("dFiles").textContent = data.files.length;
    $("dBn").textContent = data.labels.BENIGN.toLocaleString();
    $("dAn").textContent = data.labels.ANOMALY.toLocaleString();

    $("fileTable").querySelector("tbody").innerHTML = data.files
      .map((f) => `<tr><td>${f.name}</td><td>${f.rows.toLocaleString()}</td></tr>`).join("");

    const thead = $("datasetTable").querySelector("thead");
    thead.innerHTML = `<tr>${data.features.map((f) => `<th>${f}</th>`).join("")}<th>Label</th></tr>`;
    $("datasetTable").querySelector("tbody").innerHTML = data.sample
      .map((r) => `<tr>${data.features.map((f) => `<td>${fmtVal(r[f])}</td>`).join("")}
        <td class="pill ${r.Label === "BENIGN" ? "benign" : "anomaly"}">${r.Label}</td></tr>`)
      .join("") || '<tr><td colspan="12" class="muted">no sample rows</td></tr>';

    renderClassChart(data.labels);
  } catch (e) {
    $("datasetError").textContent = "failed to load dataset: " + e;
  }
}

function renderClassChart(labels) {
  if (!state.classChart) {
    state.classChart = new Chart($("classChart"), {
      type: "bar",
      data: {
        labels: ["BENIGN", "ANOMALY"],
        datasets: [{ label: "rows", data: [labels.BENIGN, labels.ANOMALY], backgroundColor: ["#3fb950", "#f85149"], borderRadius: 6, borderSkipped: false }],
      },
      options: {
        ...chartOpts,
        scales: {
          x: { ticks: { color: "#8b949e" }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: "#8b949e", precision: 0 }, grid: { color: "rgba(45,51,59,.5)" } },
        },
      },
    });
  } else {
    state.classChart.data.datasets[0].data = [labels.BENIGN, labels.ANOMALY];
    state.classChart.update();
  }
}

/* ---------- blocks & logs ---------- */
async function loadBlocks() {
  try {
    const res = await fetch("/api/blocks");
    const data = await res.json();
    state.blocked = data.blocked || [];
    $("blockList").innerHTML = state.blocked.length
      ? state.blocked.map((ip) => `<li>⛔ ${ip}</li>`).join("")
      : '<li style="color:var(--muted)">no IPs currently blocked</li>';
    $("cBlocks").textContent = state.blocked.length;
  } catch (e) {
    $("blockList").innerHTML = '<li style="color:var(--muted)">cannot read nftables (needs root?)</li>';
  }
}
$("refreshBlocks").addEventListener("click", loadBlocks);

function renderLogs() {
  const lines = state.events.slice(-60).reverse().map((e) => JSON.stringify(e));
  $("eventLog").textContent = lines.join("\n");
}

/* ---------- boot ---------- */
setInterval(loadBlocks, 5000);
