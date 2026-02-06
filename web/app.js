const $ = (id) => document.getElementById(id);
let ifaces = [];
const packets = [];
const MAX_PACKETS = 600;
let tableDirty = false;

let points = 0;
const maxPoints = 120;
const chart = new Chart($("chart"), {
  type: "line",
  data: {
    labels: [],
    datasets: [
      { label: "Mbps", data: [], borderColor: "#0d6efd", tension: 0.15 },
      { label: "Latency(us)", data: [], borderColor: "#f08c00", tension: 0.15 },
      { label: "Jitter(us)", data: [], borderColor: "#c92a2a", tension: 0.15 },
    ],
  },
  options: {
    responsive: true,
    animation: false,
    scales: { y: { beginAtZero: true } },
  },
});

function pushPoint(mbps, latUs, jitUs) {
  points += 1;
  chart.data.labels.push(String(points));
  chart.data.datasets[0].data.push(mbps);
  chart.data.datasets[1].data.push(latUs);
  chart.data.datasets[2].data.push(jitUs);
  if (chart.data.labels.length > maxPoints) {
    chart.data.labels.shift();
    chart.data.datasets.forEach((d) => d.data.shift());
  }
  chart.update();
}

function resetView() {
  points = 0;
  chart.data.labels = [];
  chart.data.datasets.forEach((d) => { d.data = []; });
  chart.update();
  $("k_mbps").textContent = "0 Mbps";
  $("k_pps").textContent = "0 pps";
  $("k_lat").textContent = "0 us";
  $("k_jit").textContent = "0 us";
  packets.length = 0;
  renderPacketTable();
  renderResult(null);
}

function renderResult(m) {
  const el = $("result");
  const pbody = $("pcpBody");
  if (!m || !m.valid) {
    el.textContent = "아직 결과 없음";
    pbody.innerHTML = "";
    return;
  }
  el.textContent =
    `pps=${Math.round(m.pps || 0)}, mbps=${(m.mbps || 0).toFixed(2)}, drops=${m.drops || 0}, ` +
    `vlan=${m.vlan_pkts || 0}, non-vlan=${m.non_vlan_pkts || 0}, lat(us)=${((m.lat_avg_ns || 0)/1000).toFixed(1)}, ` +
    `jitter(us)=${((m.jitter_avg_ns || 0)/1000).toFixed(1)}`;
  const p = m.pcp || [];
  pbody.innerHTML = "";
  for (let i = 0; i < 8; i++) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i}</td><td>${p[i] || 0}</td>`;
    pbody.appendChild(tr);
  }
}

function packetPassFilter(p) {
  const vf = $("pkt_vlan").value.trim();
  const pf = $("pkt_pcp").value.trim();
  const ipf = $("pkt_ip").value.trim().toLowerCase();
  const mf = $("pkt_mac").value.trim().toLowerCase();
  if (vf && String(p.vlan) !== vf) return false;
  if (pf && String(p.pcp) !== pf) return false;
  if (ipf && !(`${p.ip_src}`.toLowerCase().includes(ipf) || `${p.ip_dst}`.toLowerCase().includes(ipf))) return false;
  if (mf && !(`${p.src}`.toLowerCase().includes(mf) || `${p.dst}`.toLowerCase().includes(mf))) return false;
  return true;
}

function renderPacketTable() {
  const body = $("pktBody");
  const filtered = [];
  for (let i = packets.length - 1; i >= 0; i--) {
    const p = packets[i];
    if (packetPassFilter(p)) filtered.push(p);
    if (filtered.length >= 120) break;
  }
  body.innerHTML = filtered.map((p) =>
    `<tr><td>${p.t}</td><td>${p.len}</td><td>${p.vlan}</td><td>${p.pcp}</td><td>${p.src}</td><td>${p.dst}</td><td>${p.ip_src}</td><td>${p.ip_dst}</td><td>${p.sport}</td><td>${p.dport}</td></tr>`
  ).join("");
}

function scheduleTableRender() {
  if (tableDirty) return;
  tableDirty = true;
  setTimeout(() => {
    tableDirty = false;
    renderPacketTable();
  }, 250);
}

function setStatus(text) {
  $("status").textContent = text;
}

async function loadInterfaces() {
  const r = await fetch("/api/interfaces");
  const j = await r.json();
  const tx = $("tx_if");
  const rx = $("rx_if");
  tx.innerHTML = "";
  rx.innerHTML = "";
  if (!j.ok || !j.interfaces || j.interfaces.length === 0) {
    setStatus("no interfaces found");
    return;
  }
  ifaces = j.interfaces.slice();
  ifaces.sort((a, b) => {
    const score = (x) => {
      let s = 0;
      if (x.carrier === 1) s += 100;
      if (x.running === 1) s += 20;
      if ((x.name || "").startsWith("enx")) s += 10; // USB NIC 우선
      return s;
    };
    return score(b) - score(a);
  });

  ifaces.forEach((it) => {
    const ip = it.ip || "no-ip";
    const c = it.carrier === 1 ? "link-up" : "link-down";
    const label = `${it.name} (${ip}, ${it.mac}, ${c})`;
    const o1 = document.createElement("option");
    o1.value = it.name;
    o1.textContent = label;
    const o2 = document.createElement("option");
    o2.value = it.name;
    o2.textContent = label;
    tx.appendChild(o1);
    rx.appendChild(o2);
  });

  const linked = ifaces.filter((x) => x.carrier === 1 && (x.name || "").startsWith("enx"));
  if (linked.length >= 2) {
    tx.value = linked[0].name;
    rx.value = linked[1].name;
  } else if (ifaces.length >= 2) {
    tx.value = ifaces[0].name;
    rx.value = ifaces[1].name;
  } else if (ifaces.length === 1) {
    tx.value = ifaces[0].name;
    rx.value = ifaces[0].name;
  }

  const onRxChange = () => {
    if (!$("auto_dst").checked) return;
    const sel = ifaces.find((x) => x.name === rx.value);
    if (!sel) return;
    $("dst_mac").value = sel.mac || "";
    // IPv4 없으면 서버에서 fallback
    $("dst_ip").value = sel.ip || "";
  };
  rx.onchange = onRxChange;
  $("auto_dst").onchange = onRxChange;
  onRxChange();
}

async function startRun() {
  const txif = $("tx_if").value;
  const rxif = $("rx_if").value;
  if (txif === rxif) {
    setStatus("start failed: TX/RX interface must be different");
    return;
  }

  if ($("auto_dst").checked) {
    const sel = ifaces.find((x) => x.name === rxif);
    if (sel) {
      $("dst_mac").value = sel.mac || $("dst_mac").value;
      $("dst_ip").value = sel.ip || $("dst_ip").value;
    }
  }

  const q = new URLSearchParams({
    tx_if: txif,
    rx_if: rxif,
    dst_ip: $("dst_ip").value.trim(),
    dst_mac: $("dst_mac").value.trim(),
    rate_mbps: $("rate_mbps").value.trim(),
    duration_sec: $("duration_sec").value.trim(),
    vlan: $("vlan").value.trim(),
  });
  const r = await fetch(`/api/start?${q.toString()}`, { method: "POST" });
  const j = await r.json();
  if (!j.ok) {
    setStatus(`start failed: ${j.error || "unknown"}`);
    return;
  }
  resetView();
  setStatus("started");
}

async function stopRun() {
  await fetch("/api/stop", { method: "POST" });
  resetView();
  setStatus("stopped");
}

function bindButtons() {
  $("startBtn").addEventListener("click", startRun);
  $("stopBtn").addEventListener("click", stopRun);
  ["pkt_vlan", "pkt_pcp", "pkt_ip", "pkt_mac"].forEach((id) => {
    $(id).addEventListener("input", () => renderPacketTable());
  });
}

function startStream() {
  const es = new EventSource("/api/stream");
  es.onmessage = (ev) => {
    const d = JSON.parse(ev.data);
    const m = d.metrics || {};
    if (!d.running) {
      $("k_mbps").textContent = "0 Mbps";
      $("k_pps").textContent = "0 pps";
      $("k_lat").textContent = "0 us";
      $("k_jit").textContent = "0 us";
      setStatus(`running=false session=${d.session || "-"}`);
      renderResult(m.valid ? m : null);
      return;
    }
    $("k_mbps").textContent = `${(m.mbps || 0).toFixed(2)} Mbps`;
    $("k_pps").textContent = `${Math.round(m.pps || 0)} pps`;
    $("k_lat").textContent = `${((m.lat_avg_ns || 0) / 1000).toFixed(1)} us`;
    $("k_jit").textContent = `${((m.jitter_avg_ns || 0) / 1000).toFixed(1)} us`;
    setStatus(`running=${d.running} session=${d.session || "-"}`);
    renderResult(m);
    if (m.valid) pushPoint(m.mbps || 0, (m.lat_avg_ns || 0) / 1000, (m.jitter_avg_ns || 0) / 1000);
  };
  es.addEventListener("packet", (ev) => {
    try {
      const p = JSON.parse(ev.data);
      packets.push(p);
      if (packets.length > MAX_PACKETS) packets.shift();
      scheduleTableRender();
    } catch (_) {
    }
  });
  es.onerror = () => setStatus("stream reconnecting...");
}

async function init() {
  await loadInterfaces();
  bindButtons();
  startStream();
}

init();
