const $ = (id) => document.getElementById(id);

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
  j.interfaces.forEach((it, idx) => {
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
    if (idx === 0) tx.value = it.name;
    if (idx === 1) rx.value = it.name;
  });
  if (rx.options.length > 0 && rx.value === "" && tx.options.length > 0) rx.value = tx.value;
}

async function startRun() {
  const q = new URLSearchParams({
    tx_if: $("tx_if").value,
    rx_if: $("rx_if").value,
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
  setStatus("started");
}

async function stopRun() {
  await fetch("/api/stop", { method: "POST" });
  setStatus("stopped");
}

function bindButtons() {
  $("startBtn").addEventListener("click", startRun);
  $("stopBtn").addEventListener("click", stopRun);
}

function startStream() {
  const es = new EventSource("/api/stream");
  es.onmessage = (ev) => {
    const d = JSON.parse(ev.data);
    const m = d.metrics || {};
    $("k_mbps").textContent = `${(m.mbps || 0).toFixed(2)} Mbps`;
    $("k_pps").textContent = `${Math.round(m.pps || 0)} pps`;
    $("k_lat").textContent = `${((m.lat_avg_ns || 0) / 1000).toFixed(1)} us`;
    $("k_jit").textContent = `${((m.jitter_avg_ns || 0) / 1000).toFixed(1)} us`;
    setStatus(`running=${d.running} session=${d.session || "-"}`);
    if (m.valid) pushPoint(m.mbps || 0, (m.lat_avg_ns || 0) / 1000, (m.jitter_avg_ns || 0) / 1000);
  };
  es.onerror = () => setStatus("stream reconnecting...");
}

async function init() {
  await loadInterfaces();
  bindButtons();
  startStream();
}

init();
