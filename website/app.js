const baseData = {
  labels: ["Sep 20", "Sep 21", "Sep 22", "Sep 23", "Sep 24", "Sep 25", "Sep 26"],
  total: [3.1, 3.4, 3.2, 3.65, 3.48, 4.02, 4.18],
  successful: [2.82, 3.08, 2.91, 3.3, 3.13, 3.63, 3.78],
};

const regions = [
  { flag: "🇺🇸", name: "US East", requests: "8.92M", share: 36.1, response: "142 ms", error: "0.21%" },
  { flag: "🇺🇸", name: "US West", requests: "6.14M", share: 24.9, response: "168 ms", error: "0.29%" },
  { flag: "🇩🇪", name: "Europe", requests: "5.73M", share: 23.2, response: "204 ms", error: "0.38%" },
  { flag: "🇸🇬", name: "Asia Pacific", requests: "2.86M", share: 11.6, response: "238 ms", error: "0.52%" },
  { flag: "🇧🇷", name: "South America", requests: "1.05M", share: 4.2, response: "271 ms", error: "0.61%" },
  { flag: "🇦🇺", name: "Australia", requests: "0.74M", share: 3.0, response: "246 ms", error: "0.46%" },
  { flag: "🇨🇦", name: "Canada", requests: "0.51M", share: 2.1, response: "154 ms", error: "0.24%" },
];

const chart = document.querySelector("#trafficChart");
const tooltip = document.querySelector("#chartTooltip");
const regionRows = document.querySelector("#regionRows");
const dateRange = document.querySelector("#dateRange");
const regionFilter = document.querySelector("#regionFilter");
let showAll = false;
let refreshTimer = null;
let currentData = structuredClone(baseData);

function renderRows() {
  const selected = regionFilter.value;
  const filtered = regions.filter((item) => selected === "All regions" || item.name === selected);
  const visible = showAll ? filtered : filtered.slice(0, 5);
  regionRows.innerHTML = visible.map((item) => `
    <tr>
      <td><span class="region-name"><span class="flag">${item.flag}</span>${item.name}</span></td>
      <td>${item.requests}</td>
      <td><span class="share-cell"><span class="share-bar"><i style="width:${item.share}%"></i></span>${item.share}%</span></td>
      <td>${item.response}</td>
      <td class="${parseFloat(item.error) > 0.5 ? "error-warn" : "error-good"}">${item.error}</td>
    </tr>`).join("");
  document.querySelector("#viewAll").textContent = showAll ? "Show less ↑" : "View all →";
}

function drawChart() {
  const rect = chart.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  chart.width = Math.round(rect.width * ratio);
  chart.height = Math.round(rect.height * ratio);
  const ctx = chart.getContext("2d");
  ctx.scale(ratio, ratio);
  const width = rect.width;
  const height = rect.height;
  const pad = { top: 14, right: 17, bottom: 32, left: 43 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const dark = document.body.classList.contains("dark");
  const grid = dark ? "#2a3845" : "#e8edf1";
  const text = dark ? "#8fa0af" : "#8793a0";
  const max = 4.5;

  ctx.clearRect(0, 0, width, height);
  ctx.font = "10px Inter, sans-serif";
  ctx.fillStyle = text;
  ctx.strokeStyle = grid;
  ctx.lineWidth = 1;
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  for (let i = 0; i <= 4; i += 1) {
    const value = i;
    const y = pad.top + innerH - (value / max) * innerH;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width - pad.right, y); ctx.stroke();
    ctx.fillText(i === 0 ? "0" : `${i}M`, pad.left - 9, y);
  }
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  currentData.labels.forEach((label, i) => {
    const x = pad.left + (i / (currentData.labels.length - 1)) * innerW;
    ctx.fillText(label, x, height - pad.bottom + 12);
  });

  const points = (values) => values.map((value, i) => ({
    x: pad.left + (i / (values.length - 1)) * innerW,
    y: pad.top + innerH - (value / max) * innerH,
    value,
  }));
  const totalPoints = points(currentData.total);
  const successfulPoints = points(currentData.successful);
  const area = ctx.createLinearGradient(0, pad.top, 0, pad.top + innerH);
  area.addColorStop(0, "rgba(21,134,219,.12)");
  area.addColorStop(1, "rgba(21,134,219,0)");
  ctx.beginPath(); ctx.moveTo(totalPoints[0].x, pad.top + innerH);
  totalPoints.forEach((p) => ctx.lineTo(p.x, p.y));
  ctx.lineTo(totalPoints.at(-1).x, pad.top + innerH); ctx.closePath();
  ctx.fillStyle = area; ctx.fill();

  [[successfulPoints, "#22b6a8"], [totalPoints, "#1586db"]].forEach(([series, color]) => {
    ctx.beginPath();
    series.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
    series.forEach((p) => {
      ctx.beginPath(); ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = dark ? "#17212c" : "#fff"; ctx.fill();
      ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.stroke();
    });
  });
  chart._points = totalPoints;
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("show"), 1800);
}

function runQuery() {
  const button = document.querySelector("#runQuery");
  button.classList.add("running");
  button.lastChild.textContent = " Running…";
  setTimeout(() => {
    currentData = {
      ...currentData,
      total: currentData.total.map((value, i) => Math.min(4.45, +(value + Math.sin(Date.now() / 900 + i) * .07).toFixed(2))),
      successful: currentData.successful.map((value, i) => Math.min(4.1, +(value + Math.cos(Date.now() / 850 + i) * .05).toFixed(2))),
    };
    drawChart();
    document.querySelector("#updatedAt").textContent = "Updated just now";
    button.classList.remove("running");
    button.lastChild.textContent = " Run query";
    showToast("Query completed");
  }, 550);
}

document.querySelector("#runQuery").addEventListener("click", runQuery);
document.querySelector("#queryInput").addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runQuery();
});
document.querySelector("#refreshInterval").addEventListener("change", (event) => {
  clearInterval(refreshTimer);
  const seconds = Number(event.target.value);
  if (seconds) refreshTimer = setInterval(runQuery, seconds * 1000);
  showToast(seconds ? `Auto-refresh set to ${seconds}s` : "Auto-refresh disabled");
});
document.querySelector("#themeToggle").addEventListener("click", () => {
  document.body.classList.toggle("dark");
  drawChart();
});
document.querySelector("#saveView").addEventListener("click", (event) => {
  const saved = event.currentTarget.classList.toggle("saved");
  event.currentTarget.querySelector("span").textContent = saved ? "★" : "☆";
  localStorage.setItem("focus-saved-view", String(saved));
  showToast(saved ? "View saved" : "View removed");
});
document.querySelector("#shareButton").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(location.href); showToast("Share link copied"); }
  catch { showToast("Share link ready"); }
});
document.querySelector("#exportButton").addEventListener("click", () => {
  const csv = ["Region,Requests,Share,Average response,Error rate", ...regions.map((r) => `${r.name},${r.requests},${r.share}%,${r.response},${r.error}`)].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  link.download = "focus-traffic-export.csv"; link.click();
  URL.revokeObjectURL(link.href); showToast("CSV exported");
});
document.querySelector("#viewAll").addEventListener("click", () => { showAll = !showAll; renderRows(); });
regionFilter.addEventListener("change", renderRows);
dateRange.addEventListener("change", () => {
  document.querySelector("#chartSubtitle").textContent = `Trailing ${dateRange.value} days`;
  showToast(`Showing the last ${dateRange.value} days`);
});
document.querySelector("#environment").addEventListener("change", (event) => showToast(`Environment: ${event.target.value}`));
document.querySelector("#userMenu").addEventListener("click", () => showToast("Signed in as Jordan Davis"));
document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", (event) => {
  document.querySelectorAll(".nav-item").forEach((link) => link.classList.remove("active"));
  event.currentTarget.classList.add("active");
  if (event.currentTarget.dataset.section !== "Overview") showToast(`${event.currentTarget.dataset.section} selected`);
}));
chart.addEventListener("mousemove", (event) => {
  if (!chart._points) return;
  const rect = chart.getBoundingClientRect();
  const x = event.clientX - rect.left;
  let index = 0;
  chart._points.forEach((point, i) => { if (Math.abs(point.x - x) < Math.abs(chart._points[index].x - x)) index = i; });
  const point = chart._points[index];
  tooltip.innerHTML = `<strong>${currentData.labels[index]}</strong><br>Total ${currentData.total[index].toFixed(2)}M<br>Successful ${currentData.successful[index].toFixed(2)}M`;
  tooltip.style.left = `${point.x}px`; tooltip.style.top = `${point.y}px`; tooltip.classList.add("visible");
});
chart.addEventListener("mouseleave", () => tooltip.classList.remove("visible"));
window.addEventListener("resize", drawChart);

if (localStorage.getItem("focus-saved-view") === "true") {
  const button = document.querySelector("#saveView");
  button.classList.add("saved"); button.querySelector("span").textContent = "★";
}
renderRows();
requestAnimationFrame(drawChart);
