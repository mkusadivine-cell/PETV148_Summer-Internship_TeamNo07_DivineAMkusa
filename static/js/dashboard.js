// LogSentinel dashboard client logic

const $ = (id) => document.getElementById(id);

const SEV_COLORS = {
  critical: '#e5484d',
  high: '#ff7a45',
  medium: '#f2c94c',
  low: '#4fa3d1',
};
const TYPE_LABELS = {
  brute_force: 'Brute force',
  error_flood: '404 flood',
  http_flood: 'Request flood',
  suspicious_ua: 'Suspicious UA',
  after_hours: 'After hours',
};

Chart.defaults.color = '#8a97ad';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.borderColor = '#1c2739';

let charts = {};
let selectedFile = null;

// ---------------------------------------------------------------------
// Upload UI
// ---------------------------------------------------------------------
const dropzone = $('dropzone');
const fileInput = $('fileInput');

dropzone.addEventListener('click', () => fileInput.click());
$('browseBtn').addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });

['dragenter', 'dragover'].forEach(evt =>
  dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add('drag-over'); })
);
['dragleave', 'drop'].forEach(evt =>
  dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove('drag-over'); })
);
dropzone.addEventListener('drop', (e) => {
  if (e.dataTransfer.files.length) setSelectedFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) setSelectedFile(fileInput.files[0]);
});

function setSelectedFile(file) {
  selectedFile = file;
  dropzone.querySelector('p strong').textContent = file.name;
  $('uploadBtn').disabled = false;
}

$('uploadBtn').addEventListener('click', async () => {
  if (!selectedFile) return;
  const status = $('uploadStatus');
  status.textContent = 'Uploading & parsing...';
  status.className = 'upload-status';

  const form = new FormData();
  form.append('file', selectedFile);
  form.append('log_type', $('logTypeSelect').value);

  try {
    const res = await fetch('/api/upload', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Upload failed');
    status.textContent = `Ingested ${data.rows_inserted} rows as ${data.detected_type} log ` +
      `(${data.rows_skipped} skipped).`;
    status.className = 'upload-status ok';
    await runDetection();
    await refreshAll();
  } catch (err) {
    status.textContent = err.message;
    status.className = 'upload-status err';
  }
});

$('loadSampleBtn').addEventListener('click', async () => {
  const status = $('uploadStatus');
  status.textContent = 'Loading bundled sample logs...';
  status.className = 'upload-status';
  try {
    const res = await fetch('/api/load-sample', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Could not load sample data');
    status.textContent = data.message;
    status.className = 'upload-status ok';
    await runDetection();
    await refreshAll();
  } catch (err) {
    status.textContent = err.message;
    status.className = 'upload-status err';
  }
});

$('detectBtn').addEventListener('click', async () => {
  await runDetection();
  await refreshAll();
});

$('resetBtn').addEventListener('click', async () => {
  if (!confirm('Clear all ingested logs and anomalies?')) return;
  await fetch('/api/reset', { method: 'POST' });
  await refreshAll();
});

async function runDetection() {
  const status = $('detectStatus');
  status.textContent = 'Running detectors...';
  status.className = 'upload-status';
  const cfg = {
    brute_force_threshold: parseInt($('cfgBruteThreshold').value, 10),
    brute_force_window: $('cfgBruteWindow').value,
    error_flood_threshold: parseInt($('cfgErrorThreshold').value, 10),
    error_flood_window: $('cfgErrorWindow').value,
    http_flood_threshold: parseInt($('cfgFloodThreshold').value, 10),
    http_flood_window: $('cfgFloodWindow').value,
    after_hours_start: parseInt($('cfgHoursStart').value, 10),
    after_hours_end: parseInt($('cfgHoursEnd').value, 10),
  };
  try {
    const res = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Detection failed');
    status.textContent = `Found ${data.anomalies_found} anomalies.`;
    status.className = 'upload-status ok';
  } catch (err) {
    status.textContent = err.message;
    status.className = 'upload-status err';
  }
}

$('intervalSelect').addEventListener('change', renderTimeseries);
$('filterType').addEventListener('change', renderAnomalyTable);
$('filterSeverity').addEventListener('change', renderAnomalyTable);

// ---------------------------------------------------------------------
// Data refresh orchestration
// ---------------------------------------------------------------------
async function refreshAll() {
  await Promise.all([
    renderSummary(),
    renderTimeseries(),
    renderStatusCodes(),
    renderTopIps(),
    renderAnomalyBreakdown(),
    renderHourly(),
    renderAnomalyTable(),
    renderUaTable(),
  ]);
}

async function getJSON(url) {
  const res = await fetch(url);
  return res.json();
}

// ---------------------------------------------------------------------
// KPIs + beacon
// ---------------------------------------------------------------------
async function renderSummary() {
  const s = await getJSON('/api/summary');
  $('kpi-total').textContent = s.total_logs.toLocaleString();
  $('kpi-ips').textContent = s.unique_ips.toLocaleString();
  $('kpi-errors').textContent = s.error_count.toLocaleString();
  $('kpi-anomalies').textContent = s.total_anomalies.toLocaleString();
  $('stat-rows').textContent = s.total_logs.toLocaleString();
  $('stat-anoms').textContent = s.total_anomalies.toLocaleString();
  $('stat-critical').textContent = s.critical_anomalies.toLocaleString();

  const beacon = $('beacon');
  beacon.className = 'beacon';
  if (s.critical_anomalies > 0) beacon.classList.add('beacon-critical');
  else if (s.total_anomalies > 5) beacon.classList.add('beacon-high');
  else if (s.total_anomalies > 0) beacon.classList.add('beacon-medium');
}

// ---------------------------------------------------------------------
// Timeseries
// ---------------------------------------------------------------------
async function renderTimeseries() {
  const interval = $('intervalSelect').value;
  const d = await getJSON(`/api/timeseries?interval=${interval}`);
  const labels = d.labels.map(l => new Date(l).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));

  const ctx = $('timeseriesChart');
  if (charts.timeseries) charts.timeseries.destroy();
  charts.timeseries = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Requests',
          data: d.requests,
          borderColor: '#3dd9c2',
          backgroundColor: 'rgba(61,217,194,0.12)',
          fill: true,
          tension: 0.25,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          label: 'Errors (4xx/5xx)',
          data: d.errors,
          borderColor: '#e5484d',
          backgroundColor: 'rgba(229,72,77,0.08)',
          fill: true,
          tension: 0.25,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { position: 'top', labels: { boxWidth: 10, usePointStyle: true } } },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } },
        y: { grid: { color: '#1c2739' }, beginAtZero: true },
      },
    },
  });
}

// ---------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------
async function renderStatusCodes() {
  const d = await getJSON('/api/status-codes');
  const colorFor = (code) => {
    const n = parseInt(code, 10);
    if (n >= 500) return '#e5484d';
    if (n >= 400) return '#ff7a45';
    if (n >= 300) return '#f2c94c';
    return '#3dd9c2';
  };
  const ctx = $('statusChart');
  if (charts.status) charts.status.destroy();
  charts.status = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: d.labels,
      datasets: [{ data: d.counts, backgroundColor: d.labels.map(colorFor), borderRadius: 4 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: '#1c2739' }, beginAtZero: true },
      },
    },
  });
}

// ---------------------------------------------------------------------
// Top IPs
// ---------------------------------------------------------------------
async function renderTopIps() {
  const d = await getJSON('/api/top-ips?limit=8');
  const ctx = $('topIpsChart');
  if (charts.topIps) charts.topIps.destroy();
  charts.topIps = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: d.labels,
      datasets: [{ data: d.counts, backgroundColor: '#f5a623', borderRadius: 4 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1c2739' }, beginAtZero: true },
        y: { grid: { display: false }, ticks: { font: { family: "'IBM Plex Mono', monospace", size: 11 } } },
      },
    },
  });
}

// ---------------------------------------------------------------------
// Anomaly breakdown doughnut
// ---------------------------------------------------------------------
async function renderAnomalyBreakdown() {
  const d = await getJSON('/api/anomaly-summary');
  const entries = Object.entries(d.by_type || {});
  const ctx = $('anomalyTypeChart');
  if (charts.anomalyType) charts.anomalyType.destroy();

  if (entries.length === 0) {
    charts.anomalyType = new Chart(ctx, {
      type: 'doughnut',
      data: { labels: ['No anomalies'], datasets: [{ data: [1], backgroundColor: ['#182338'] }] },
      options: { plugins: { legend: { display: false }, tooltip: { enabled: false } } },
    });
    return;
  }

  const palette = ['#f5a623', '#e5484d', '#3dd9c2', '#4fa3d1', '#f2c94c'];
  charts.anomalyType = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: entries.map(([k]) => TYPE_LABELS[k] || k),
      datasets: [{ data: entries.map(([, v]) => v), backgroundColor: palette, borderColor: '#121a2b', borderWidth: 2 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true, font: { size: 11 } } } },
    },
  });
}

// ---------------------------------------------------------------------
// Hourly distribution
// ---------------------------------------------------------------------
async function renderHourly() {
  const d = await getJSON('/api/hourly-distribution');
  const start = parseInt($('cfgHoursStart').value, 10) || 8;
  const end = parseInt($('cfgHoursEnd').value, 10) || 20;
  const colors = d.labels.map(h => {
    const hour = parseInt(h, 10);
    return (hour >= start && hour < end) ? '#3dd9c2' : '#ff7a45';
  });
  const ctx = $('hourlyChart');
  if (charts.hourly) charts.hourly.destroy();
  charts.hourly = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: d.labels.map(h => `${h}:00`),
      datasets: [{ data: d.counts, backgroundColor: colors, borderRadius: 3 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            afterLabel: (item) => {
              const hour = parseInt(item.label, 10);
              return (hour >= start && hour < end) ? 'business hours' : 'after hours';
            },
          },
        },
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { family: "'IBM Plex Mono', monospace", size: 10 } } },
        y: { grid: { color: '#1c2739' }, beginAtZero: true },
      },
    },
  });
}

// ---------------------------------------------------------------------
// Anomalies table
// ---------------------------------------------------------------------
async function renderAnomalyTable() {
  const type = $('filterType').value;
  const severity = $('filterSeverity').value;
  const params = new URLSearchParams();
  if (type) params.set('type', type);
  if (severity) params.set('severity', severity);
  const rows = await getJSON(`/api/anomalies?${params.toString()}`);
  const tbody = $('anomalyTableBody');

  if (!rows.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No anomalies match this filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(r => {
    const start = r.window_start ? new Date(r.window_start).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
    const end = r.window_end ? new Date(r.window_end).toLocaleString([], { hour: '2-digit', minute: '2-digit' }) : '';
    return `<tr>
      <td><span class="badge badge-${r.severity}">${r.severity}</span></td>
      <td><span class="type-tag">${TYPE_LABELS[r.type] || r.type}</span></td>
      <td><span class="ip-mono">${r.ip || '—'}</span></td>
      <td>${start}${end ? ' → ' + end : ''}</td>
      <td>${r.count}</td>
      <td>${escapeHtml(r.description || '')}</td>
    </tr>`;
  }).join('');
}

// ---------------------------------------------------------------------
// Suspicious UA table
// ---------------------------------------------------------------------
async function renderUaTable() {
  const rows = await getJSON('/api/suspicious-agents');
  const tbody = $('uaTableBody');
  if (!rows.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="3">Nothing suspicious yet.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `<tr>
    <td><span class="ip-mono">${escapeHtml(r.user_agent || '(empty)')}</span></td>
    <td>${r.count}</td>
    <td>${r.unique_ips}</td>
  </tr>`).join('');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------
refreshAll();
