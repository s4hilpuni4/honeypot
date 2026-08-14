// Aegis Honeypot Intrusion Detection System client controller

let socket;
let audioEnabled = false;
let audioCtx = null;

// Charts instances
let trendChart = null;
let distributionChart = null;
let severityChart = null;

// Current alert logs stored locally
let cachedLogs = [];

// Init function
document.addEventListener('DOMContentLoaded', () => {
  initWS();
  initCharts();
  fetchInitialData();
  setupEventListeners();
});

// Setup DOM Event Listeners
function setupEventListeners() {
  // Toggle service ports
  ['HTTP', 'SSH', 'FTP'].forEach(service => {
    const el = document.getElementById(`toggle-${service}`);
    if (el) {
      el.addEventListener('change', () => {
        toggleService(service);
      });
    }
  });

  // Clear logs button
  document.getElementById('btn-clear-logs').addEventListener('click', () => {
    if (confirm('Are you sure you want to purge all active logs and reset telemetry metrics?')) {
      clearLogs();
    }
  });

  // Audio warning toggle
  const audioBtn = document.getElementById('btn-audio-toggle');
  audioBtn.addEventListener('click', () => {
    audioEnabled = !audioEnabled;
    if (audioEnabled) {
      audioBtn.classList.add('muted');
      audioBtn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i>';
      // Play a startup tone to unlock browser AudioContext
      playBeep(600, 0.1, 'sine');
      setTimeout(() => playBeep(800, 0.15, 'sine'), 100);
      logToTerminal('[AUDIO] Real-time sound warnings ENABLED', 'cyan');
    } else {
      audioBtn.classList.remove('muted');
      audioBtn.innerHTML = '<i class="fa-solid fa-volume-high"></i>';
      logToTerminal('[AUDIO] Sound warnings disabled', 'dim');
    }
  });

  // Modal handlers
  document.getElementById('close-modal-btn').addEventListener('click', closeModal);
  document.getElementById('details-modal').addEventListener('click', (e) => {
    if (e.target.id === 'details-modal') {
      closeModal();
    }
  });
}

// ----------------------------------------------------
// REST APIs Integration
// ----------------------------------------------------
async function fetchInitialData() {
  try {
    // 1. Fetch status of ports
    const statusRes = await fetch('/api/status');
    const status = await statusRes.json();
    updateToggles(status);

    // 2. Fetch logs
    const logsRes = await fetch('/api/logs');
    const logs = await logsRes.json();
    cachedLogs = logs;
    renderLogsTable(logs);
    
    // Output past logs to terminal in batch
    logToTerminal('[SYSTEM] Syncing database logs...', 'dim');
    logs.slice(-20).reverse().forEach(log => {
      printLogToTerminal(log);
    });

    // 3. Fetch stats and render charts
    const statsRes = await fetch('/api/stats');
    const stats = await statsRes.json();
    updateStatsDisplay(stats);
    updateCharts(stats);
  } catch (err) {
    console.error('Error fetching initial dataset:', err);
    logToTerminal('[ERROR] Database sync failed. Backend offline or unreachable.', 'red');
  }
}

async function toggleService(service) {
  try {
    const res = await fetch('/api/toggle-service', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service })
    });
    const data = await res.json();
    logToTerminal(`[SYSTEM] Sent instruction to toggle ${service} honeypot daemon.`, 'cyan');
  } catch (err) {
    console.error('Error toggling service:', err);
    logToTerminal(`[ERROR] Failed to modify status of ${service} honeypot.`, 'red');
  }
}

async function clearLogs() {
  try {
    await fetch('/api/clear', { method: 'POST' });
    logToTerminal('[SYSTEM] Cleared database logs.', 'dim');
  } catch (err) {
    console.error('Error clearing database logs:', err);
  }
}

// ----------------------------------------------------
// WebSockets Logic
// ----------------------------------------------------
function initWS() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}`;
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    logToTerminal('[WS] WebSockets communication tunnel active.', 'green');
    document.getElementById('system-state-value').textContent = 'SECURE';
    document.getElementById('system-state-value').className = 'stat-value text-safe';
  };

  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    const { type, data } = message;

    switch (type) {
      case 'NEW_LOG':
        cachedLogs.unshift(data);
        if (cachedLogs.length > 500) cachedLogs.pop();
        prependLogRow(data);
        printLogToTerminal(data);
        triggerThreatAlert(data);
        break;

      case 'STATS_UPDATE':
        updateStatsDisplay(data);
        updateCharts(data);
        break;

      case 'STATUS_UPDATE':
        updateToggles(data);
        break;

      case 'SESSIONS_COUNT':
        document.getElementById('stat-active-sessions').textContent = data;
        break;

      case 'CLEAR_LOGS':
        cachedLogs = [];
        document.getElementById('alerts-tbody').innerHTML = '';
        const term = document.getElementById('terminal-output');
        term.innerHTML = '<div class="terminal-line text-dim">[INFO] Database records purged. Waiting for new traffic...</div>';
        break;
    }
  };

  socket.onclose = () => {
    logToTerminal('[WS] WebSockets tunnel disconnected. Retrying in 5 seconds...', 'red');
    document.getElementById('system-state-value').textContent = 'OFFLINE';
    document.getElementById('system-state-value').className = 'stat-value text-muted';
    setTimeout(initWS, 5000);
  };
}

// ----------------------------------------------------
// UI Render Helpers
// ----------------------------------------------------
function updateToggles(status) {
  ['HTTP', 'SSH', 'FTP'].forEach(service => {
    const active = status[service];
    const toggle = document.getElementById(`toggle-${service}`);
    const label = document.getElementById(`status-${service}`);
    
    if (toggle) toggle.checked = active;
    if (label) {
      label.textContent = active ? 'ONLINE' : 'OFFLINE';
      label.className = active ? 'service-status text-green' : 'service-status text-muted';
    }
  });
}

function updateStatsDisplay(stats) {
  document.getElementById('stat-total-blocked').textContent = stats.totalBlocked;
}

// Draw list of logs to table
function renderLogsTable(logs) {
  const tbody = document.getElementById('alerts-tbody');
  tbody.innerHTML = '';
  logs.forEach(log => {
    tbody.appendChild(createRowElement(log));
  });
}

// Add new log to top of table
function prependLogRow(log) {
  const tbody = document.getElementById('alerts-tbody');
  const row = createRowElement(log);
  row.classList.add('row-new');
  
  tbody.insertBefore(row, tbody.firstChild);
  
  // Keep max rows in view
  if (tbody.children.length > 100) {
    tbody.removeChild(tbody.lastChild);
  }
}

// Create individual table row
function createRowElement(log) {
  const tr = document.createElement('tr');
  tr.id = `row-${log.id}`;
  
  const time = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const serviceClass = log.service.toLowerCase();
  const severityClass = log.severity.toLowerCase();

  tr.innerHTML = `
    <td style="font-family: 'Share Tech Mono', monospace; font-size: 0.75rem;">${time}</td>
    <td><span class="badge-service ${serviceClass}">${log.service}</span></td>
    <td style="font-family: 'Share Tech Mono', monospace; font-weight: 600;">${log.ip}</td>
    <td><img src="https://flagcdn.com/16x12/${log.countryCode.toLowerCase()}.png" style="vertical-align: middle; margin-right: 6px; border-radius:1px;" width="16" height="12"> ${log.country}</td>
    <td style="color: var(--text-primary); font-weight: 500;">${log.type}</td>
    <td><span class="severity-badge ${severityClass}">${log.severity}</span></td>
    <td>
      <button class="view-details-btn" onclick="openDetails('${log.id}')">
        <i class="fa-solid fa-square-poll-horizontal"></i> DETAILS
      </button>
    </td>
  `;
  return tr;
}

// Render dynamic log outputs to terminal
function logToTerminal(message, type = 'dim') {
  const term = document.getElementById('terminal-output');
  const line = document.createElement('div');
  line.className = `terminal-line text-${type}`;
  line.textContent = message;
  term.appendChild(line);
  
  // Scroll to bottom
  term.scrollTop = term.scrollHeight;
}

function printLogToTerminal(log) {
  const time = new Date(log.timestamp).toLocaleTimeString();
  let typeColor = 'dim';
  if (log.severity === 'Critical') typeColor = 'red';
  else if (log.severity === 'High') typeColor = 'pink';
  else if (log.severity === 'Medium') typeColor = 'yellow';
  
  logToTerminal(`[${time}] [${log.service}] INTRUSION: ${log.type} from ${log.ip} (${log.country}) - Risk: ${log.severity}`, typeColor);
}

// ----------------------------------------------------
// Details Modal Controllers
// ----------------------------------------------------
function openDetails(logId) {
  const log = cachedLogs.find(l => l.id === logId);
  if (!log) return;

  const dateStr = new Date(log.timestamp).toLocaleString();
  document.getElementById('modal-timestamp').textContent = dateStr;
  document.getElementById('modal-service').innerHTML = `<span class="badge-service ${log.service.toLowerCase()}">${log.service}</span> on port ${log.port}`;
  document.getElementById('modal-ip').textContent = log.ip;
  document.getElementById('modal-location').textContent = `${log.country} (${log.countryCode})`;
  
  const typeEl = document.getElementById('modal-type');
  typeEl.textContent = log.type;
  typeEl.className = `field-value severity-badge ${log.severity.toLowerCase()} font-bold`;

  document.getElementById('modal-payload').textContent = log.payload;

  document.getElementById('details-modal').classList.remove('hidden');
}

// Declare openDetails globally so it is accessible from inline buttons
window.openDetails = openDetails;

function closeModal() {
  document.getElementById('details-modal').classList.add('hidden');
}

// ----------------------------------------------------
// Interactive Warning Effects & Audio Synth
// ----------------------------------------------------
function triggerThreatAlert(log) {
  // If severity is critical/high, toggle state status text
  const stateVal = document.getElementById('system-state-value');
  if (log.severity === 'Critical') {
    stateVal.textContent = 'CRITICAL ATTACK DETECTED';
    stateVal.className = 'stat-value text-alert';
    playIntrusionSiren();
  } else if (log.severity === 'High') {
    stateVal.textContent = 'THREAT MITIGATED';
    stateVal.className = 'stat-value text-neon-red';
    playIntrusionAlert();
  } else {
    // Normal beep
    playBeep(450, 0.08, 'sine');
  }

  // Restore secure label after 4 seconds if no critical events occur
  if (log.severity === 'Critical' || log.severity === 'High') {
    setTimeout(() => {
      // Check if state has been changed by another newer critical event
      if (stateVal.textContent !== 'SECURE' && socket && socket.readyState === WebSocket.OPEN) {
        stateVal.textContent = 'SECURE';
        stateVal.className = 'stat-value text-safe';
      }
    }, 4500);
  }
}

// Audio Synthesizer Beeps (using Web Audio API)
function playBeep(frequency, duration, type = 'sine') {
  if (!audioEnabled) return;
  try {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    
    // Check state
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }

    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();

    oscillator.type = type;
    oscillator.frequency.value = frequency;
    
    gainNode.gain.setValueAtTime(0.06, audioCtx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);

    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    oscillator.start();
    oscillator.stop(audioCtx.currentTime + duration);
  } catch (err) {
    console.error('Synthesizer audio block:', err);
  }
}

// Siren for Critical incidents
function playIntrusionSiren() {
  if (!audioEnabled) return;
  playBeep(880, 0.25, 'sawtooth');
  setTimeout(() => playBeep(720, 0.25, 'sawtooth'), 200);
  setTimeout(() => playBeep(880, 0.25, 'sawtooth'), 400);
}

// Alert tone for High incidents
function playIntrusionAlert() {
  if (!audioEnabled) return;
  playBeep(650, 0.15, 'triangle');
  setTimeout(() => playBeep(650, 0.15, 'triangle'), 150);
}

// ----------------------------------------------------
// Chart.js Configuration
// ----------------------------------------------------
function initCharts() {
  // Set global styles for charts
  Chart.defaults.color = '#8f9cae';
  Chart.defaults.font.family = "'Outfit', sans-serif";
  Chart.defaults.font.size = 10;

  // 1. Timeline Chart (Line)
  const trendCtx = document.getElementById('trendChart').getContext('2d');
  const cyanGlow = trendCtx.createLinearGradient(0, 0, 0, 180);
  cyanGlow.addColorStop(0, 'rgba(0, 240, 255, 0.2)');
  cyanGlow.addColorStop(1, 'rgba(0, 240, 255, 0.0)');

  trendChart = new Chart(trendCtx, {
    type: 'line',
    data: {
      labels: Array(10).fill(''),
      datasets: [{
        label: 'Attacks Intercepted',
        data: Array(10).fill(0),
        borderColor: '#00f0ff',
        borderWidth: 2,
        backgroundColor: cyanGlow,
        fill: true,
        tension: 0.35,
        pointBackgroundColor: '#00f0ff',
        pointHoverRadius: 5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.03)' } },
        y: { 
          grid: { color: 'rgba(255,255,255,0.03)' },
          ticks: { precision: 0 }
        }
      }
    }
  });

  // 2. Distribution Chart (Doughnut)
  const distCtx = document.getElementById('distributionChart').getContext('2d');
  distributionChart = new Chart(distCtx, {
    type: 'doughnut',
    data: {
      labels: ['HTTP', 'SSH', 'FTP'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: [
          'rgba(0, 240, 255, 0.75)',
          'rgba(157, 78, 221, 0.75)',
          'rgba(255, 183, 0, 0.75)'
        ],
        borderWidth: 1,
        borderColor: '#10121e'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { boxWidth: 8, font: { size: 9 } }
        }
      },
      cutout: '68%'
    }
  });

  // 3. Severity Chart (Bar)
  const sevCtx = document.getElementById('severityChart').getContext('2d');
  severityChart = new Chart(sevCtx, {
    type: 'bar',
    data: {
      labels: ['CRIT', 'HIGH', 'MED', 'LOW'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [
          'rgba(255, 51, 51, 0.75)',
          'rgba(255, 0, 127, 0.75)',
          'rgba(255, 183, 0, 0.75)',
          'rgba(57, 255, 20, 0.75)'
        ],
        borderWidth: 1,
        borderColor: '#10121e'
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { display: false } },
        y: { grid: { display: false } }
      }
    }
  });
}

function updateCharts(stats) {
  if (!trendChart || !distributionChart || !severityChart) return;

  // Update timeline trend
  trendChart.data.labels = stats.timeline.map(t => t.time);
  trendChart.data.datasets[0].data = stats.timeline.map(t => t.count);
  trendChart.update();

  // Update target distribution
  distributionChart.data.datasets[0].data = [
    stats.serviceCounts.HTTP || 0,
    stats.serviceCounts.SSH || 0,
    stats.serviceCounts.FTP || 0
  ];
  distributionChart.update();

  // Update severity bars
  severityChart.data.datasets[0].data = [
    stats.severityCounts.Critical || 0,
    stats.severityCounts.High || 0,
    stats.severityCounts.Medium || 0,
    stats.severityCounts.Low || 0
  ];
  severityChart.update();
}
