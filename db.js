const fs = require('fs');
const path = require('path');

const LOGS_FILE = path.join(__dirname, 'logs.json');

// Mock data list for pre-populating historical data
const mockIPs = [
  { ip: '185.220.101.5', country: 'Germany', code: 'DE' },
  { ip: '45.143.203.14', country: 'Russia', code: 'RU' },
  { ip: '198.51.100.42', country: 'United States', code: 'US' },
  { ip: '103.241.22.98', country: 'India', code: 'IN' },
  { ip: '91.241.19.22', country: 'Ukraine', code: 'UA' },
  { ip: '222.186.31.50', country: 'China', code: 'CN' },
  { ip: '177.53.120.5', country: 'Brazil', code: 'BR' },
  { ip: '81.169.145.88', country: 'Germany', code: 'DE' },
  { ip: '109.244.11.90', country: 'United Kingdom', code: 'GB' },
  { ip: '194.187.168.4', country: 'France', code: 'FR' }
];

const mockAttackPayloads = {
  HTTP: [
    { type: 'SQL Injection', severity: 'High', payload: "GET /admin?user=' OR '1'='1" },
    { type: 'Directory Traversal', severity: 'High', payload: 'GET /../../etc/passwd' },
    { type: 'Vulnerability Scanning', severity: 'Medium', payload: 'GET /wp-admin/install.php' },
    { type: 'Command Injection', severity: 'Critical', payload: 'POST /api/upload cmd=rm -rf /' },
    { type: 'XSS Attack', severity: 'Medium', payload: 'GET /search?q=<script>alert(1)</script>' }
  ],
  SSH: [
    { type: 'Brute Force Login', severity: 'High', payload: 'Failed login attempt. User: root, Pass: 123456' },
    { type: 'Brute Force Login', severity: 'High', payload: 'Failed login attempt. User: admin, Pass: admin' },
    { type: 'Brute Force Login', severity: 'Medium', payload: 'Failed login attempt. User: support, Pass: password' },
    { type: 'SSH Scan', severity: 'Low', payload: 'SSH Portscan / Connection attempt' }
  ],
  FTP: [
    { type: 'Brute Force Login', severity: 'High', payload: 'Failed FTP login. User: anonymous, Pass: anonymous@' },
    { type: 'Directory Traversal', severity: 'High', payload: 'FTP Command: DELE ../../boot.ini' },
    { type: 'Exploit Attempt', severity: 'Critical', payload: 'FTP Command: SITE CHMOD 777 /bin' }
  ]
};

// Helper to get random item
function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Generate a random IP and country if not matched
function getGeoIP(ip) {
  const match = mockIPs.find(item => item.ip === ip);
  if (match) return { country: match.country, code: match.code };
  
  // Return random country if not found
  const randomGeo = randomItem(mockIPs);
  return { country: randomGeo.country, code: randomGeo.code };
}

// Read database from file
function readDB() {
  try {
    if (!fs.existsSync(LOGS_FILE)) {
      // Create with initial mock data
      const initialLogs = generateMockHistoricalData();
      fs.writeFileSync(LOGS_FILE, JSON.stringify(initialLogs, null, 2));
      return initialLogs;
    }
    const data = fs.readFileSync(LOGS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading logs file:', error);
    return [];
  }
}

// Write database to file
function writeDB(data) {
  try {
    fs.writeFileSync(LOGS_FILE, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('Error writing logs file:', error);
  }
}

// Pre-populate system with historical data
function generateMockHistoricalData() {
  const logs = [];
  const now = new Date();
  
  // Generate 80 mock attacks spread over the last 12 hours
  for (let i = 80; i > 0; i--) {
    const service = randomItem(['HTTP', 'SSH', 'FTP']);
    const geo = randomItem(mockIPs);
    const attack = randomItem(mockAttackPayloads[service]);
    const timestamp = new Date(now.getTime() - i * 9 * 60000); // spread logs
    
    logs.push({
      id: `evt_${Date.now() - i * 540000}_${Math.random().toString(36).substr(2, 5)}`,
      timestamp: timestamp.toISOString(),
      ip: geo.ip,
      service: service,
      port: service === 'HTTP' ? 8080 : service === 'SSH' ? 2222 : 2121,
      type: attack.type,
      severity: attack.severity,
      payload: attack.payload,
      country: geo.country,
      countryCode: geo.code
    });
  }
  return logs;
}

module.exports = {
  getGeoIP,

  addLog(entry) {
    const logs = readDB();
    const geo = getGeoIP(entry.ip);
    
    const newLog = {
      id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      timestamp: new Date().toISOString(),
      ip: entry.ip,
      service: entry.service,
      port: entry.port,
      type: entry.type || 'Suspicious Activity',
      severity: entry.severity || 'Medium',
      payload: entry.payload || '',
      country: geo.country,
      countryCode: geo.code
    };
    
    logs.push(newLog);
    // Keep max 1000 logs to prevent file bloat
    if (logs.length > 1000) {
      logs.shift();
    }
    writeDB(logs);
    return newLog;
  },

  getLogs(limit = 100) {
    const logs = readDB();
    // Return sorted by timestamp descending
    return [...logs].reverse().slice(0, limit);
  },

  clearLogs() {
    writeDB([]);
    return [];
  },

  getStats() {
    const logs = readDB();
    const stats = {
      totalBlocked: logs.length,
      serviceCounts: { HTTP: 0, SSH: 0, FTP: 0 },
      severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0 },
      topIPs: {},
      topCountries: {},
      timeline: []
    };

    // Calculate distributions
    logs.forEach(log => {
      // Services
      if (stats.serviceCounts[log.service] !== undefined) {
        stats.serviceCounts[log.service]++;
      } else {
        stats.serviceCounts[log.service] = 1;
      }

      // Severities
      if (stats.severityCounts[log.severity] !== undefined) {
        stats.severityCounts[log.severity]++;
      }

      // Attacker IPs
      stats.topIPs[log.ip] = (stats.topIPs[log.ip] || 0) + 1;

      // Countries
      stats.topCountries[log.country] = (stats.topCountries[log.country] || 0) + 1;
    });

    // Format top IPs for charts (limit to top 5)
    stats.topIPs = Object.entries(stats.topIPs)
      .map(([ip, count]) => {
        const geo = getGeoIP(ip);
        return { ip, count, country: geo.country, code: geo.code };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Format top countries (limit to top 5)
    stats.topCountries = Object.entries(stats.topCountries)
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Timeline: Attacks over the last 10 periods (each period = 10 minutes)
    const now = Date.now();
    const PERIOD_MS = 10 * 60 * 1000; // 10 minutes
    const timelineData = Array.from({ length: 10 }).map((_, idx) => {
      const start = now - (9 - idx) * PERIOD_MS;
      const end = start + PERIOD_MS;
      const timeStr = new Date(start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      
      const count = logs.filter(log => {
        const t = new Date(log.timestamp).getTime();
        return t >= start && t < end;
      }).length;

      return { time: timeStr, count };
    });
    
    stats.timeline = timelineData;

    return stats;
  }
};
