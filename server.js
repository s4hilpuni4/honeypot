const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const net = require('net');
const path = require('path');
const db = require('./db');
const detection = require('./detection');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration and State
const SERVICES = {
  HTTP: { port: 8080, active: true, instance: null },
  SSH: { port: 2222, active: true, instance: null },
  FTP: { port: 2121, active: true, instance: null }
};

// WebSocket Broadcast helper
function broadcast(type, data) {
  const message = JSON.stringify({ type, data });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// ----------------------------------------------------
// 1. HTTP HONEYPOT SIMULATOR (Port 8080)
// ----------------------------------------------------
function startHTTPHoneypot() {
  const httpApp = express();
  httpApp.use(express.json());
  httpApp.use(express.urlencoded({ extended: true }));

  // Fake admin portal templates
  const loginHTML = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Router Admin Portal</title>
      <style>
        body { background: #121214; color: #e1e1e6; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #202024; padding: 2.5rem; border-radius: 8px; border: 1px solid #323238; box-shadow: 0 4px 10px rgba(0,0,0,0.3); width: 320px; }
        h2 { margin-top: 0; color: #ff5555; text-align: center; }
        input { width: 100%; padding: 0.75rem; margin: 0.75rem 0; border: 1px solid #323238; border-radius: 4px; background: #121214; color: #fff; box-sizing: border-box; }
        button { width: 100%; padding: 0.75rem; border: none; border-radius: 4px; background: #ff5555; color: #fff; font-weight: bold; cursor: pointer; }
        button:hover { background: #ff6e6e; }
        .footer { text-align: center; margin-top: 1.5rem; font-size: 0.8rem; color: #7c7c8a; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Gateway Control Panel</h2>
        <form method="POST" action="/login">
          <input type="text" name="username" placeholder="Username" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Sign In</button>
        </form>
        <div class="footer">Firmware v4.81.2 Build 20240901</div>
      </div>
    </body>
    </html>
  `;

  // Interceptor middleware for exploit scanning
  httpApp.use((req, res, next) => {
    const ip = req.ip.replace('::ffff:', '');
    const result = detection.analyzeHTTPRequest(req.method, req.url, req.headers, req.body);
    
    if (result.detected) {
      const log = db.addLog({
        ip,
        service: 'HTTP',
        port: SERVICES.HTTP.port,
        type: result.type,
        severity: result.severity,
        payload: `Method: ${req.method} | URL: ${req.url} | Reason: ${result.reason} | Headers: ${JSON.stringify(req.headers)}`
      });
      broadcast('NEW_LOG', log);
      broadcast('STATS_UPDATE', db.getStats());
      
      // Make it look like a vulnerability exists or throw error depending on severity
      if (result.severity === 'Critical') {
        return res.status(500).send('Internal Server Error: Execution failed on cluster module.');
      }
    }
    next();
  });

  // Serve login page
  httpApp.get('/', (req, res) => {
    res.send(loginHTML);
  });

  // Handle fake login post
  httpApp.post('/login', (req, res) => {
    const ip = req.ip.replace('::ffff:', '');
    const { username, password } = req.body;
    
    // Log auth attempts as vulnerability scanning / brute forcing
    const log = db.addLog({
      ip,
      service: 'HTTP',
      port: SERVICES.HTTP.port,
      type: 'Admin Portal Access Attempt',
      severity: 'Medium',
      payload: `Login credentials submitted. User: '${username}', Pass: '${password}'`
    });
    
    broadcast('NEW_LOG', log);
    broadcast('STATS_UPDATE', db.getStats());

    // Send mock failed auth response
    res.status(401).send('<h3>401 Unauthorized</h3><p>Invalid admin gateway credentials.</p>');
  });

  // Catch-all for directory scanning / fake files
  httpApp.all('*', (req, res) => {
    const ip = req.ip.replace('::ffff:', '');
    
    // Non-existent route is scanned
    const log = db.addLog({
      ip,
      service: 'HTTP',
      port: SERVICES.HTTP.port,
      type: 'Vulnerability Scanning',
      severity: 'Low',
      payload: `Requested non-existent endpoint: ${req.method} ${req.url}`
    });
    
    broadcast('NEW_LOG', log);
    broadcast('STATS_UPDATE', db.getStats());

    res.status(404).send('<h3>404 Not Found</h3><p>The requested path does not exist on this server.</p>');
  });

  SERVICES.HTTP.instance = httpApp.listen(SERVICES.HTTP.port, () => {
    console.log(`[HIDS] HTTP Honeypot active on port ${SERVICES.HTTP.port}`);
  });
}

// ----------------------------------------------------
// 2. SSH HONEYPOT SIMULATOR (Port 2222)
// ----------------------------------------------------
function startSSHHoneypot() {
  SERVICES.SSH.instance = net.createServer((socket) => {
    const ip = socket.remoteAddress.replace('::ffff:', '');
    let state = 'BANNER';
    let username = '';
    let password = '';

    // Log the connection attempt
    const initLog = db.addLog({
      ip,
      service: 'SSH',
      port: SERVICES.SSH.port,
      type: 'Port Probe',
      severity: 'Low',
      payload: `SSH TCP connection established from IP ${ip}`
    });
    broadcast('NEW_LOG', initLog);
    broadcast('STATS_UPDATE', db.getStats());

    // Send mock banner
    socket.write('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n');

    socket.on('data', (data) => {
      const dataStr = data.toString().trim();

      // If client sends standard SSH client banner first, wait
      if (state === 'BANNER') {
        if (dataStr.startsWith('SSH-')) {
          // It's a real SSH client. We print authentication prompts to guide simple netcat/interactive exploits.
          // Note: Full SSH handshakes require cryptographic negotiations which standard library 'net' won't do.
          // However, many brute force script scanners or standard telnet/netcat probes will send raw strings or expect interactive shells.
          state = 'USER';
          socket.write('login as: ');
          return;
        } else {
          // If they didn't send SSH header, assume simple netcat or telnet scanner
          state = 'USER';
          socket.write('login as: ');
          return;
        }
      }

      if (state === 'USER') {
        username = dataStr;
        state = 'PASS';
        socket.write('password: ');
        return;
      }

      if (state === 'PASS') {
        password = dataStr;
        
        // Analyze failed login
        const analysis = detection.analyzeSSHAttempt(ip, username, password);
        const log = db.addLog({
          ip,
          service: 'SSH',
          port: SERVICES.SSH.port,
          type: analysis.type,
          severity: analysis.severity,
          payload: analysis.payload
        });
        
        broadcast('NEW_LOG', log);
        broadcast('STATS_UPDATE', db.getStats());

        // Allow access to fake shell to lure them further!
        state = 'SHELL';
        socket.write('\r\nWelcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-46-generic x86_64)\r\n');
        socket.write('Last login: Thu Aug 14 10:14:22 2026 from 192.168.1.105\r\n');
        socket.write('root@server-node-1:~# ');
        return;
      }

      if (state === 'SHELL') {
        if (dataStr.toLowerCase() === 'exit' || dataStr.toLowerCase() === 'logout') {
          socket.write('logout\r\nConnection to localhost closed.\r\n');
          socket.end();
          return;
        }

        // Log interactive command execution
        const log = db.addLog({
          ip,
          service: 'SSH',
          port: SERVICES.SSH.port,
          type: 'SSH Command Executed',
          severity: 'Critical',
          payload: `Attacker executed shell command: '${dataStr}'`
        });
        
        broadcast('NEW_LOG', log);
        broadcast('STATS_UPDATE', db.getStats());

        // Simple interactive mock responses
        if (dataStr === 'ls') {
          socket.write('config.json  db.sql  deployment.sh  secrets.txt  web/\r\nroot@server-node-1:~# ');
        } else if (dataStr === 'whoami') {
          socket.write('root\r\nroot@server-node-1:~# ');
        } else if (dataStr === 'id') {
          socket.write('uid=0(root) gid=0(root) groups=0(root)\r\nroot@server-node-1:~# ');
        } else if (dataStr.startsWith('cat ')) {
          const file = dataStr.replace('cat ', '').trim();
          if (file === 'secrets.txt') {
            socket.write('FLAG{h0n3yp0t_c4ptur3d_y0u}\r\nAPI_KEY=sk_live_51M7z2A2Fh90A2Ld...\r\nroot@server-node-1:~# ');
          } else {
            socket.write(`cat: ${file}: Permission denied\r\nroot@server-node-1:~# `);
          }
        } else if (dataStr === 'help' || dataStr === '?') {
          socket.write('bash: help: no help topics match this query.\r\nroot@server-node-1:~# ');
        } else {
          socket.write(`bash: ${dataStr.split(' ')[0]}: command not found\r\nroot@server-node-1:~# `);
        }
      }
    });

    socket.on('error', (err) => {
      // Ignore socket resets
    });
  });

  SERVICES.SSH.instance.listen(SERVICES.SSH.port, () => {
    console.log(`[HIDS] SSH Honeypot active on port ${SERVICES.SSH.port}`);
  });
}

// ----------------------------------------------------
// 3. FTP HONEYPOT SIMULATOR (Port 2121)
// ----------------------------------------------------
function startFTPHoneypot() {
  SERVICES.FTP.instance = net.createServer((socket) => {
    const ip = socket.remoteAddress.replace('::ffff:', '');
    let authenticated = false;
    let username = '';

    socket.write('220-Welcome to FTP Server\r\n220 Service Ready.\r\n');

    socket.on('data', (data) => {
      const dataStr = data.toString().trim();
      const firstSpaceIdx = dataStr.indexOf(' ');
      const cmd = firstSpaceIdx > -1 ? dataStr.substring(0, firstSpaceIdx) : dataStr;
      const args = firstSpaceIdx > -1 ? dataStr.substring(firstSpaceIdx + 1) : '';

      const analysis = detection.analyzeFTPAttempt(ip, cmd, args);
      if (analysis) {
        const log = db.addLog({
          ip,
          service: 'FTP',
          port: SERVICES.FTP.port,
          type: analysis.type,
          severity: analysis.severity,
          payload: analysis.payload
        });
        broadcast('NEW_LOG', log);
        broadcast('STATS_UPDATE', db.getStats());
      }

      const upperCmd = cmd.toUpperCase();
      switch (upperCmd) {
        case 'USER':
          username = args;
          socket.write('331 User name okay, need password.\r\n');
          break;
        case 'PASS':
          authenticated = true;
          socket.write('230 User logged in, proceed.\r\n');
          break;
        case 'SYST':
          socket.write('215 UNIX Type: L8\r\n');
          break;
        case 'PWD':
          socket.write('257 "/" is current directory.\r\n');
          break;
        case 'CWD':
          socket.write('550 Access denied: sandbox folder locked.\r\n');
          break;
        case 'PORT':
          socket.write('200 PORT command successful.\r\n');
          break;
        case 'LIST':
          socket.write('150 Opening ASCII mode data connection for file list.\r\n');
          socket.write('226 Transfer complete. 0 files in root.\r\n');
          break;
        case 'QUIT':
          socket.write('221 Service closing control connection. Goodbye.\r\n');
          socket.end();
          break;
        default:
          socket.write('502 Command not implemented.\r\n');
          break;
      }
    });

    socket.on('error', (err) => {
      // Ignore socket resets
    });
  });

  SERVICES.FTP.instance.listen(SERVICES.FTP.port, () => {
    console.log(`[HIDS] FTP Honeypot active on port ${SERVICES.FTP.port}`);
  });
}

// ----------------------------------------------------
// Core Controls & APIs
// ----------------------------------------------------
app.get('/api/logs', (req, res) => {
  res.json(db.getLogs());
});

app.get('/api/stats', (req, res) => {
  res.json(db.getStats());
});

app.post('/api/clear', (req, res) => {
  db.clearLogs();
  broadcast('CLEAR_LOGS', []);
  broadcast('STATS_UPDATE', db.getStats());
  res.json({ success: true });
});

// Toggle service dynamically
app.post('/api/toggle-service', (req, res) => {
  const { service } = req.body;
  if (!SERVICES[service]) {
    return res.status(400).json({ error: 'Invalid service' });
  }

  const s = SERVICES[service];
  if (s.active) {
    // Stop service
    if (s.instance) {
      s.instance.close();
      s.instance = null;
    }
    s.active = false;
    console.log(`[HIDS] Stopped ${service} Honeypot`);
  } else {
    // Start service
    s.active = true;
    if (service === 'HTTP') startHTTPHoneypot();
    if (service === 'SSH') startSSHHoneypot();
    if (service === 'FTP') startFTPHoneypot();
  }

  broadcast('STATUS_UPDATE', {
    HTTP: SERVICES.HTTP.active,
    SSH: SERVICES.SSH.active,
    FTP: SERVICES.FTP.active
  });

  res.json({ success: true, active: s.active });
});

app.get('/api/status', (req, res) => {
  res.json({
    HTTP: SERVICES.HTTP.active,
    SSH: SERVICES.SSH.active,
    FTP: SERVICES.FTP.active
  });
});

// Real-time connections count tracker
let activeSessions = 0;
wss.on('connection', (ws) => {
  activeSessions++;
  broadcast('SESSIONS_COUNT', activeSessions);

  // Send initial data to client
  ws.send(JSON.stringify({ type: 'STATUS_UPDATE', data: {
    HTTP: SERVICES.HTTP.active,
    SSH: SERVICES.SSH.active,
    FTP: SERVICES.FTP.active
  }}));
  ws.send(JSON.stringify({ type: 'SESSIONS_COUNT', data: activeSessions }));

  ws.on('close', () => {
    activeSessions--;
    broadcast('SESSIONS_COUNT', activeSessions);
  });
});

// Start everything
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`[HIDS] Dashboard Web / WS Server on http://localhost:${PORT}`);
  console.log(`====================================================`);
  
  if (SERVICES.HTTP.active) startHTTPHoneypot();
  if (SERVICES.SSH.active) startSSHHoneypot();
  if (SERVICES.FTP.active) startFTPHoneypot();
});
