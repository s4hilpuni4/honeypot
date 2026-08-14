// Rule-based Intrusion Detection Engine

// In-memory track for brute force attacks
const loginAttempts = {
  ssh: {}, // ip: { count, lastTime }
  ftp: {}  // ip: { count, lastTime }
};

const BRUTE_FORCE_THRESHOLD = 3;
const TIME_WINDOW_MS = 60 * 1000; // 1 minute

module.exports = {
  // 1. Analyze HTTP Intrusion
  analyzeHTTPRequest(method, url, headers, body) {
    const rawContent = decodeURIComponent(url + ' ' + (typeof body === 'string' ? body : JSON.stringify(body || '')));
    
    // Check for Remote Command Injection
    const rcePatterns = [
      /\b(rm\s+-rf|chmod\s+\+x|cat\s+\/etc|wget\s+|curl\s+|nc\s+|powershell\s+|cmd\.exe|bash\s+-i)/i,
      /;\s*(ping|id|whoami|uname|ls|cat)\b/i,
      /\$\(.*\)/
    ];
    for (const pattern of rcePatterns) {
      if (pattern.test(rawContent)) {
        return {
          detected: true,
          type: 'Remote Code Execution',
          severity: 'Critical',
          reason: `Detected command injection pattern: ${pattern.toString()}`
        };
      }
    }

    // Check for Directory Traversal
    const traversalPatterns = [
      /\.\.\//,
      /\.\.\\/,
      /etc\/passwd/i,
      /boot\.ini/i,
      /win\.ini/i
    ];
    for (const pattern of traversalPatterns) {
      if (pattern.test(rawContent)) {
        return {
          detected: true,
          type: 'Directory Traversal',
          severity: 'High',
          reason: 'Path traversal character sequence detected'
        };
      }
    }

    // Check for SQL Injection
    const sqliPatterns = [
      /\b(select|union|insert|update|delete|drop|alter|truncate|declare)\b.*\bfrom\b/i,
      /union\s+select/i,
      /['"]\s*or\s*['"]?\d+['"]?\s*=\s*['"]?\d+/i,
      /['"]\s*and\s*['"]?\d+['"]?\s*=\s*['"]?\d+/i,
      /--/,
      /admin' --/i,
      /admin' #/i
    ];
    for (const pattern of sqliPatterns) {
      if (pattern.test(rawContent)) {
        return {
          detected: true,
          type: 'SQL Injection',
          severity: 'High',
          reason: 'SQL query structure pattern detected'
        };
      }
    }

    // Check for Cross-Site Scripting (XSS)
    const xssPatterns = [
      /<script.*?>.*?<\/script>/gi,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /<img.*?src.*?onerror/gi
    ];
    for (const pattern of xssPatterns) {
      if (pattern.test(rawContent)) {
        return {
          detected: true,
          type: 'Cross-Site Scripting',
          severity: 'Medium',
          reason: 'HTML/JS execution payload injection detected'
        };
      }
    }

    // Check for standard web scans
    const scanPaths = [
      /wp-admin/i,
      /wp-login/i,
      /\.env/i,
      /\.git/i,
      /phpmyadmin/i,
      /config/i,
      /backup/i
    ];
    for (const pattern of scanPaths) {
      if (pattern.test(url)) {
        return {
          detected: true,
          type: 'Vulnerability Scanning',
          severity: 'Medium',
          reason: `Access attempt to sensitive deployment path: ${url}`
        };
      }
    }

    return { detected: false };
  },

  // 2. SSH Brute Force Detection
  analyzeSSHAttempt(ip, username, password) {
    const now = Date.now();
    const attempts = loginAttempts.ssh[ip] || { count: 0, lastTime: 0 };
    
    // Reset if outside window
    if (now - attempts.lastTime > TIME_WINDOW_MS) {
      attempts.count = 0;
    }
    
    attempts.count++;
    attempts.lastTime = now;
    loginAttempts.ssh[ip] = attempts;

    if (attempts.count >= BRUTE_FORCE_THRESHOLD) {
      return {
        detected: true,
        type: 'SSH Brute Force Attack',
        severity: 'High',
        payload: `Repeated failed logins. Last Attempt: User='${username}', Pass='${password}'. Attempt #${attempts.count}`
      };
    }

    return {
      detected: true,
      type: 'SSH Failed Auth',
      severity: 'Low',
      payload: `Failed SSH login. User='${username}', Pass='${password}'`
    };
  },

  // 3. FTP Login and command analysis
  analyzeFTPAttempt(ip, cmd, args) {
    const now = Date.now();
    const command = (cmd || '').toUpperCase();
    const argumentsStr = args || '';

    // Check directory traversal in FTP path
    if (/\.\.\//.test(argumentsStr) || /\.\.\\/.test(argumentsStr)) {
      return {
        detected: true,
        type: 'FTP Directory Traversal',
        severity: 'High',
        payload: `FTP command '${command} ${argumentsStr}' attempted directory traversal`
      };
    }

    // Trace failed logins
    if (command === 'PASS') {
      const attempts = loginAttempts.ftp[ip] || { count: 0, lastTime: 0 };
      
      if (now - attempts.lastTime > TIME_WINDOW_MS) {
        attempts.count = 0;
      }
      
      attempts.count++;
      attempts.lastTime = now;
      loginAttempts.ftp[ip] = attempts;

      if (attempts.count >= BRUTE_FORCE_THRESHOLD) {
        return {
          detected: true,
          type: 'FTP Brute Force Attack',
          severity: 'High',
          payload: `Multiple failed FTP logins. Attempt #${attempts.count}`
        };
      }

      return {
        detected: true,
        type: 'FTP Failed Auth',
        severity: 'Low',
        payload: `Failed FTP login. Pass='${argumentsStr}'`
      };
    }

    // Command injections or dangerous commands
    if (command === 'SITE' && /\b(chmod|chown|exec|system)\b/i.test(argumentsStr)) {
      return {
        detected: true,
        type: 'FTP Exploit Attempt',
        severity: 'Critical',
        payload: `Dangerous SITE instruction: '${command} ${argumentsStr}'`
      };
    }

    return null;
  }
};
