const express = require('express');
const router = express.Router();
const { nidsEngine } = require('../automata/nidsEngine');
const { ipv4ValidatorDFA } = require('../automata/definitions');
const {
  saveTrafficLog,
  saveAlert,
  getTrafficLogs,
  clearAllData,
  getStats,
} = require('../store/dataStore');

// IP Regex validation
const IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

/**
 * Helper to validate form input on server-side
 */
const validatePacketInput = (body) => {
  const errors = {};
  const { sourceIP, destinationIP, port, protocol, payload } = body;

  // Source IP validation via DFA & regex
  if (!sourceIP || !sourceIP.trim()) {
    errors.sourceIP = 'Source IP is required';
  } else {
    const dfaCheck = ipv4ValidatorDFA.validate(sourceIP.trim());
    if (!dfaCheck.accepted || !IP_REGEX.test(sourceIP.trim())) {
      errors.sourceIP = 'Invalid IPv4 address format (e.g., 192.168.1.10)';
    }
  }

  // Destination IP validation via DFA & regex
  if (!destinationIP || !destinationIP.trim()) {
    errors.destinationIP = 'Destination IP is required';
  } else {
    const dfaCheck = ipv4ValidatorDFA.validate(destinationIP.trim());
    if (!dfaCheck.accepted || !IP_REGEX.test(destinationIP.trim())) {
      errors.destinationIP = 'Invalid IPv4 address format (e.g., 10.0.0.1)';
    }
  }

  // Port validation
  const portNum = Number(port);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    errors.port = 'Port must be a valid integer between 1 and 65535';
  }

  // Protocol validation
  const validProtocols = ['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'SSH', 'FTP', 'ICMP'];
  if (!protocol || !validProtocols.includes(protocol.toUpperCase())) {
    errors.protocol = `Protocol must be one of: ${validProtocols.join(', ')}`;
  }

  // Payload validation
  if (!payload || typeof payload !== 'string' || payload.trim().length === 0) {
    errors.payload = 'Packet payload is required and cannot be empty';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};

/**
 * POST /api/traffic/process
 * Inspect and process an incoming network packet
 */
router.post('/process', async (req, res) => {
  try {
    const validation = validatePacketInput(req.body);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        message: 'Form validation failed',
        errors: validation.errors,
      });
    }

    const { sourceIP, destinationIP, port, protocol, payload } = req.body;

    // Run packet through DFA Automata and Regex engine
    const analysis = nidsEngine.inspectPacket({
      sourceIP: sourceIP.trim(),
      destinationIP: destinationIP.trim(),
      port: Number(port),
      protocol: protocol.toUpperCase(),
      payload: payload.trim(),
    });

    // Save Traffic Log
    const logData = {
      sourceIP: sourceIP.trim(),
      destinationIP: destinationIP.trim(),
      port: Number(port),
      protocol: protocol.toUpperCase(),
      payload: payload.trim(),
      status: analysis.status,
      threatScore: analysis.threatScore,
      detectedAttacks: analysis.detectedAttacks,
      actionTaken: analysis.actionTaken,
    };
    const savedLog = await saveTrafficLog(logData);

    // If attacks detected, generate individual alerts
    const createdAlerts = [];
    for (const attack of analysis.detectedAttacks) {
      const alertData = {
        ruleId: attack.ruleId,
        ruleName: attack.ruleName,
        attackType: attack.attackType,
        severity: attack.severity,
        sourceIP: sourceIP.trim(),
        destinationIP: destinationIP.trim(),
        port: Number(port),
        protocol: protocol.toUpperCase(),
        payloadSnippet:
          attack.matchedPattern || payload.trim().substring(0, 60),
        fullPayload: payload.trim(),
        matchedPattern: attack.matchedPattern,
        detectionMechanism: attack.matchedBy,
        automataTrace: attack.automataTrace || [],
        status: 'ACTIVE',
        recommendedAction:
          attack.severity === 'CRITICAL'
            ? 'Immediately terminate TCP session and block source IP in campus firewall.'
            : 'Log security event, inspect access logs, and rate limit subnet.',
      };
      const savedAlert = await saveAlert(alertData);
      createdAlerts.push(savedAlert);
    }

    return res.status(201).json({
      success: true,
      message:
        analysis.status === 'NORMAL'
          ? 'Packet verified and forwarded (Clean traffic)'
          : `Alert! ${analysis.status} network activity detected`,
      log: savedLog,
      analysis,
      alerts: createdAlerts,
    });
  } catch (error) {
    console.error('Error processing packet:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error processing network packet',
      error: error.message,
    });
  }
});

/**
 * GET /api/traffic
 * Fetch recent packet traffic logs
 */
router.get('/', async (req, res) => {
  try {
    const limit = req.query.limit || 100;
    const logs = await getTrafficLogs(limit);
    return res.json({ success: true, count: logs.length, logs });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/traffic/stats
 * Overview dashboard metrics
 */
router.get('/stats', async (req, res) => {
  try {
    const stats = await getStats();
    return res.json({ success: true, stats });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/traffic/simulate-preset
 * Inject realistic presets (clean, SQLi, XSS, Path Traversal, Port Scan)
 */
router.post('/simulate-preset', async (req, res) => {
  const { type } = req.body;
  const presets = {
    clean: {
      sourceIP: '192.168.10.45',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /student/portal/grades?semester=5 HTTP/1.1\r\nHost: college.edu',
    },
    sqli: {
      sourceIP: '10.20.4.112',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: "POST /api/login HTTP/1.1\r\nusername=admin' OR 1=1--&password=xyz",
    },
    sqli_union: {
      sourceIP: '10.20.4.115',
      destinationIP: '172.16.0.5',
      port: 8080,
      protocol: 'HTTP',
      payload: "GET /search?query=1' UNION SELECT username, password FROM users-- HTTP/1.1",
    },
    xss: {
      sourceIP: '172.28.12.89',
      destinationIP: '172.16.0.5',
      port: 443,
      protocol: 'HTTPS',
      payload: 'POST /feedback HTTP/1.1\r\ncomment=<script>alert("College XSS Exploit")</script>',
    },
    traversal: {
      sourceIP: '198.51.100.22',
      destinationIP: '172.16.0.10',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /download?file=../../etc/passwd HTTP/1.1\r\nHost: portal.college.edu',
    },
    command_injection: {
      sourceIP: '203.0.113.88',
      destinationIP: '172.16.0.12',
      port: 80,
      protocol: 'HTTP',
      payload: 'POST /system/diagnostics HTTP/1.1\r\nhost=127.0.0.1; rm -rf /var/log/traffic',
    },
    port_probe: {
      sourceIP: '198.51.100.99',
      destinationIP: '172.16.0.2',
      port: 23,
      protocol: 'TCP',
      payload: 'SYN Packet probe: Telnet connection attempt on unencrypted terminal port',
    },
  };

  const selected = presets[type] || presets.clean;
  req.body = selected;
  return router.handle(req, res);
});

/**
 * DELETE /api/traffic
 * Reset traffic data
 */
router.delete('/', async (req, res) => {
  try {
    const result = await clearAllData();
    return res.json({ success: true, ...result });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
