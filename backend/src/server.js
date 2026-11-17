const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const dotenv = require('dotenv');
const { connectDB, getDBStatus } = require('./config/db');
const trafficRoutes = require('./routes/trafficRoutes');
const alertRoutes = require('./routes/alertRoutes');
const automataRoutes = require('./routes/automataRoutes');
const { saveTrafficLog, saveAlert } = require('./store/dataStore');
const { nidsEngine } = require('./automata/nidsEngine');

const path = require('path');
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Routes
app.use('/api/traffic', trafficRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/automata', automataRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'UP',
    system: 'College Network Intrusion Detection System (NIDS)',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    database: getDBStatus(),
    automataEngine: {
      status: 'ACTIVE',
      supportedDFA: ['SQL Injection', 'Cross-Site Scripting (XSS)', 'Path Traversal', 'IPv4 Form Validator'],
    },
  });
});

// Serve compiled React frontend in production
const clientBuildPath = path.resolve(__dirname, '../../frontend/dist');
const fs = require('fs');
if (fs.existsSync(clientBuildPath)) {
  app.use(express.static(clientBuildPath));
}

// 404 Handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ success: false, message: 'API Route Not Found' });
});

// Client SPA fallback
app.get('*', (req, res) => {
  const indexFile = path.join(clientBuildPath, 'index.html');
  if (fs.existsSync(indexFile)) {
    res.sendFile(indexFile);
  } else {
    res.status(200).send('College NIDS Backend is running. Run "npm run build:frontend" to serve the dashboard.');
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[Internal Error]', err);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error',
    error: err.message,
  });
});

// Initial Seed Data to populate dashboard upon launch
const seedInitialData = async () => {
  const initialPackets = [
    {
      sourceIP: '192.168.1.105',
      destinationIP: '10.0.0.1',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /index.html HTTP/1.1\r\nHost: intranet.college.edu',
    },
    {
      sourceIP: '10.0.4.15',
      destinationIP: '172.16.0.2',
      port: 80,
      protocol: 'HTTP',
      payload: "POST /login HTTP/1.1\r\nusername=' OR 1=1&password=xyz",
    },
    {
      sourceIP: '172.16.5.20',
      destinationIP: '10.0.0.1',
      port: 443,
      protocol: 'HTTPS',
      payload: 'GET /library/catalog?category=CS&page=2 HTTP/1.1',
    },
    {
      sourceIP: '198.51.100.42',
      destinationIP: '10.0.0.5',
      port: 8080,
      protocol: 'HTTP',
      payload: 'GET /search?q=<script>alert("XSS")</script> HTTP/1.1',
    },
    {
      sourceIP: '203.0.113.19',
      destinationIP: '10.0.0.1',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /view?doc=../../etc/passwd HTTP/1.1',
    },
    {
      sourceIP: '192.168.1.14',
      destinationIP: '10.0.0.2',
      port: 23,
      protocol: 'TCP',
      payload: 'Telnet administrative handshake probe',
    },
  ];

  for (const pkt of initialPackets) {
    const analysis = nidsEngine.inspectPacket(pkt);
    const logData = {
      ...pkt,
      status: analysis.status,
      threatScore: analysis.threatScore,
      detectedAttacks: analysis.detectedAttacks,
      actionTaken: analysis.actionTaken,
    };
    await saveTrafficLog(logData);

    for (const attack of analysis.detectedAttacks) {
      await saveAlert({
        ruleId: attack.ruleId,
        ruleName: attack.ruleName,
        attackType: attack.attackType,
        severity: attack.severity,
        sourceIP: pkt.sourceIP,
        destinationIP: pkt.destinationIP,
        port: pkt.port,
        protocol: pkt.protocol,
        payloadSnippet: attack.matchedPattern || pkt.payload.substring(0, 50),
        fullPayload: pkt.payload,
        matchedPattern: attack.matchedPattern,
        detectionMechanism: attack.matchedBy,
        automataTrace: attack.automataTrace || [],
        status: 'ACTIVE',
        recommendedAction:
          attack.severity === 'CRITICAL'
            ? 'Block IP on core switch and terminate session.'
            : 'Flag IP for deep packet inspection and alert security admin.',
      });
    }
  }
  console.log('[Seed] Initial network packets and alerts loaded.');
};

// Start Server
const startServer = async () => {
  await connectDB();
  await seedInitialData();

  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(` college NIDS Server running on http://localhost:${PORT}`);
    console.log(` Health check: http://localhost:${PORT}/api/health`);
    console.log(` Automata Specs: http://localhost:${PORT}/api/automata/specs`);
    console.log(`====================================================`);
  });
};

startServer();
