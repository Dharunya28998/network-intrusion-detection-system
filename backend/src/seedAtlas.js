const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const TrafficLog = require('./models/TrafficLog');
const Alert = require('./models/Alert');
const SignatureRule = require('./models/SignatureRule');
const { nidsEngine, REGEX_RULES } = require('./automata/nidsEngine');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://dharunya28:dharudhanu@cluster0.kage7ax.mongodb.net/college_nids?retryWrites=true&w=majority';

async function seed() {
  console.log('Connecting to MongoDB Atlas at:', MONGO_URI.replace(/:([^@]+)@/, ':****@'));
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
    console.log('MongoDB Atlas Connected Successfully!');

    // Clean existing
    await TrafficLog.deleteMany({});
    await Alert.deleteMany({});
    await SignatureRule.deleteMany({});
    console.log('Cleaned old records.');

    // Seed Rules
    for (const rule of REGEX_RULES) {
      await SignatureRule.create({
        ruleId: rule.id,
        name: rule.ruleName,
        category: rule.attackType,
        severity: rule.severity,
        regexPattern: rule.regex ? rule.regex.toString() : 'PORT_CHECK',
        description: rule.description,
        mitigation: rule.mitigation,
      });
    }
    console.log('Rules seeded successfully.');

    // Seed Sample Traffic & Alerts
    const samplePackets = [
      {
        sourceIP: '192.168.1.100',
        destinationIP: '10.0.0.1',
        port: 80,
        protocol: 'HTTP',
        payload: 'GET /student/portal/grades?sem=5 HTTP/1.1\r\nHost: college.edu',
      },
      {
        sourceIP: '10.20.1.14',
        destinationIP: '172.16.0.5',
        port: 80,
        protocol: 'HTTP',
        payload: "POST /login HTTP/1.1\r\nusername=admin' OR 1=1--&password=xyz",
      },
      {
        sourceIP: '172.28.4.11',
        destinationIP: '172.16.0.5',
        port: 443,
        protocol: 'HTTPS',
        payload: 'POST /feedback HTTP/1.1\r\ncomment=<script>alert("XSS")</script>',
      },
      {
        sourceIP: '198.51.100.3',
        destinationIP: '172.16.0.10',
        port: 80,
        protocol: 'HTTP',
        payload: 'GET /download?doc=../../etc/passwd HTTP/1.1',
      },
      {
        sourceIP: '203.0.113.88',
        destinationIP: '172.16.0.12',
        port: 8080,
        protocol: 'HTTP',
        payload: 'POST /diagnostics HTTP/1.1\r\nhost=127.0.0.1; whoami; cat /etc/shadow',
      },
      {
        sourceIP: '192.168.1.14',
        destinationIP: '10.0.0.2',
        port: 23,
        protocol: 'TCP',
        payload: 'Telnet administrative port connection attempt',
      },
    ];

    for (const pkt of samplePackets) {
      const analysis = nidsEngine.inspectPacket(pkt);
      const log = await TrafficLog.create({
        ...pkt,
        status: analysis.status,
        threatScore: analysis.threatScore,
        detectedAttacks: analysis.detectedAttacks,
        actionTaken: analysis.actionTaken,
      });

      for (const attack of analysis.detectedAttacks) {
        await Alert.create({
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
          recommendedAction: attack.severity === 'CRITICAL'
            ? 'Block IP on core switch and terminate session.'
            : 'Flag IP for deep inspection and rate limit subnet.',
        });
      }
    }

    console.log('All sample traffic and alerts populated in MongoDB Atlas!');
    const logCount = await TrafficLog.countDocuments();
    const alertCount = await Alert.countDocuments();
    console.log(`Database 'college_nids' now has ${logCount} Traffic Logs and ${alertCount} Security Alerts!`);
    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('Atlas connection error:', err.message);
    process.exit(1);
  }
}

seed();
