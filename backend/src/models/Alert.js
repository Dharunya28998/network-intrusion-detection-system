const mongoose = require('mongoose');

const AlertSchema = new mongoose.Schema(
  {
    ruleId: {
      type: String,
      required: true,
    },
    ruleName: {
      type: String,
      required: true,
    },
    attackType: {
      type: String,
      required: true,
      enum: [
        'SQL Injection',
        'Cross-Site Scripting (XSS)',
        'Path Traversal',
        'Command Injection',
        'Port Scan / Probe',
        'Malformed Packet',
      ],
    },
    severity: {
      type: String,
      required: true,
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      default: 'MEDIUM',
    },
    sourceIP: {
      type: String,
      required: true,
    },
    destinationIP: {
      type: String,
      required: true,
    },
    port: {
      type: Number,
      required: true,
    },
    protocol: {
      type: String,
      required: true,
    },
    payloadSnippet: {
      type: String,
      required: true,
    },
    fullPayload: {
      type: String,
    },
    matchedPattern: {
      type: String,
      required: true,
    },
    detectionMechanism: {
      type: String,
      enum: ['DFA_AUTOMATON', 'REGEX_SIGNATURE', 'HYBRID'],
      default: 'DFA_AUTOMATON',
    },
    automataTrace: [
      {
        from: String,
        input: String,
        to: String,
      },
    ],
    status: {
      type: String,
      enum: ['ACTIVE', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
      default: 'ACTIVE',
    },
    recommendedAction: {
      type: String,
      default: 'Block IP and inspect firewall ACLs',
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Alert', AlertSchema);
