const mongoose = require('mongoose');

const TrafficLogSchema = new mongoose.Schema(
  {
    sourceIP: {
      type: String,
      required: [true, 'Source IP is required'],
      trim: true,
    },
    destinationIP: {
      type: String,
      required: [true, 'Destination IP is required'],
      trim: true,
    },
    port: {
      type: Number,
      required: [true, 'Port is required'],
      min: 1,
      max: 65535,
    },
    protocol: {
      type: String,
      required: true,
      enum: ['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'SSH', 'FTP', 'ICMP'],
      default: 'HTTP',
    },
    payload: {
      type: String,
      required: [true, 'Packet payload is required'],
    },
    status: {
      type: String,
      enum: ['NORMAL', 'SUSPICIOUS', 'MALICIOUS'],
      default: 'NORMAL',
    },
    threatScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    detectedAttacks: [
      {
        ruleId: String,
        ruleName: String,
        attackType: String,
        severity: String,
        matchedPattern: String,
        matchedBy: {
          type: String,
          enum: ['DFA_AUTOMATON', 'REGEX_SIGNATURE', 'HYBRID'],
        },
        automataTrace: [
          {
            from: String,
            input: String,
            to: String,
          },
        ],
      },
    ],
    actionTaken: {
      type: String,
      enum: ['FORWARDED', 'ALERTED', 'DROPPED', 'BLOCKED'],
      default: 'FORWARDED',
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('TrafficLog', TrafficLogSchema);
