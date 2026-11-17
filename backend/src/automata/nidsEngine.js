const { sqliDFA, xssDFA, pathTraversalDFA } = require('./definitions');

/**
 * Predefined Regular Expression Signatures
 */
const REGEX_RULES = [
  {
    id: 'REG-SQLI-01',
    ruleName: 'SQL Injection - UNION / SELECT / DROP Detection',
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    regex: /((\%27)|(\'))\s*(union|select|insert|update|delete|drop)\b|union\s+select/i,
    description: 'Detects SQL data exfiltration or table tampering keywords',
    mitigation: 'Use parameterized queries / prepared statements',
  },
  {
    id: 'REG-SQLI-02',
    ruleName: 'SQL Injection - Boolean Tautology (OR 1=1)',
    attackType: 'SQL Injection',
    severity: 'CRITICAL',
    regex: /((\%27)|(\'))\s*or\s+[\'\"0-9a-zA-Z]+\s*=\s*[\'\"0-9a-zA-Z]+/i,
    description: 'Detects auth bypass logic tampering',
    mitigation: 'Implement strict input validation and ORM queries',
  },
  {
    id: 'REG-XSS-01',
    ruleName: 'Cross-Site Scripting - Script Tag & Event Handler',
    attackType: 'Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    regex: /<script\b[^>]*>(.*?)<\/script>|onerror\s*=|onload\s*=|javascript:/i,
    description: 'Detects malicious JavaScript execution injection in parameters',
    mitigation: 'Sanitize HTML output using DOMPurify and set Content-Security-Policy',
  },
  {
    id: 'REG-LFI-01',
    ruleName: 'Path Traversal - Sensitive File Access',
    attackType: 'Path Traversal',
    severity: 'HIGH',
    regex: /(\.\.[\/\\])+|(etc\/passwd|windows\/system32|boot\.ini)/i,
    description: 'Detects attempts to break out of webroot and read operating system files',
    mitigation: 'Disallow dot-dot-slash sequence in path parameters',
  },
  {
    id: 'REG-CMD-01',
    ruleName: 'Command Injection - Shell Metacharacters',
    attackType: 'Command Injection',
    severity: 'CRITICAL',
    regex: /(;\s*(rm|cat|ls|whoami|curl|wget|nc|powershell|cmd\.exe))|(\|\s*(bash|sh))/i,
    description: 'Detects chained shell command execution attempts',
    mitigation: 'Never pass user-supplied input to child_process or system shell',
  },
  {
    id: 'REG-PORT-01',
    ruleName: 'Suspicious Port Probe (Telnet / Metasploit / RDP)',
    attackType: 'Port Scan / Probe',
    severity: 'MEDIUM',
    check: (port) => [23, 1433, 3389, 4444, 5555, 6667].includes(Number(port)),
    description: 'Detects connection attempts to vulnerable or remote administration ports',
    mitigation: 'Enforce campus firewall ACL to drop inbound traffic on non-whitelisted ports',
  },
];

/**
 * Hybrid Network Intrusion Detection Engine
 * Integrates DFA State Automata + Regular Expression Signatures
 */
class NIDSEngine {
  constructor() {
    this.dfaList = [
      { dfa: sqliDFA, attackType: 'SQL Injection', severity: 'CRITICAL', ruleName: "DFA: SQL Injection (' OR 1=1)" },
      { dfa: xssDFA, attackType: 'Cross-Site Scripting (XSS)', severity: 'HIGH', ruleName: 'DFA: XSS Injection (<script)' },
      { dfa: pathTraversalDFA, attackType: 'Path Traversal', severity: 'HIGH', ruleName: 'DFA: Directory Traversal (../..)' },
    ];
  }

  /**
   * Analyzes an incoming network packet
   */
  inspectPacket({ sourceIP, destinationIP, port, protocol, payload }) {
    const detectedAttacks = [];
    let threatScore = 0;

    // 1. Run Formal DFA Automata Scanning
    for (const item of this.dfaList) {
      const scanResult = item.dfa.scan(payload);
      if (scanResult.detected) {
        detectedAttacks.push({
          ruleId: item.dfa.id,
          ruleName: item.ruleName,
          attackType: item.attackType,
          severity: item.severity,
          matchedPattern: scanResult.matchedSubstring,
          matchedBy: 'DFA_AUTOMATON',
          automataTrace: scanResult.trace,
        });

        threatScore += item.severity === 'CRITICAL' ? 50 : 35;
      }
    }

    // 2. Run Regular Expression Rules
    for (const rule of REGEX_RULES) {
      if (rule.regex) {
        const match = payload.match(rule.regex);
        if (match) {
          // Avoid duplicate rule type if already matched identically
          const alreadyMatched = detectedAttacks.some(
            (a) => a.ruleName === rule.ruleName || a.matchedPattern === match[0]
          );

          if (!alreadyMatched) {
            detectedAttacks.push({
              ruleId: rule.id,
              ruleName: rule.ruleName,
              attackType: rule.attackType,
              severity: rule.severity,
              matchedPattern: match[0],
              matchedBy: 'REGEX_SIGNATURE',
              automataTrace: [],
            });

            threatScore += rule.severity === 'CRITICAL' ? 45 : 30;
          }
        }
      } else if (rule.check && rule.check(port)) {
        detectedAttacks.push({
          ruleId: rule.id,
          ruleName: rule.ruleName,
          attackType: rule.attackType,
          severity: rule.severity,
          matchedPattern: `Targeted Port ${port}`,
          matchedBy: 'REGEX_SIGNATURE',
          automataTrace: [],
        });
        threatScore += 25;
      }
    }

    // Determine final status & action
    let status = 'NORMAL';
    let actionTaken = 'FORWARDED';

    if (threatScore >= 40) {
      status = 'MALICIOUS';
      actionTaken = threatScore >= 70 ? 'BLOCKED' : 'DROPPED';
    } else if (threatScore > 0) {
      status = 'SUSPICIOUS';
      actionTaken = 'ALERTED';
    }

    return {
      status,
      threatScore: Math.min(threatScore, 100),
      detectedAttacks,
      actionTaken,
    };
  }
}

const nidsEngineInstance = new NIDSEngine();

module.exports = {
  nidsEngine: nidsEngineInstance,
  REGEX_RULES,
};
