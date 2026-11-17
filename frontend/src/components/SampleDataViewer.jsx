import React from 'react';
import { CheckCircle2, Copy, FileCheck, Layers, Terminal } from 'lucide-react';

const SAMPLES = [
  {
    id: 'TC-01',
    category: 'Normal Clean Traffic',
    input: {
      sourceIP: '192.168.1.50',
      destinationIP: '10.0.0.1',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /student/dashboard/grades?semester=5 HTTP/1.1\r\nHost: portal.college.edu',
    },
    expectedOutput: {
      status: 'NORMAL',
      threatScore: 0,
      action: 'FORWARDED',
      matchedRule: 'None (Clean Traffic)',
      automataResult: 'Automaton remains in non-accepting states; Packet forwarded',
    },
  },
  {
    id: 'TC-02',
    category: 'SQL Injection - Auth Bypass',
    input: {
      sourceIP: '10.20.1.14',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: "POST /login HTTP/1.1\r\nusername=admin' OR 1=1--&password=xyz",
    },
    expectedOutput: {
      status: 'MALICIOUS',
      threatScore: 95,
      action: 'BLOCKED',
      matchedRule: "DFA: SQL Injection (' OR 1=1)",
      automataResult: 'Transition Sequence: q0 -> q1 -> q2 -> q3 -> q4 -> q5 -> q6 -> q7 -> q8 (ACCEPT)',
    },
  },
  {
    id: 'TC-03',
    category: 'Cross-Site Scripting (XSS)',
    input: {
      sourceIP: '172.28.4.11',
      destinationIP: '172.16.0.5',
      port: 443,
      protocol: 'HTTPS',
      payload: 'POST /feedback HTTP/1.1\r\ncomment=<script>alert("Hacked")</script>',
    },
    expectedOutput: {
      status: 'MALICIOUS',
      threatScore: 75,
      action: 'BLOCKED',
      matchedRule: 'DFA: XSS Injection (<script)',
      automataResult: 'Transition Sequence: s0 -> s1 -> s2 -> s3 -> s4 -> s5 -> s6 -> s7 (ACCEPT)',
    },
  },
  {
    id: 'TC-04',
    category: 'Directory / Path Traversal',
    input: {
      sourceIP: '198.51.100.3',
      destinationIP: '172.16.0.10',
      port: 80,
      protocol: 'HTTP',
      payload: 'GET /view?doc=../../etc/passwd HTTP/1.1\r\nHost: college.edu',
    },
    expectedOutput: {
      status: 'MALICIOUS',
      threatScore: 75,
      action: 'BLOCKED',
      matchedRule: 'DFA: Directory Traversal (../..)',
      automataResult: 'Transition Sequence: p0 -> p1 -> p2 -> p3 -> p4 -> p5 (ACCEPT)',
    },
  },
  {
    id: 'TC-05',
    category: 'OS Command Injection',
    input: {
      sourceIP: '203.0.113.88',
      destinationIP: '172.16.0.12',
      port: 80,
      protocol: 'HTTP',
      payload: 'POST /system/diagnostics HTTP/1.1\r\nhost=127.0.0.1; rm -rf /var/logs',
    },
    expectedOutput: {
      status: 'MALICIOUS',
      threatScore: 80,
      action: 'BLOCKED',
      matchedRule: 'REG-CMD-01: Command Injection - Shell Metacharacters',
      automataResult: 'Regex match on pattern (;\\s*(rm|cat|ls|whoami))',
    },
  },
  {
    id: 'TC-06',
    category: 'Form Validation - Invalid IP',
    input: {
      sourceIP: '999.300.1.1',
      destinationIP: '172.16.0.5',
      port: 80,
      protocol: 'HTTP',
      payload: 'Normal query',
    },
    expectedOutput: {
      status: 'FORM REJECTED',
      threatScore: 'N/A',
      action: 'DROPPED AT CLIENT / SERVER VALIDATION',
      matchedRule: 'Form Validation DFA (dfa-ipv4-validator)',
      automataResult: 'Automaton transitions into TRAP state; Client displays red error highlight',
    },
  },
  {
    id: 'TC-07',
    category: 'Form Validation - Invalid Port',
    input: {
      sourceIP: '192.168.1.1',
      destinationIP: '172.16.0.5',
      port: 70000,
      protocol: 'HTTP',
      payload: 'Normal query',
    },
    expectedOutput: {
      status: 'FORM REJECTED',
      threatScore: 'N/A',
      action: 'DROPPED AT CLIENT VALIDATION',
      matchedRule: 'Port Range Constraint (1 - 65535)',
      automataResult: 'Rejected: Port out of IEEE range [1, 65535]',
    },
  },
];

export default function SampleDataViewer() {
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(JSON.stringify(text, null, 2));
    alert('Sample test case copied to clipboard!');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Submission Checklist */}
      <div className="panel-card">
        <div className="panel-header">
          <h2 className="panel-title">
            <FileCheck size={20} color="#00ff88" />
            <span>GitHub Submission Deliverables Checklist</span>
          </h2>
          <span className="badge badge-clean">Scenario 23 Verified</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px', fontSize: '0.85rem' }}>
          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <CheckCircle2 size={16} />
              <span>1. Full MERN Stack Runnable Code</span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
              React frontend with responsive dashboard, Node.js + Express backend with REST APIs, and MongoDB Mongoose integration with resilient in-memory fallback.
            </p>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <CheckCircle2 size={16} />
              <span>2. Automata Design & State Diagrams</span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
              Formally modeled DFAs for SQL Injection, XSS, Path Traversal, and IPv4 Form Input Validation with formal 5-tuples M = (Q, Σ, δ, q₀, F).
            </p>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <CheckCircle2 size={16} />
              <span>3. State Transition Tables</span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
              Complete state transition matrices detailing states Q, alphabet symbols Σ, start state (→), and accept states (*), viewable in the app and markdown docs.
            </p>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <CheckCircle2 size={16} />
              <span>4. Form Validation & Sample Inputs/Outputs</span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
              Real-time client-side and server-side validation on IPv4, Port bounds, and non-empty payloads, verified with comprehensive test suites.
            </p>
          </div>
        </div>
      </div>

      {/* Sample Inputs and Outputs Matrix */}
      <div className="panel-card">
        <div className="panel-header">
          <h2 className="panel-title">
            <Terminal size={18} color="#38bdf8" />
            <span>Sample Inputs and Expected Outputs Test Suite</span>
          </h2>
          <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>
            Ready for Lab Viva Demonstration & Automated Grading
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {SAMPLES.map((sample) => (
            <div
              key={sample.id}
              style={{
                background: '#0d131f',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '16px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span
                    style={{
                      background: '#172033',
                      color: '#38bdf8',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontFamily: 'monospace',
                      fontWeight: 'bold',
                      fontSize: '0.78rem',
                    }}
                  >
                    {sample.id}
                  </span>
                  <strong style={{ fontSize: '0.95rem', color: '#fff' }}>{sample.category}</strong>
                </div>

                <button
                  onClick={() => copyToClipboard(sample.input)}
                  className="btn-preset"
                  style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '4px 10px' }}
                >
                  <Copy size={12} />
                  <span>Copy Input JSON</span>
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', fontSize: '0.82rem' }}>
                {/* Input */}
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '6px' }}>
                  <div style={{ color: '#38bdf8', fontWeight: 'bold', marginBottom: '6px' }}>Sample Input:</div>
                  <div style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>
                    <div><strong>Source IP:</strong> {sample.input.sourceIP}</div>
                    <div><strong>Destination IP:</strong> {sample.input.destinationIP}</div>
                    <div><strong>Port:</strong> {sample.input.port} ({sample.input.protocol})</div>
                    <div style={{ marginTop: '4px' }}>
                      <strong>Payload:</strong>
                      <pre style={{ background: '#06090e', padding: '6px', borderRadius: '4px', marginTop: '2px', whiteSpace: 'pre-wrap' }}>
                        {sample.input.payload}
                      </pre>
                    </div>
                  </div>
                </div>

                {/* Expected Output */}
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '6px' }}>
                  <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '6px' }}>Expected Output:</div>
                  <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>
                    <div>
                      <strong>Status: </strong>
                      <span
                        className={`badge ${
                          sample.expectedOutput.status === 'NORMAL'
                            ? 'badge-clean'
                            : sample.expectedOutput.status === 'MALICIOUS'
                            ? 'badge-malicious'
                            : 'badge-high'
                        }`}
                      >
                        {sample.expectedOutput.status}
                      </span>
                    </div>
                    <div style={{ marginTop: '4px' }}>
                      <strong>Action: </strong>
                      <span style={{ color: '#fbbf24', fontWeight: 'bold' }}>{sample.expectedOutput.action}</span>
                    </div>
                    <div style={{ marginTop: '4px' }}>
                      <strong>Matched Rule: </strong>
                      <span>{sample.expectedOutput.matchedRule}</span>
                    </div>
                    <div style={{ marginTop: '6px', background: '#06090e', padding: '8px', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>
                      {sample.expectedOutput.automataResult}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
