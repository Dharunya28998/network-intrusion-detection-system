import React, { useState } from 'react';
import { Eye, ShieldAlert, CheckCircle, AlertTriangle, X } from 'lucide-react';

export default function LiveTrafficTable({ logs, loading }) {
  const [selectedLog, setSelectedLog] = useState(null);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'MALICIOUS':
        return <span className="badge badge-malicious">MALICIOUS</span>;
      case 'SUSPICIOUS':
        return <span className="badge badge-suspicious">SUSPICIOUS</span>;
      case 'NORMAL':
      default:
        return <span className="badge badge-clean">NORMAL</span>;
    }
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">
          <span>Real-Time Network Traffic Stream</span>
        </h2>
        <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>
          Monitoring College Subnet Traffic (Port 80/443/8080/TCP)
        </span>
      </div>

      <div className="table-container">
        <table className="traffic-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Port</th>
              <th>Protocol</th>
              <th>Status</th>
              <th>Action</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '24px' }}>
                  Loading network traffic...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '24px', color: '#9ca3af' }}>
                  No packet logs available. Transmit a packet using the form on the left.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log._id}>
                  <td style={{ color: '#9ca3af', fontSize: '0.75rem' }}>
                    {new Date(log.createdAt).toLocaleTimeString()}
                  </td>
                  <td style={{ color: '#38bdf8' }}>{log.sourceIP}</td>
                  <td>{log.destinationIP}</td>
                  <td>{log.port}</td>
                  <td>
                    <span
                      style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'rgba(255,255,255,0.06)',
                        fontSize: '0.72rem',
                      }}
                    >
                      {log.protocol}
                    </span>
                  </td>
                  <td>{getStatusBadge(log.status)}</td>
                  <td>
                    <span
                      style={{
                        color:
                          log.actionTaken === 'BLOCKED' || log.actionTaken === 'DROPPED'
                            ? '#f43f5e'
                            : '#10b981',
                        fontWeight: 'bold',
                        fontSize: '0.75rem',
                      }}
                    >
                      {log.actionTaken}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => setSelectedLog(log)}
                      className="btn-preset"
                      style={{ padding: '4px 8px', display: 'flex', alignItems: 'center', gap: '4px' }}
                      title="Inspect Automata State Transitions & Payload"
                    >
                      <Eye size={12} />
                      <span>Trace</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Packet Inspection Modal */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 100,
          }}
          onClick={() => setSelectedLog(null)}
        >
          <div
            style={{
              background: '#101623',
              border: '1px solid var(--border-color)',
              borderRadius: '14px',
              width: '90%',
              maxWidth: '650px',
              padding: '24px',
              maxHeight: '85vh',
              overflowY: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={18} color="#00ff88" />
                <span>Deep Packet Inspection & Automata Analysis</span>
              </h3>
              <button
                onClick={() => setSelectedLog(null)}
                style={{ background: 'transparent', border: 'none', color: '#9ca3af', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.85rem', marginBottom: '16px' }}>
              <div>
                <span style={{ color: '#9ca3af' }}>Source: </span>
                <strong style={{ color: '#38bdf8' }}>{selectedLog.sourceIP}:{selectedLog.port}</strong>
              </div>
              <div>
                <span style={{ color: '#9ca3af' }}>Destination: </span>
                <strong>{selectedLog.destinationIP}</strong>
              </div>
              <div>
                <span style={{ color: '#9ca3af' }}>Protocol: </span>
                <span>{selectedLog.protocol}</span>
              </div>
              <div>
                <span style={{ color: '#9ca3af' }}>Threat Score: </span>
                <span style={{ color: selectedLog.threatScore > 50 ? '#f43f5e' : '#00ff88' }}>
                  {selectedLog.threatScore} / 100
                </span>
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '0.8rem', color: '#9ca3af', marginBottom: '4px' }}>Packet Payload:</div>
              <pre
                style={{
                  background: '#06090e',
                  border: '1px solid rgba(255,255,255,0.08)',
                  padding: '12px',
                  borderRadius: '8px',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                  whiteSpace: 'pre-wrap',
                  color: '#e2e8f0',
                }}
              >
                {selectedLog.payload}
              </pre>
            </div>

            {selectedLog.detectedAttacks && selectedLog.detectedAttacks.length > 0 ? (
              <div>
                <h4 style={{ fontSize: '0.9rem', color: '#f87171', marginBottom: '8px' }}>
                  Matched Intrusion Signatures & Automata Traces:
                </h4>
                {selectedLog.detectedAttacks.map((att, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'rgba(244, 63, 94, 0.08)',
                      border: '1px solid rgba(244, 63, 94, 0.3)',
                      borderRadius: '8px',
                      padding: '12px',
                      marginBottom: '10px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <strong style={{ color: '#f43f5e' }}>{att.ruleName}</strong>
                      <span className="badge badge-high">{att.severity}</span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                      Detection Mechanism: <strong style={{ color: '#38bdf8' }}>{att.matchedBy}</strong>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                      Matched Pattern: <code style={{ color: '#fbbf24' }}>{att.matchedPattern}</code>
                    </div>

                    {att.automataTrace && att.automataTrace.length > 0 && (
                      <div style={{ marginTop: '8px' }}>
                        <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginBottom: '4px' }}>
                          State Transition History (δ):
                        </div>
                        <div className="trace-sequence">
                          {att.automataTrace.map((t, stepIdx) => (
                            <div key={stepIdx} className="trace-step">
                              <span>{t.from}</span>
                              <span className="trace-arrow">--[{t.input}]-&gt;</span>
                              <span style={{ color: '#38bdf8' }}>{t.to}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#00ff88', fontSize: '0.85rem' }}>
                <CheckCircle size={16} />
                <span>Zero intrusion signatures matched. Payload verified clean by Finite Automata.</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
