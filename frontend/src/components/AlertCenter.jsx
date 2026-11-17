import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Check, Filter } from 'lucide-react';

export default function AlertCenter({ alerts, onResolveAlert }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity === 'ALL') return true;
    return a.severity === filterSeverity;
  });

  return (
    <div className="panel-card">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">
            <ShieldAlert size={20} color="#f43f5e" />
            <span>Campus Network Intrusion Alerts & Incident Response</span>
          </h2>
          <p style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '2px' }}>
            Automated alerts raised by Finite Automata Pattern Recognition & Regex Filter
          </p>
        </div>

        {/* Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={14} color="#9ca3af" />
          <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Severity:</span>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="form-select"
            style={{ padding: '4px 8px', fontSize: '0.78rem', width: 'auto' }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
          </select>
        </div>
      </div>

      {filteredAlerts.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#9ca3af' }}>
          <ShieldAlert size={36} color="#00ff88" style={{ margin: '0 auto 12px', opacity: 0.8 }} />
          <h3>No Intrusion Alerts Active</h3>
          <p style={{ fontSize: '0.8rem', marginTop: '4px' }}>
            All inspected traffic complies with college firewall baseline rules.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredAlerts.map((alert) => (
            <div
              key={alert._id}
              style={{
                background: '#0d131f',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderLeft: `4px solid ${
                  alert.severity === 'CRITICAL'
                    ? '#f43f5e'
                    : alert.severity === 'HIGH'
                    ? '#f97316'
                    : '#fbbf24'
                }`,
                borderRadius: '8px',
                padding: '16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    className={`badge ${
                      alert.severity === 'CRITICAL'
                        ? 'badge-critical'
                        : alert.severity === 'HIGH'
                        ? 'badge-high'
                        : 'badge-suspicious'
                    }`}
                  >
                    {alert.severity}
                  </span>
                  <strong style={{ fontSize: '0.95rem' }}>{alert.ruleName}</strong>
                </div>
                <div style={{ fontSize: '0.75rem', color: '#9ca3af', fontFamily: 'monospace' }}>
                  {new Date(alert.createdAt).toLocaleString()}
                </div>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                  gap: '8px',
                  fontSize: '0.8rem',
                  color: '#9ca3af',
                  background: 'rgba(0,0,0,0.25)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                }}
              >
                <div>
                  Offender IP: <strong style={{ color: '#f43f5e' }}>{alert.sourceIP}</strong>
                </div>
                <div>
                  Target IP: <strong style={{ color: '#e2e8f0' }}>{alert.destinationIP}:{alert.port}</strong>
                </div>
                <div>
                  Protocol: <strong style={{ color: '#38bdf8' }}>{alert.protocol}</strong>
                </div>
                <div>
                  Engine: <strong style={{ color: '#00ff88' }}>{alert.detectionMechanism}</strong>
                </div>
              </div>

              <div style={{ fontSize: '0.82rem' }}>
                <span style={{ color: '#9ca3af' }}>Signature Pattern Trigger: </span>
                <code
                  style={{
                    background: 'rgba(244, 63, 94, 0.15)',
                    color: '#fb7185',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontFamily: 'monospace',
                  }}
                >
                  {alert.matchedPattern}
                </code>
              </div>

              <div
                style={{
                  fontSize: '0.8rem',
                  color: '#6ee7b7',
                  background: 'rgba(16, 185, 129, 0.08)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <Check size={14} color="#00ff88" />
                <span>
                  <strong>Admin Action Recommendation:</strong> {alert.recommendedAction}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
