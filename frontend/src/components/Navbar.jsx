import React from 'react';
import { ShieldAlert, Activity, Bell, Cpu, FileText, Database, RotateCcw } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, alertsCount, health, onClearData }) {
  const isDbConnected = health?.database?.connected;

  return (
    <header className="header-bar">
      <div className="brand-section">
        <div className="brand-icon-wrapper">
          <ShieldAlert size={24} color="#00ff88" />
        </div>
        <div>
          <h1 className="brand-title">CAMPUS DEFENDER NIDS</h1>
          <p className="brand-subtitle">Regular Expressions & Finite Automata Engine</p>
        </div>
      </div>

      <nav className="nav-tabs">
        <button
          className={`nav-tab-btn ${activeTab === 'monitor' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitor')}
        >
          <Activity size={16} />
          <span>Live Monitor & Form</span>
        </button>

        <button
          className={`nav-tab-btn ${activeTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('alerts')}
        >
          <Bell size={16} />
          <span>Intrusion Alerts</span>
          {alertsCount > 0 && (
            <span
              style={{
                background: '#f43f5e',
                color: '#fff',
                fontSize: '0.7rem',
                padding: '1px 6px',
                borderRadius: '9999px',
                fontWeight: 'bold',
              }}
            >
              {alertsCount}
            </span>
          )}
        </button>

        <button
          className={`nav-tab-btn ${activeTab === 'automata' ? 'active' : ''}`}
          onClick={() => setActiveTab('automata')}
        >
          <Cpu size={16} />
          <span>Automata & Transition Tables</span>
        </button>

        <button
          className={`nav-tab-btn ${activeTab === 'samples' ? 'active' : ''}`}
          onClick={() => setActiveTab('samples')}
        >
          <FileText size={16} />
          <span>Sample Inputs & Deliverables</span>
        </button>
      </nav>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div className="status-pill" title={isDbConnected ? 'Connected to MongoDB' : 'Resilient In-Memory Mode'}>
          <Database size={13} />
          <span>{isDbConnected ? 'MongoDB: Online' : 'MongoDB: In-Memory'}</span>
        </div>

        <div className="status-pill">
          <span className="pulse-dot"></span>
          <span>NIDS Engine: ACTIVE</span>
        </div>

        <button
          onClick={onClearData}
          className="btn-preset"
          style={{ display: 'flex', alignItems: 'center', gap: '5px' }}
          title="Reset traffic & alerts"
        >
          <RotateCcw size={13} />
          <span>Reset</span>
        </button>
      </div>
    </header>
  );
}
