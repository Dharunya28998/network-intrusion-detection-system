import React, { useState, useEffect, useRef } from 'react';
import mermaid from 'mermaid';
import { Cpu, Play, CheckCircle, XCircle, BookOpen, Layers, ArrowRight } from 'lucide-react';
import { fetchAutomataSpecs, testAutomaton } from '../utils/api';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  securityLevel: 'loose',
  fontFamily: 'Inter, monospace',
});

export default function AutomataViewer() {
  const [specs, setSpecs] = useState([]);
  const [selectedAutomatonId, setSelectedAutomatonId] = useState('dfa-ipv4-validator');
  const [loading, setLoading] = useState(true);

  // Interactive Test String State
  const [testInput, setTestInput] = useState('192.168.1.1');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const mermaidRef = useRef(null);

  // Load specs from backend API
  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchAutomataSpecs();
        if (data.automata) {
          setSpecs(data.automata);
        }
      } catch (err) {
        console.error('Failed to load automata specs:', err);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const activeAutomaton = specs.find((a) => a.id === selectedAutomatonId) || specs[0];

  // Set default test input when automaton changes
  useEffect(() => {
    if (selectedAutomatonId === 'dfa-ipv4-validator') {
      setTestInput('192.168.1.1');
    } else if (selectedAutomatonId === 'dfa-sqli') {
      setTestInput("' OR 1=1");
    } else if (selectedAutomatonId === 'dfa-xss') {
      setTestInput('<script');
    } else if (selectedAutomatonId === 'dfa-traversal') {
      setTestInput('../../');
    }
    setTestResult(null);
  }, [selectedAutomatonId]);

  // Render Mermaid Diagram
  useEffect(() => {
    if (!activeAutomaton?.mermaidDiagram || !mermaidRef.current) return;

    const renderDiagram = async () => {
      try {
        mermaidRef.current.innerHTML = '';
        const id = `mermaid-${Date.now()}`;
        const { svg } = await mermaid.render(id, activeAutomaton.mermaidDiagram);
        if (mermaidRef.current) {
          mermaidRef.current.innerHTML = svg;
        }
      } catch (err) {
        console.warn('Mermaid render warning:', err);
        if (mermaidRef.current) {
          mermaidRef.current.innerHTML = `<pre style="color:#9ca3af;font-size:0.8rem;text-align:left;">${activeAutomaton.mermaidDiagram}</pre>`;
        }
      }
    };

    renderDiagram();
  }, [activeAutomaton]);

  // Run interactive DFA test
  const handleRunTest = async (e) => {
    e.preventDefault();
    if (!testInput) return;
    setTesting(true);

    try {
      const result = await testAutomaton(selectedAutomatonId, testInput);
      setTestResult(result);
    } catch (err) {
      console.error('Test execution failed:', err);
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="panel-card" style={{ textAlign: 'center', padding: '40px' }}>
        Loading formal Automata specifications and transition matrices...
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Automata Selector Tabs */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 className="panel-title">
              <Cpu size={20} color="#00ff88" />
              <span>Formal Automata & State Transition Specifications</span>
            </h2>
            <p style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '2px' }}>
              Academic models for Pattern Recognition and Form Validation
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {specs.map((item) => (
              <button
                key={item.id}
                onClick={() => setSelectedAutomatonId(item.id)}
                className={`btn-preset ${selectedAutomatonId === item.id ? 'active' : ''}`}
                style={{
                  background: selectedAutomatonId === item.id ? '#172033' : 'rgba(255,255,255,0.05)',
                  borderColor: selectedAutomatonId === item.id ? '#00ff88' : 'rgba(255,255,255,0.1)',
                  color: selectedAutomatonId === item.id ? '#00ff88' : '#e2e8f0',
                  fontWeight: '600',
                }}
              >
                {item.category === 'FORM_VALIDATION' ? '📝 Form DFA: ' : '🛡️ NIDS DFA: '}
                {item.id.replace('dfa-', '').toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {activeAutomaton && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          {/* Left Column: Formal Definition & State Transition Diagram */}
          <div className="panel-card">
            <div className="panel-header">
              <div>
                <h3 style={{ fontSize: '1.05rem', color: '#fff' }}>{activeAutomaton.name}</h3>
                <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>
                  Category: {activeAutomaton.category}
                </span>
              </div>
            </div>

            <p style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '14px' }}>
              {activeAutomaton.description}
            </p>

            {/* Formal 5-Tuple Box */}
            <div
              style={{
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '8px',
                padding: '12px 16px',
                marginBottom: '16px',
                fontSize: '0.8rem',
                fontFamily: 'monospace',
              }}
            >
              <div style={{ color: '#00ff88', fontWeight: 'bold', marginBottom: '6px' }}>
                Mathematical 5-Tuple: M = (Q, Σ, δ, q₀, F)
              </div>
              <div style={{ color: '#9ca3af' }}>• <strong>States:</strong> {activeAutomaton.formalTuple?.states}</div>
              <div style={{ color: '#9ca3af' }}>• <strong>Alphabet:</strong> {activeAutomaton.formalTuple?.alphabet}</div>
              <div style={{ color: '#9ca3af' }}>• <strong>Start State:</strong> q₀ = {activeAutomaton.startState}</div>
              <div style={{ color: '#9ca3af' }}>• <strong>Accept States:</strong> {activeAutomaton.formalTuple?.acceptStates}</div>
              <div style={{ color: '#9ca3af' }}>• <strong>Transitions:</strong> δ : Q × Σ → Q</div>
            </div>

            {/* State Transition Diagram Container */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '0.82rem', fontWeight: 'bold', color: '#e2e8f0' }}>
                  State Transition Diagram
                </span>
                <span style={{ fontSize: '0.7rem', color: '#9ca3af' }}>Formal Graphical Graph</span>
              </div>
              <div className="diagram-container">
                <div ref={mermaidRef} style={{ width: '100%', overflowX: 'auto' }}></div>
              </div>
            </div>
          </div>

          {/* Right Column: State Transition Table & Interactive DFA Simulator */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Transition Table */}
            <div className="panel-card">
              <div className="panel-header">
                <div>
                  <h3 style={{ fontSize: '1rem', color: '#fff' }}>State Transition Table (δ)</h3>
                  <span style={{ fontSize: '0.72rem', color: '#9ca3af' }}>
                    Rows: States Q | Columns: Input Symbols Σ | (→ Start, * Accept)
                  </span>
                </div>
              </div>

              <div className="transition-table-box" style={{ maxHeight: '280px', overflowY: 'auto' }}>
                <table className="ttable">
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', minWidth: '100px' }}>Current State (q)</th>
                      {activeAutomaton.alphabet.map((sym, idx) => (
                        <th key={idx}>'{sym === ' ' ? '[space]' : sym}'</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {activeAutomaton.transitionTable?.map((row, rIdx) => (
                      <tr
                        key={rIdx}
                        className={`${row.isStart ? 'start-state' : ''} ${row.isAccept ? 'accept-state' : ''}`}
                      >
                        <td style={{ textAlign: 'left', fontWeight: 'bold' }}>
                          {row.isStart && <span style={{ color: '#38bdf8' }}>→ </span>}
                          {row.isAccept && <span style={{ color: '#00ff88' }}>* </span>}
                          <span>{row.state}</span>
                        </td>
                        {activeAutomaton.alphabet.map((sym, sIdx) => (
                          <td key={sIdx}>
                            {row.transitions[sym] ? (
                              <span style={{ color: row.transitions[sym] !== '—' ? '#00ff88' : '#6b7280' }}>
                                {row.transitions[sym]}
                              </span>
                            ) : (
                              <span style={{ color: '#6b7280' }}>—</span>
                            )}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Interactive Step-by-Step DFA String Simulator */}
            <div className="panel-card">
              <div className="panel-header">
                <h3 style={{ fontSize: '1rem', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Play size={16} color="#00ff88" />
                  <span>Interactive DFA Execution & Step Simulator</span>
                </h3>
              </div>

              <form onSubmit={handleRunTest} style={{ marginBottom: '14px' }}>
                <label className="form-label">
                  Test String to trace through {activeAutomaton.name}:
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    className="form-input"
                    value={testInput}
                    onChange={(e) => setTestInput(e.target.value)}
                    placeholder="Enter input string..."
                  />
                  <button type="submit" className="btn-primary" style={{ width: 'auto', padding: '0 20px' }}>
                    {testing ? 'Simulating...' : 'Test String'}
                  </button>
                </div>
              </form>

              {/* Simulation Result */}
              {testResult && (
                <div
                  style={{
                    background: 'rgba(0, 0, 0, 0.4)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '14px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div>
                      {activeAutomaton.category === 'FORM_VALIDATION' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {testResult.fullValidation.accepted ? (
                            <CheckCircle size={18} color="#00ff88" />
                          ) : (
                            <XCircle size={18} color="#f43f5e" />
                          )}
                          <strong style={{ color: testResult.fullValidation.accepted ? '#00ff88' : '#f43f5e' }}>
                            {testResult.fullValidation.accepted
                              ? 'ACCEPTED (Valid IPv4 Format)'
                              : 'REJECTED (Invalid Format - Reached Trap State)'}
                          </strong>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {testResult.substringScan.detected ? (
                            <CheckCircle size={18} color="#f43f5e" />
                          ) : (
                            <CheckCircle size={18} color="#00ff88" />
                          )}
                          <strong style={{ color: testResult.substringScan.detected ? '#f43f5e' : '#00ff88' }}>
                            {testResult.substringScan.detected
                              ? 'ALERT! Malicious Pattern Accepted by Automaton'
                              : 'CLEAN: No Malicious DFA State Traversal Detected'}
                          </strong>
                        </div>
                      )}
                    </div>

                    <span style={{ fontSize: '0.75rem', color: '#9ca3af', fontFamily: 'monospace' }}>
                      Final State: {activeAutomaton.category === 'FORM_VALIDATION'
                        ? testResult.fullValidation.finalState
                        : testResult.substringScan.finalState || 'Non-Accept'}
                    </span>
                  </div>

                  {/* Execution Trace Pills */}
                  <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '6px' }}>
                    Step-by-Step State Transition Sequence:
                  </div>
                  <div className="trace-sequence" style={{ maxHeight: '120px', overflowY: 'auto' }}>
                    {(activeAutomaton.category === 'FORM_VALIDATION'
                      ? testResult.fullValidation.trace
                      : testResult.substringScan.trace || []
                    ).map((t, idx) => (
                      <div key={idx} className="trace-step">
                        <span>{t.from}</span>
                        <span className="trace-arrow">
                          --[{t.input === ' ' ? 'space' : t.input}]-&gt;
                        </span>
                        <span style={{ color: '#38bdf8' }}>{t.to}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
