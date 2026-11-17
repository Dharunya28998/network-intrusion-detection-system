const API_BASE = '/api';

export const fetchHealth = async () => {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
};

export const fetchTraffic = async (limit = 100) => {
  const res = await fetch(`${API_BASE}/traffic?limit=${limit}`);
  return res.json();
};

export const fetchStats = async () => {
  const res = await fetch(`${API_BASE}/traffic/stats`);
  return res.json();
};

export const fetchAlerts = async (limit = 100) => {
  const res = await fetch(`${API_BASE}/alerts?limit=${limit}`);
  return res.json();
};

export const processPacket = async (packetData) => {
  const res = await fetch(`${API_BASE}/traffic/process`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(packetData),
  });
  return res.json();
};

export const fetchAutomataSpecs = async () => {
  const res = await fetch(`${API_BASE}/automata/specs`);
  return res.json();
};

export const testAutomaton = async (automatonId, inputString) => {
  const res = await fetch(`${API_BASE}/automata/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ automatonId, inputString }),
  });
  return res.json();
};

export const clearData = async () => {
  const res = await fetch(`${API_BASE}/traffic`, { method: 'DELETE' });
  return res.json();
};
