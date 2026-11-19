# VELALAR COLLEGE OF ENGINEERING AND TECHNOLOGY, ERODE -12
### (AUTONOMOUS)
### DEPARTMENT OF INFORMATION TECHNOLOGY
### ACADEMIC YEAR: 2026 - 27 (ODD)
### ACTIVITY - Project-Based Assessment

**NAME** : DHARUNYA G  
**CLASS** : 24IT5A  
**REG.NO** : 732924ITR030 *(Please update if different)*  
**SUBJECT CODE** : 22ITT51  
**SUBJECT NAME** : FULL STACK WEB DEVELOPMENT (FSWD)  
**ACTIVITY** : 2 (Project-Based Assessment)  

**PROBLEM STATEMENT** :  
A college network administrator wants to detect suspicious network traffic and display alerts on a dashboard. Develop a web application that monitors network traffic and uses regular expressions and finite automata to identify predefined malicious patterns.

**Title Assigned** :  
Network Intrusion Detection System Using Regular Expressions and Finite Automata (Campus Defender NIDS)

---

### Project Folder Structure :
```
CAMPUS-DEFENDER-NIDS/
├── backend/
│   ├── src/
│   │   ├── automata/
│   │   │   ├── DFA.js                  # Formal Automata Engine M = (Q, Σ, δ, q0, F)
│   │   │   ├── definitions.js          # IPv4 Validator, SQLi, XSS, Traversal DFAs
│   │   │   └── nidsEngine.js           # Hybrid Engine (Automata + Regex Signatures)
│   │   ├── config/
│   │   │   └── db.js                   # MongoDB Connection & In-Memory Fallback
│   │   ├── models/
│   │   │   ├── TrafficLog.js           # Mongoose Schema for Network Traffic
│   │   │   ├── Alert.js                # Mongoose Schema for Security Alerts
│   │   │   └── SignatureRule.js        # Mongoose Schema for Attack Signatures
│   │   ├── routes/
│   │   │   ├── trafficRoutes.js        # Packet Processing & Simulation APIs
│   │   │   ├── alertRoutes.js          # Alert Feed & Incident Resolution APIs
│   │   │   └── automataRoutes.js       # Formal Automata Specs & Test APIs
│   │   ├── store/
│   │   │   └── dataStore.js            # Central Persistence Manager
│   │   └── server.js                   # Express Server & Production SPA Serving
│   ├── .env                            # Environment Variables (Port: 5001)
│   └── package.json
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx              # Status Header & Tab Controls
│   │   │   ├── DashboardStats.jsx      # High-level Metrics & Threat Ratio
│   │   │   ├── PacketInjectorForm.jsx  # Form with Real-time Validation & Presets
│   │   │   ├── LiveTrafficTable.jsx    # Real-Time Packet Feed & Inspection Modal
│   │   │   ├── AlertCenter.jsx         # Security Alerts & Mitigations
│   │   │   ├── AutomataViewer.jsx      # State Diagrams, Tables & Step Simulator
│   │   │   └── SampleDataViewer.jsx    # Sample Inputs & Expected Outputs Matrix
│   │   ├── styles/
│   │   │   └── index.css               # SOC Dark Cyber Theme
│   │   ├── utils/
│   │   │   └── api.js                  # Axios/Fetch API Services
│   │   ├── App.jsx                     # Core React Dashboard Component
│   │   └── main.jsx
│   ├── index.html
│   ├── vite.config.js                  # Relative Base & API Proxy Configuration
│   └── package.json
├── AUTOMATA_DESIGN_AND_TRANSITION_TABLES.md
├── sample_inputs_outputs.json
├── render.yaml
├── vercel.json
├── Dockerfile
├── docker-compose.yml
├── README.md
└── package.json
```

**Repository** :  
* **GitHub Repository** : https://github.com/Dharunya28998/network-intrusion-detection-system  
* **Live Deployment URL** : https://potentially-horn-saw-kick.trycloudflare.com  
* **Local Production URL** : http://localhost:5001  

---

## 1.4 Working Principle of the Project

The Campus Defender Network Intrusion Detection System operates through an end-to-end pipeline of packet ingestion, formal automata processing, signature matching, automated threat defense, persistent storage, and responsive web visualization:

1. **Packet Capture & Simulation Ingestion**: The system receives simulated network connection packets through an administrative web form containing source IP, destination IP, target port, protocol (`HTTP`, `HTTPS`, `TCP`, `UDP`), and packet payload.
2. **Multi-tier Form Validation**: Client-side (React) and server-side (Node.js) validators verify that the IP addresses conform to IPv4 standards using both a formal 16-state DFA (`dfa-ipv4-validator`) and regular expressions, while ensuring the port lies within the IEEE range of 1 to 65535.
3. **Formal Finite Automata Traversal**: Incoming payloads are streamed character-by-character through dedicated Deterministic Finite Automata ($M = (Q, \Sigma, \delta, q_0, F)$) to detect attack patterns including SQL Injection (`' OR 1=1`), Cross-Site Scripting (`<script`), and Directory Traversal (`../..`).
4. **Regular Expression Signature Scanning**: Alongside DFA execution, high-performance regex signatures scan for complex attack payloads such as `UNION SELECT`, OS Command Injection shell metacharacters (`; rm -rf`, `| bash`), and unauthorized port probing (e.g. Telnet port 23).
5. **Threat Scoring & Classification**: Packets are evaluated for an aggregated threat score (0 to 100) and categorized into three security levels: `NORMAL`, `SUSPICIOUS`, or `MALICIOUS`.
6. **Automated Defensive Action**: Clean traffic is assigned the action `FORWARDED` to campus servers; suspicious port probing triggers an `ALERTED` action; critical attacks (score $\ge 70$) are immediately assigned `DROPPED` or `BLOCKED`.
7. **Database Persistence**: Network packet events are recorded in MongoDB using the `TrafficLog` Mongoose model, while confirmed intrusion events generate structured incident logs in the `Alert` collection with state transition history.
8. **Interactive Dashboard & Automata Visualization**: The React dashboard displays live telemetry cards, a real-time streaming traffic table with deep packet inspection modals, security alert feeds, and an interactive DFA simulator where users can type any string and watch character-by-character state transitions live.

---

## SOURCE CODE FILE INDEX

### 1. `frontend/src/App.jsx` (Core Dashboard Container)
```jsx
import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import DashboardStats from './components/DashboardStats';
import PacketInjectorForm from './components/PacketInjectorForm';
import LiveTrafficTable from './components/LiveTrafficTable';
import AlertCenter from './components/AlertCenter';
import AutomataViewer from './components/AutomataViewer';
import SampleDataViewer from './components/SampleDataViewer';
import { fetchHealth, fetchTraffic, fetchStats, fetchAlerts, clearData } from './utils/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('monitor');
  const [trafficLogs, setTrafficLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadAllData = async () => {
    try {
      const [healthData, trafficData, alertsData, statsData] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchTraffic(50).catch(() => ({ logs: [] })),
        fetchAlerts(50).catch(() => ({ alerts: [] })),
        fetchStats().catch(() => ({ stats: null })),
      ]);

      if (healthData) setHealth(healthData);
      if (trafficData?.logs) setTrafficLogs(trafficData.logs);
      if (alertsData?.alerts) setAlerts(alertsData.alerts);
      if (statsData?.stats) setStats(statsData.stats);
    } catch (err) {
      console.error('Failed to sync network data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handlePacketSubmitted = () => {
    loadAllData();
  };

  const handleClearData = async () => {
    if (window.confirm('Are you sure you want to clear all traffic logs and alerts?')) {
      await clearData();
      loadAllData();
    }
  };

  return (
    <div className="app-layout">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertsCount={alerts.length}
        health={health}
        onClearData={handleClearData}
      />

      <main className="main-viewport">
        <DashboardStats stats={stats} />

        {activeTab === 'monitor' && (
          <div className="dashboard-grid">
            <PacketInjectorForm onPacketSubmitted={handlePacketSubmitted} />
            <LiveTrafficTable logs={trafficLogs} loading={loading} />
          </div>
        )}

        {activeTab === 'alerts' && (
          <AlertCenter alerts={alerts} onResolveAlert={loadAllData} />
        )}

        {activeTab === 'automata' && <AutomataViewer />}
        {activeTab === 'samples' && <SampleDataViewer />}
      </main>
    </div>
  );
}
```

---

### 2. `backend/src/automata/DFA.js` (Formal Automata Class)
```javascript
/**
 * Formal Deterministic Finite Automaton (DFA) Implementation
 * M = (Q, Sigma, delta, q0, F)
 */
class DFA {
  constructor({ id, name, description, states, alphabet, transitions, startState, acceptStates, category }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.states = states;
    this.alphabet = alphabet;
    this.transitions = transitions;
    this.startState = startState;
    this.acceptStates = new Set(acceptStates);
    this.category = category;
  }

  transition(currentState, inputChar) {
    const stateTransitions = this.transitions[currentState];
    if (!stateTransitions) return null;

    if (stateTransitions[inputChar] !== undefined) return stateTransitions[inputChar];
    const lower = inputChar.toLowerCase();
    if (stateTransitions[lower] !== undefined) return stateTransitions[lower];
    const upper = inputChar.toUpperCase();
    if (stateTransitions[upper] !== undefined) return stateTransitions[upper];
    if (stateTransitions['*'] !== undefined) return stateTransitions['*'];
    if (stateTransitions['default'] !== undefined) return stateTransitions['default'];

    return null;
  }

  validate(inputString) {
    let currentState = this.startState;
    const trace = [];

    for (let i = 0; i < inputString.length; i++) {
      const char = inputString[i];
      const nextState = this.transition(currentState, char);
      trace.push({ step: i + 1, from: currentState, input: char, to: nextState || 'TRAP' });

      if (!nextState || nextState === 'TRAP') {
        return { accepted: false, finalState: 'TRAP', rejectedAtIndex: i, trace };
      }
      currentState = nextState;
    }

    return { accepted: this.acceptStates.has(currentState), finalState: currentState, trace };
  }

  scan(payload) {
    if (!payload || typeof payload !== 'string') return { detected: false };
    const maxLen = payload.length;

    for (let start = 0; start < maxLen; start++) {
      let currentState = this.startState;
      const currentTrace = [];

      for (let i = start; i < maxLen; i++) {
        const char = payload[i];
        const nextState = this.transition(currentState, char);
        if (!nextState || nextState === 'TRAP') break;

        currentTrace.push({ from: currentState, input: char, to: nextState });
        currentState = nextState;

        if (this.acceptStates.has(currentState)) {
          return {
            detected: true,
            matchedSubstring: payload.substring(start, i + 1),
            startIndex: start,
            endIndex: i + 1,
            finalState: currentState,
            trace: currentTrace,
          };
        }
      }
    }
    return { detected: false };
  }
}

module.exports = DFA;
```

---

### 3. `backend/src/server.js` (Express Server & SPA Host)
```javascript
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');
const { connectDB, getDBStatus } = require('./config/db');
const trafficRoutes = require('./routes/trafficRoutes');
const alertRoutes = require('./routes/alertRoutes');
const automataRoutes = require('./routes/automataRoutes');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

app.use('/api/traffic', trafficRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/automata', automataRoutes);

app.get('/api/health', (req, res) => {
  res.json({
    status: 'UP',
    system: 'College Network Intrusion Detection System (NIDS)',
    database: getDBStatus(),
    automataEngine: { status: 'ACTIVE' },
  });
});

const clientBuildPath = path.resolve(__dirname, '../../frontend/dist');
if (fs.existsSync(clientBuildPath)) {
  app.use(express.static(clientBuildPath));
}

app.get('*', (req, res) => {
  const indexFile = path.join(clientBuildPath, 'index.html');
  if (fs.existsSync(indexFile)) {
    res.sendFile(indexFile);
  } else {
    res.status(200).send('College NIDS Backend Running.');
  }
});

const startServer = async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

startServer();
```

---

## AUTOMATA DESIGN, STATE DIAGRAMS & TRANSITION TABLES

A Deterministic Finite Automaton is formally denoted as:
$$M = (Q, \Sigma, \delta, q_0, F)$$

### 1. Form Input Validation DFA (IPv4 Address Format)
- **Problem**: Validates that source and destination IP addresses match `X.X.X.X` (0-255 each).
- **Formal 5-Tuple**:
  - $Q = \{ v_0, v_1, v_2, v_3, v_4, v_5, v_6, v_7, v_8, v_9, v_{10}, v_{11}, v_{12}, v_{13}, v_{14}, v_{15}, v_{\text{trap}} \}$
  - $\Sigma = \{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, . \}$
  - $q_0 = v_0$
  - $F = \{ v_{13}, v_{14}, v_{15} \}$

#### State Transition Table (IPv4 Form Validation):
| State | `[0-9]` | `.` | Other / Invalid |
|---|:---:|:---:|:---:|
| $\rightarrow v_0$ | $v_1$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $v_1$ | $v_2$ | $v_4$ | $v_{\text{trap}}$ |
| $v_2$ | $v_3$ | $v_4$ | $v_{\text{trap}}$ |
| $v_3$ | $v_{\text{trap}}$ | $v_4$ | $v_{\text{trap}}$ |
| $v_4$ | $v_5$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $v_5$ | $v_6$ | $v_8$ | $v_{\text{trap}}$ |
| $v_6$ | $v_7$ | $v_8$ | $v_{\text{trap}}$ |
| $v_7$ | $v_{\text{trap}}$ | $v_8$ | $v_{\text{trap}}$ |
| $v_8$ | $v_9$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $v_9$ | $v_{10}$ | $v_{12}$ | $v_{\text{trap}}$ |
| $v_{10}$ | $v_{11}$ | $v_{12}$ | $v_{\text{trap}}$ |
| $v_{11}$ | $v_{\text{trap}}$ | $v_{12}$ | $v_{\text{trap}}$ |
| $v_{12}$ | $v_{13}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $* v_{13}$ | $v_{14}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $* v_{14}$ | $v_{15}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $* v_{15}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |
| $v_{\text{trap}}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ | $v_{\text{trap}}$ |

---

### 2. SQL Injection Detection Automaton (`' OR 1=1`)
- **Problem**: Detects authentication bypass SQL injection tautology `' OR 1=1`.
- **Formal 5-Tuple**:
  - $Q = \{ q_0, q_1, q_2, q_3, q_4, q_5, q_6, q_7, q_8 \}$
  - $\Sigma = \{ ', \text{space}, o, r, 1, = \}$
  - $q_0 = q_0$
  - $F = \{ q_8 \}$ (SQLi Alert Trigger)

#### State Transition Table (SQL Injection DFA):
| State | `'` | ` ` (space) | `o` / `O` | `r` / `R` | `1` | `=` | Other |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| $\rightarrow q_0$ | $q_1$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ |
| $q_1$ | $q_1$ | $q_2$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ |
| $q_2$ | $q_1$ | $q_2$ | $q_3$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ |
| $q_3$ | $q_1$ | $q_0$ | $q_0$ | $q_4$ | $q_0$ | $q_0$ | $q_0$ |
| $q_4$ | $q_1$ | $q_5$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ |
| $q_5$ | $q_1$ | $q_5$ | $q_0$ | $q_0$ | $q_6$ | $q_0$ | $q_0$ |
| $q_6$ | $q_1$ | $q_0$ | $q_0$ | $q_0$ | $q_0$ | $q_7$ | $q_0$ |
| $q_7$ | $q_1$ | $q_0$ | $q_0$ | $q_0$ | $q_8$ | $q_0$ | $q_0$ |
| $* q_8$ | — | — | — | — | — | — | — |

---

## SAMPLE INPUTS AND EXPECTED OUTPUTS

| Test ID | Test Category | Sample Input | Expected Output Status | Expected Defensive Action & Automata Result |
|---|---|---|:---:|---|
| **TC-01** | Clean Web Traffic | `{"sourceIP":"192.168.1.100", "destinationIP":"10.0.0.1", "port":80, "protocol":"HTTP", "payload":"GET /student/portal HTTP/1.1"}` | `NORMAL` | **FORWARDED**<br>All DFAs stay in non-accepting states. |
| **TC-02** | SQL Injection Attack | `{"sourceIP":"10.20.1.14", "destinationIP":"172.16.0.5", "port":80, "protocol":"HTTP", "payload":"username=admin' OR 1=1--"}` | `MALICIOUS` | **BLOCKED**<br>DFA reaches state $q_8$ (Accept). |
| **TC-03** | Cross-Site Scripting | `{"sourceIP":"172.28.4.11", "destinationIP":"172.16.0.5", "port":443, "protocol":"HTTPS", "payload":"<script>alert(1)</script>"}` | `MALICIOUS` | **BLOCKED**<br>DFA reaches state $s_7$ (Accept). |
| **TC-04** | Directory Traversal | `{"sourceIP":"198.51.100.3", "destinationIP":"172.16.0.10", "port":80, "protocol":"HTTP", "payload":"GET /file=../../etc/passwd"}` | `MALICIOUS` | **BLOCKED**<br>DFA reaches state $p_5$ (Accept). |
| **TC-05** | Form Validation Rejection | `{"sourceIP":"999.300.1.1", "destinationIP":"172.16.0.5", "port":80, "protocol":"HTTP", "payload":"test"}` | `FORM REJECTED` | **HTTP 400 Bad Request**<br>Input DFA reaches $v_{\text{trap}}$ state. |

---

## MONGODB COMMANDS USED IN PROJECT
MongoDB stores packet telemetry logs and security incident alerts.

1. **Display Available Databases**:
   `show dbs`
2. **Select Campus NIDS Database**:
   `use college_nids`
3. **Display Collections**:
   `show collections`
4. **Retrieve All Security Alerts**:
   `db.alerts.find()`
5. **Display Alerts in Readable Format**:
   `db.alerts.find().pretty()`
6. **Query Alerts by Offending Source IP**:
   `db.alerts.find({ sourceIP: "10.20.1.14" })`
7. **Count Total Logged Packets**:
   `db.trafficlogs.countDocuments()`
8. **Retrieve Latest 5 Malicious Packets**:
   `db.trafficlogs.find({ status: "MALICIOUS" }).sort({ createdAt: -1 }).limit(5)`

---

## GITHUB COMMANDS TO PUSH PROJECT
Open PowerShell in the project directory:
```powershell
cd "c:\Users\DHARUNYA G\OneDrive\Desktop\individual activity"

# 1. Check Git Status
git status

# 2. Add all files
git add .

# 3. Commit files
git commit -m "Complete College NIDS Project with Automata Engine and Form Validation"

# 4. Set remote repository
git remote set-url origin https://github.com/Dharunya28998/network-intrusion-detection-system.git

# 5. Set branch to main and push
git branch -M main
git push -u origin main
```

---

## PROCEDURE TO RUN PROJECT LOCALLY

* **Step 1: Open the Project Directory**
  ```powershell
  cd "c:\Users\DHARUNYA G\OneDrive\Desktop\individual activity"
  ```
* **Step 2: Start MongoDB**
  Ensure MongoDB service is running locally (`mongodb://127.0.0.1:27017`).
* **Step 3: Run the Application (Unified Server)**
  ```powershell
  npm start
  ```
  *Server starts on `http://localhost:5001` serving both Backend API and React Frontend.*
* **Step 4: Alternative (Developer Mode with Vite)**
  - Terminal 1 (Backend): `npm --prefix backend start` (Port 5001)
  - Terminal 2 (Frontend): `npm --prefix frontend run dev` (Port 3000)
* **Step 5: Open Browser Dashboard**
  Open Google Chrome and navigate to:  
  **`http://localhost:5001`** *(or `http://localhost:3000` in dev mode)*
* **Step 6: Test Features**
  - Click **1-Click Attack Presets** (SQLi, XSS, Path Traversal) to inject test packets.
  - Observe real-time state traversal in the Live Traffic Table.
  - Navigate to **Automata & Transition Tables** to inspect diagrams and run custom strings through the Step Simulator.
