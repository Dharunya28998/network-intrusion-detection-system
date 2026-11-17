const DFA = require('./DFA');

/**
 * 1. SQL Injection Detection Automaton
 * Pattern: ' OR 1=1
 * Sigma: { ', ' ', 'o', 'r', '1', '=' }
 */
const sqliDFAConfig = {
  id: 'dfa-sqli',
  name: "SQL Injection Detection Automaton (' OR 1=1)",
  description: "Detects classic SQL authentication bypass injection signature ' OR 1=1",
  category: 'INTRUSION_DETECTION',
  attackType: 'SQL Injection',
  severity: 'CRITICAL',
  states: ['q0', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8'],
  alphabet: ["'", ' ', 'o', 'r', '1', '='],
  startState: 'q0',
  acceptStates: ['q8'],
  transitions: {
    q0: { "'": 'q1' },
    q1: { ' ': 'q2' },
    q2: { o: 'q3', O: 'q3' },
    q3: { r: 'q4', R: 'q4' },
    q4: { ' ': 'q5' },
    q5: { '1': 'q6' },
    q6: { '=': 'q7' },
    q7: { '1': 'q8' },
    q8: {} // Accept state
  },
  mermaidDiagram: `stateDiagram-v2
    [*] --> q0
    q0 --> q1 : "'"
    q1 --> q2 : " " (space)
    q2 --> q3 : "o" | "O"
    q3 --> q4 : "r" | "R"
    q4 --> q5 : " " (space)
    q5 --> q6 : "1"
    q6 --> q7 : "="
    q7 --> q8 : "1"
    q8 --> [*] : ACCEPT (SQLi Alert)
`,
  formalTuple: {
    states: 'Q = { q0, q1, q2, q3, q4, q5, q6, q7, q8 }',
    alphabet: 'Σ = {\' , [space], o, r, 1, = }',
    startState: 'q0',
    acceptStates: 'F = { q8 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table'
  }
};

/**
 * 2. Cross-Site Scripting (XSS) Detection Automaton
 * Pattern: <script
 * Sigma: { '<', 's', 'c', 'r', 'i', 'p', 't' }
 */
const xssDFAConfig = {
  id: 'dfa-xss',
  name: "Cross-Site Scripting (XSS) Automaton (<script)",
  description: "Detects unauthorized inline script injection tags in network HTTP payloads",
  category: 'INTRUSION_DETECTION',
  attackType: 'Cross-Site Scripting (XSS)',
  severity: 'HIGH',
  states: ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7'],
  alphabet: ['<', 's', 'c', 'r', 'i', 'p', 't'],
  startState: 's0',
  acceptStates: ['s7'],
  transitions: {
    s0: { '<': 's1' },
    s1: { s: 's2', S: 's2' },
    s2: { c: 's3', C: 's3' },
    s3: { r: 's4', R: 's4' },
    s4: { i: 's5', I: 's5' },
    s5: { p: 's6', P: 's6' },
    s6: { t: 's7', T: 's7' },
    s7: {} // Accept state
  },
  mermaidDiagram: `stateDiagram-v2
    [*] --> s0
    s0 --> s1 : "<"
    s1 --> s2 : "s" | "S"
    s2 --> s3 : "c" | "C"
    s3 --> s4 : "r" | "R"
    s4 --> s5 : "i" | "I"
    s5 --> s6 : "p" | "P"
    s6 --> s7 : "t" | "T"
    s7 --> [*] : ACCEPT (XSS Alert)
`,
  formalTuple: {
    states: 'Q = { s0, s1, s2, s3, s4, s5, s6, s7 }',
    alphabet: 'Σ = { <, s, c, r, i, p, t }',
    startState: 's0',
    acceptStates: 'F = { s7 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table'
  }
};

/**
 * 3. Path Traversal Detection Automaton
 * Pattern: ../..
 * Sigma: { '.', '/' }
 */
const pathTraversalDFAConfig = {
  id: 'dfa-traversal',
  name: "Path Traversal Automaton (../../)",
  description: "Detects unauthorized directory climb attempts (../..) in URL queries & packet payloads",
  category: 'INTRUSION_DETECTION',
  attackType: 'Path Traversal',
  severity: 'HIGH',
  states: ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'],
  alphabet: ['.', '/'],
  startState: 'p0',
  acceptStates: ['p5'],
  transitions: {
    p0: { '.': 'p1' },
    p1: { '.': 'p2' },
    p2: { '/': 'p3' },
    p3: { '.': 'p4' },
    p4: { '.': 'p5' },
    p5: {} // Accept state
  },
  mermaidDiagram: `stateDiagram-v2
    [*] --> p0
    p0 --> p1 : "."
    p1 --> p2 : "."
    p2 --> p3 : "/"
    p3 --> p4 : "."
    p4 --> p5 : "."
    p5 --> [*] : ACCEPT (Path Traversal Alert)
`,
  formalTuple: {
    states: 'Q = { p0, p1, p2, p3, p4, p5 }',
    alphabet: 'Σ = { . , / }',
    startState: 'p0',
    acceptStates: 'F = { p5 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table'
  }
};

/**
 * 4. User Form Input Validation - IPv4 Address Validator Automaton
 * Validates canonical IPv4 addresses with 4 octets separated by dots
 * Regex equivalent: ^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$
 * Simplified Formal DFA representation:
 * States:
 * v0: Start
 * v1: 1st digit of octet 1
 * v2: 2nd digit of octet 1
 * v3: 3rd digit of octet 1
 * v4: dot after octet 1
 * v5: 1st digit of octet 2
 * v6: 2nd digit of octet 2
 * v7: 3rd digit of octet 2
 * v8: dot after octet 2
 * v9: 1st digit of octet 3
 * v10: 2nd digit of octet 3
 * v11: 3rd digit of octet 3
 * v12: dot after octet 3
 * v13: 1st digit of octet 4 (Accepting)
 * v14: 2nd digit of octet 4 (Accepting)
 * v15: 3rd digit of octet 4 (Accepting)
 */
const digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

const buildIPv4Transitions = () => {
  const trans = {};
  const setDigits = (fromState, toState) => {
    trans[fromState] = trans[fromState] || {};
    digits.forEach(d => {
      trans[fromState][d] = toState;
    });
  };

  // Octet 1
  setDigits('v0', 'v1');
  setDigits('v1', 'v2');
  trans['v1'] = trans['v1'] || {};
  trans['v1']['.'] = 'v4';

  setDigits('v2', 'v3');
  trans['v2'] = trans['v2'] || {};
  trans['v2']['.'] = 'v4';

  trans['v3'] = trans['v3'] || {};
  trans['v3']['.'] = 'v4';

  // Octet 2
  setDigits('v4', 'v5');
  setDigits('v5', 'v6');
  trans['v5'] = trans['v5'] || {};
  trans['v5']['.'] = 'v8';

  setDigits('v6', 'v7');
  trans['v6'] = trans['v6'] || {};
  trans['v6']['.'] = 'v8';

  trans['v7'] = trans['v7'] || {};
  trans['v7']['.'] = 'v8';

  // Octet 3
  setDigits('v8', 'v9');
  setDigits('v9', 'v10');
  trans['v9'] = trans['v9'] || {};
  trans['v9']['.'] = 'v12';

  setDigits('v10', 'v11');
  trans['v10'] = trans['v10'] || {};
  trans['v10']['.'] = 'v12';

  trans['v11'] = trans['v11'] || {};
  trans['v11']['.'] = 'v12';

  // Octet 4
  setDigits('v12', 'v13');
  setDigits('v13', 'v14');
  setDigits('v14', 'v15');

  return trans;
};

const ipv4ValidatorConfig = {
  id: 'dfa-ipv4-validator',
  name: 'User Form Input Validation Automaton (IPv4 Address)',
  description: 'Deterministic Finite Automaton to validate IPv4 format (e.g. 192.168.1.1) in network form inputs',
  category: 'FORM_VALIDATION',
  states: [
    'v0', 'v1', 'v2', 'v3', 'v4',
    'v5', 'v6', 'v7', 'v8', 'v9',
    'v10', 'v11', 'v12', 'v13', 'v14', 'v15'
  ],
  alphabet: ['0-9', '.'],
  startState: 'v0',
  acceptStates: ['v13', 'v14', 'v15'],
  transitions: buildIPv4Transitions(),
  mermaidDiagram: `stateDiagram-v2
    [*] --> v0
    v0 --> v1 : [0-9]
    v1 --> v2 : [0-9]
    v1 --> v4 : "."
    v2 --> v3 : [0-9]
    v2 --> v4 : "."
    v3 --> v4 : "."

    v4 --> v5 : [0-9]
    v5 --> v6 : [0-9]
    v5 --> v8 : "."
    v6 --> v7 : [0-9]
    v6 --> v8 : "."
    v7 --> v8 : "."

    v8 --> v9 : [0-9]
    v9 --> v10 : [0-9]
    v9 --> v12 : "."
    v10 --> v11 : [0-9]
    v10 --> v12 : "."
    v11 --> v12 : "."

    v12 --> v13 : [0-9]
    v13 --> v14 : [0-9]
    v14 --> v15 : [0-9]

    v13 --> [*] : ACCEPT
    v14 --> [*] : ACCEPT
    v15 --> [*] : ACCEPT
`,
  formalTuple: {
    states: 'Q = { v0, v1, v2, ..., v15 }',
    alphabet: 'Σ = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, . }',
    startState: 'v0',
    acceptStates: 'F = { v13, v14, v15 }',
    transitionFunction: 'δ: Q × Σ → Q as specified in transition table'
  }
};

// Instantiate DFA instances
const sqliDFA = new DFA(sqliDFAConfig);
const xssDFA = new DFA(xssDFAConfig);
const pathTraversalDFA = new DFA(pathTraversalDFAConfig);
const ipv4ValidatorDFA = new DFA(ipv4ValidatorConfig);

module.exports = {
  sqliDFAConfig,
  xssDFAConfig,
  pathTraversalDFAConfig,
  ipv4ValidatorConfig,
  sqliDFA,
  xssDFA,
  pathTraversalDFA,
  ipv4ValidatorDFA
};
