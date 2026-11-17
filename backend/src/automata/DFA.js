/**
 * Formal Deterministic Finite Automaton (DFA) Implementation
 * M = (Q, Sigma, delta, q0, F)
 * 
 * Q: Finite set of states
 * Sigma: Finite alphabet of input symbols
 * delta: Transition function Q x Sigma -> Q
 * q0: Initial state (q0 in Q)
 * F: Set of accepting / final states (F subset of Q)
 */

class DFA {
  constructor({ id, name, description, states, alphabet, transitions, startState, acceptStates, category }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.states = states; // Array of state labels: ['q0', 'q1', ...]
    this.alphabet = alphabet; // Array of symbols or descriptors
    this.transitions = transitions; // Object: { 'q0': { 'a': 'q1', 'b': 'q0', default: 'q0' }, ... }
    this.startState = startState;
    this.acceptStates = new Set(acceptStates);
    this.category = category;
  }

  /**
   * Transition function delta(q, a)
   */
  transition(currentState, inputChar) {
    const stateTransitions = this.transitions[currentState];
    if (!stateTransitions) return null;

    // Check exact char match
    if (stateTransitions[inputChar] !== undefined) {
      return stateTransitions[inputChar];
    }

    // Check case-insensitive if defined
    const lower = inputChar.toLowerCase();
    if (stateTransitions[lower] !== undefined) {
      return stateTransitions[lower];
    }
    const upper = inputChar.toUpperCase();
    if (stateTransitions[upper] !== undefined) {
      return stateTransitions[upper];
    }

    // Check wildcard / default transition
    if (stateTransitions['*'] !== undefined) {
      return stateTransitions['*'];
    }
    if (stateTransitions['default'] !== undefined) {
      return stateTransitions['default'];
    }

    return null; // Undefined / Dead state
  }

  /**
   * Validates full string from start to end (used for Form Validation e.g., IPv4)
   * Returns: { accepted: boolean, finalState, trace: [] }
   */
  validate(inputString) {
    let currentState = this.startState;
    const trace = [];

    for (let i = 0; i < inputString.length; i++) {
      const char = inputString[i];
      const nextState = this.transition(currentState, char);
      
      trace.push({
        step: i + 1,
        from: currentState,
        input: char,
        to: nextState || 'TRAP'
      });

      if (!nextState || nextState === 'TRAP') {
        return {
          accepted: false,
          finalState: 'TRAP',
          rejectedAtIndex: i,
          trace
        };
      }
      currentState = nextState;
    }

    const accepted = this.acceptStates.has(currentState);
    return {
      accepted,
      finalState: currentState,
      trace
    };
  }

  /**
   * Scans payload for substrings that drive the automaton to an accept state.
   * Uses a sliding-window or search DFA simulation for Network Payload Inspection.
   */
  scan(payload) {
    if (!payload || typeof payload !== 'string') {
      return { detected: false };
    }

    // Test substrings or streaming simulation
    const maxLen = payload.length;
    for (let start = 0; start < maxLen; start++) {
      let currentState = this.startState;
      const currentTrace = [];

      for (let i = start; i < maxLen; i++) {
        const char = payload[i];
        const nextState = this.transition(currentState, char);

        if (!nextState || nextState === 'TRAP') {
          // Path broken, break inner loop to try next starting position
          break;
        }

        currentTrace.push({
          from: currentState,
          input: char,
          to: nextState
        });

        currentState = nextState;

        if (this.acceptStates.has(currentState)) {
          return {
            detected: true,
            matchedSubstring: payload.substring(start, i + 1),
            startIndex: start,
            endIndex: i + 1,
            finalState: currentState,
            trace: currentTrace
          };
        }
      }
    }

    return { detected: false };
  }

  /**
   * Generates a structured State Transition Table
   */
  getTransitionTable() {
    const table = [];
    for (const state of this.states) {
      const isStart = state === this.startState;
      const isAccept = this.acceptStates.has(state);
      const row = {
        state,
        isStart,
        isAccept,
        transitions: {}
      };

      for (const symbol of this.alphabet) {
        const target = this.transition(state, symbol);
        row.transitions[symbol] = target || '—';
      }
      table.push(row);
    }
    return table;
  }
}

module.exports = DFA;
