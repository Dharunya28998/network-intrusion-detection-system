const express = require('express');
const router = express.Router();
const {
  sqliDFAConfig,
  xssDFAConfig,
  pathTraversalDFAConfig,
  ipv4ValidatorConfig,
  sqliDFA,
  xssDFA,
  pathTraversalDFA,
  ipv4ValidatorDFA,
} = require('../automata/definitions');

/**
 * GET /api/automata/specs
 * Returns formal definitions, transition tables, diagrams for all automata
 */
router.get('/specs', (req, res) => {
  const automata = [
    {
      ...sqliDFAConfig,
      transitionTable: sqliDFA.getTransitionTable(),
    },
    {
      ...xssDFAConfig,
      transitionTable: xssDFA.getTransitionTable(),
    },
    {
      ...pathTraversalDFAConfig,
      transitionTable: pathTraversalDFA.getTransitionTable(),
    },
    {
      ...ipv4ValidatorConfig,
      transitionTable: ipv4ValidatorDFA.getTransitionTable(),
    },
  ];

  return res.json({
    success: true,
    total: automata.length,
    automata,
  });
});

/**
 * POST /api/automata/test
 * Test an input string step-by-step against any automaton
 */
router.post('/test', (req, res) => {
  const { automatonId, inputString } = req.body;

  if (typeof inputString !== 'string') {
    return res.status(400).json({
      success: false,
      message: 'inputString is required and must be a string',
    });
  }

  let targetDFA;
  let targetConfig;
  switch (automatonId) {
    case 'dfa-sqli':
      targetDFA = sqliDFA;
      targetConfig = sqliDFAConfig;
      break;
    case 'dfa-xss':
      targetDFA = xssDFA;
      targetConfig = xssDFAConfig;
      break;
    case 'dfa-traversal':
      targetDFA = pathTraversalDFA;
      targetConfig = pathTraversalDFAConfig;
      break;
    case 'dfa-ipv4-validator':
    default:
      targetDFA = ipv4ValidatorDFA;
      targetConfig = ipv4ValidatorConfig;
      break;
  }

  // If form validation automaton, run full string validation
  // If pattern matching automaton, run scan + validate
  const validationResult = targetDFA.validate(inputString);
  const scanResult = targetDFA.scan(inputString);

  return res.json({
    success: true,
    automaton: {
      id: targetConfig.id,
      name: targetConfig.name,
      formalTuple: targetConfig.formalTuple,
      mermaidDiagram: targetConfig.mermaidDiagram,
    },
    inputString,
    fullValidation: validationResult,
    substringScan: scanResult,
  });
});

module.exports = router;
