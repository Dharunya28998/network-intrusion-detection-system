const mongoose = require('mongoose');

const SignatureRuleSchema = new mongoose.Schema(
  {
    ruleId: {
      type: String,
      required: true,
      unique: true,
    },
    name: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      required: true,
    },
    severity: {
      type: String,
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      default: 'HIGH',
    },
    regexPattern: {
      type: String,
      required: true,
    },
    automatonKey: {
      type: String, // Reference to precompiled DFA if applicable
    },
    description: {
      type: String,
    },
    mitigation: {
      type: String,
    },
    enabled: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('SignatureRule', SignatureRuleSchema);
