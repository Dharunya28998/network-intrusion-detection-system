const express = require('express');
const router = express.Router();
const { getAlerts, clearAllData } = require('../store/dataStore');
const Alert = require('../models/Alert');
const mongoose = require('mongoose');

/**
 * GET /api/alerts
 * List all generated intrusion alerts
 */
router.get('/', async (req, res) => {
  try {
    const limit = req.query.limit || 100;
    const alerts = await getAlerts(limit);
    return res.json({ success: true, count: alerts.length, alerts });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * PATCH /api/alerts/:id/resolve
 * Mark an alert as RESOLVED or INVESTIGATING
 */
router.patch('/:id/resolve', async (req, res) => {
  try {
    const { status } = req.body;
    const targetStatus = status || 'RESOLVED';

    if (mongoose.connection.readyState === 1) {
      const alert = await Alert.findByIdAndUpdate(
        req.params.id,
        { status: targetStatus },
        { new: true }
      );
      if (alert) return res.json({ success: true, alert });
    }

    return res.json({
      success: true,
      message: `Alert ${req.params.id} updated to ${targetStatus}`,
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * DELETE /api/alerts
 * Clear alerts
 */
router.delete('/', async (req, res) => {
  try {
    await clearAllData();
    return res.json({ success: true, message: 'Alerts cleared' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
