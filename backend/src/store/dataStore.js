const mongoose = require('mongoose');
const TrafficLog = require('../models/TrafficLog');
const Alert = require('../models/Alert');

// In-Memory store fallback
let memoryTraffic = [];
let memoryAlerts = [];

const isMongoActive = () => mongoose.connection.readyState === 1;

const saveTrafficLog = async (data) => {
  if (isMongoActive()) {
    try {
      const log = new TrafficLog(data);
      return await log.save();
    } catch (err) {
      console.warn('[DataStore] Mongo save failed, falling back to memory:', err.message);
    }
  }

  const log = {
    _id: 'mem_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
    ...data,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  memoryTraffic.unshift(log);
  if (memoryTraffic.length > 500) memoryTraffic.pop();
  return log;
};

const saveAlert = async (data) => {
  if (isMongoActive()) {
    try {
      const alert = new Alert(data);
      return await alert.save();
    } catch (err) {
      console.warn('[DataStore] Mongo alert save failed, falling back to memory:', err.message);
    }
  }

  const alert = {
    _id: 'alt_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
    ...data,
    status: data.status || 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  memoryAlerts.unshift(alert);
  if (memoryAlerts.length > 300) memoryAlerts.pop();
  return alert;
};

const getTrafficLogs = async (limit = 100) => {
  if (isMongoActive()) {
    try {
      return await TrafficLog.find().sort({ createdAt: -1 }).limit(Number(limit));
    } catch (err) {
      console.warn('[DataStore] Mongo query failed, using memory:', err.message);
    }
  }
  return memoryTraffic.slice(0, Number(limit));
};

const getAlerts = async (limit = 100) => {
  if (isMongoActive()) {
    try {
      return await Alert.find().sort({ createdAt: -1 }).limit(Number(limit));
    } catch (err) {
      console.warn('[DataStore] Mongo alerts query failed, using memory:', err.message);
    }
  }
  return memoryAlerts.slice(0, Number(limit));
};

const clearAllData = async () => {
  if (isMongoActive()) {
    try {
      await TrafficLog.deleteMany({});
      await Alert.deleteMany({});
    } catch (err) {
      console.warn('[DataStore] Failed to clear MongoDB data:', err.message);
    }
  }
  memoryTraffic = [];
  memoryAlerts = [];
  return { message: 'All traffic and alert records cleared successfully.' };
};

const getStats = async () => {
  const traffic = await getTrafficLogs(1000);
  const alerts = await getAlerts(1000);

  const totalPackets = traffic.length;
  const maliciousCount = traffic.filter((t) => t.status === 'MALICIOUS').length;
  const suspiciousCount = traffic.filter((t) => t.status === 'SUSPICIOUS').length;
  const cleanCount = traffic.filter((t) => t.status === 'NORMAL').length;

  const attackTypeBreakdown = {};
  alerts.forEach((alt) => {
    attackTypeBreakdown[alt.attackType] = (attackTypeBreakdown[alt.attackType] || 0) + 1;
  });

  return {
    totalPackets,
    maliciousCount,
    suspiciousCount,
    cleanCount,
    totalAlerts: alerts.length,
    attackTypeBreakdown,
  };
};

module.exports = {
  saveTrafficLog,
  saveAlert,
  getTrafficLogs,
  getAlerts,
  clearAllData,
  getStats,
  isMongoActive,
};
