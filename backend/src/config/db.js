const mongoose = require('mongoose');

let isConnected = false;

const connectDB = async () => {
  const mongoURI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/college_nids';
  try {
    const conn = await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 2500,
    });
    isConnected = true;
    console.log(`[MongoDB] Connected successfully to host: ${conn.connection.host}`);
  } catch (error) {
    console.warn(`[MongoDB Warning] Could not connect to MongoDB at ${mongoURI}.`);
    console.warn(`[MongoDB Warning] Details: ${error.message}`);
    console.log(`[MongoDB Fallback] App will operate in resilient mode (saving in-memory if DB is offline).`);
    isConnected = false;
  }
};

const getDBStatus = () => ({
  connected: isConnected,
  readyState: mongoose.connection.readyState,
  uri: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/college_nids'
});

module.exports = { connectDB, getDBStatus };
