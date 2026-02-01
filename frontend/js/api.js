/*
api.js - API Communication Module
===================================

This module handles all fetch() calls to the backend API.

OWNER: Member 3 (Frontend Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Configuration:
   - const API_BASE_URL = 'http://localhost:5000/api'
   - Default fetch options (headers, credentials)

2. Helper function:
   - async fetchApi(endpoint, options = {}): Wrapper around fetch()
     * Prepends API_BASE_URL to endpoint
     * Adds default headers
     * Handles JSON parsing
     * Handles errors and returns {success, data, error}

3. API functions (one for each endpoint):
   
   async getStatus()
   - Calls: GET /api/status
   - Returns: {status, uptime, version}
   
   async getRealtimeStats()
   - Calls: GET /api/stats/realtime
   - Returns: {bandwidth_bps, active_devices, packets_per_second}
   
   async getTopDevices(limit = 10)
   - Calls: GET /api/devices/top?limit=N
   - Returns: {devices: [...]}
   
   async getProtocols(hours = 1)
   - Calls: GET /api/protocols?hours=N
   - Returns: {protocols: [...]}
   
   async getBandwidthHistory(hours = 1)
   - Calls: GET /api/bandwidth/history?hours=N
   - Returns: {history: [...]}
   
   async getAlerts(limit = 50, severity = null)
   - Calls: GET /api/alerts?limit=N&severity=X
   - Returns: {alerts: [...]}
   
   async getHealthScore()
   - Calls: GET /api/health
   - Returns: {score, status, factors}
   
   async updateDeviceName(ipAddress, hostname)
   - Calls: POST /api/devices/update-name
   - Body: {ip_address, hostname}
   - Returns: {success, message}

4. Export all functions for use in other modules

EXAMPLE STRUCTURE:
------------------
const API_BASE_URL = 'http://localhost:5000/api';

async function fetchApi(endpoint, options = {}) {
    try {
        const response = await fetch(API_BASE_URL + endpoint, {
            ...options,
            headers: { 'Content-Type': 'application/json', ...options.headers }
        });
        const data = await response.json();
        return { success: response.ok, data };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getRealtimeStats() {
    return fetchApi('/stats/realtime');
}

// ... more functions
*/
