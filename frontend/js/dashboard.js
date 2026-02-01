/*
dashboard.js - Main Dashboard Update Logic
============================================

This module handles the main dashboard page initialization and updates.

OWNER: Member 3 (Frontend Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Configuration:
   - const REFRESH_INTERVAL = 3000 (3 seconds)
   - References to DOM elements

2. Initialization function:
   
   initDashboard()
   - Called when DOM is loaded
   - Creates chart instances using charts.js functions
   - Performs initial data fetch
   - Starts the auto-refresh interval
   - Sets up event listeners

3. Data update functions:

   async updateMetrics()
   - Calls getRealtimeStats() from api.js
   - Updates the metric cards with new values
   - Adds animation class for value changes
   
   async updateHealthScore()
   - Calls getHealthScore() from api.js
   - Updates health score display
   - Changes color based on score (green/yellow/red)
   
   async updateBandwidthHistory()
   - Calls getBandwidthHistory() from api.js
   - Passes data to updateBandwidthChart() from charts.js
   
   async updateProtocolDistribution()
   - Calls getProtocols() from api.js
   - Passes data to updateProtocolChart() from charts.js
   
   async updateTopDevices()
   - Calls getTopDevices() from api.js
   - Rebuilds the devices table HTML
   - Highlights changes from previous data

4. Main update loop:
   
   async refreshDashboard()
   - Calls all update functions
   - Updates "last updated" timestamp
   - Handles errors gracefully (show error message, retry)

5. Event listeners:
   - DOMContentLoaded: Call initDashboard()
   - Visibility change: Pause/resume refresh when tab hidden
   - Manual refresh button click

6. Error handling:
   - Show toast/notification on API errors
   - Retry logic for failed requests
   - Graceful degradation (show stale data with warning)

EXAMPLE STRUCTURE:
------------------
const REFRESH_INTERVAL = 3000;
let refreshIntervalId = null;

async function initDashboard() {
    createBandwidthChart('bandwidthCanvas');
    createProtocolChart('protocolCanvas');
    await refreshDashboard();
    refreshIntervalId = setInterval(refreshDashboard, REFRESH_INTERVAL);
}

async function refreshDashboard() {
    await Promise.all([
        updateMetrics(),
        updateHealthScore(),
        updateBandwidthHistory(),
        updateProtocolDistribution(),
        updateTopDevices()
    ]);
    document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
}

document.addEventListener('DOMContentLoaded', initDashboard);
*/
