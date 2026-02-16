/*
dashboard.js - Main Dashboard Update Logic
============================================

This module handles the main dashboard page initialization and updates.

OWNER: Member 3 (Frontend Developer)
*/

// ===========================
// 1. Configuration
// ===========================

const REFRESH_INTERVAL = 3000; // 3 seconds
let refreshIntervalId = null;
let isPaused = false;

// DOM element references (populated on init)
let elements = {};

// ===========================
// 2. Initialization Function
// ===========================

/**
 * Initialize the dashboard
 * - Creates charts
 * - Performs initial data fetch
 * - Starts auto-refresh interval
 * - Sets up event listeners
 */
async function initDashboard() {
    console.log('Initializing NetWatch Dashboard...');

    // Cache DOM element references
    cacheElements();

    // Create chart instances
    NetWatchCharts.createBandwidthChart('bandwidthCanvas');
    NetWatchCharts.createProtocolChart('protocolCanvas');

    // Initial data load
    showLoadingState();
    await refreshDashboard();
    hideLoadingState();

    // Start auto-refresh
    startAutoRefresh();

    // Setup event listeners
    setupEventListeners();

    console.log('Dashboard initialized successfully');
}

/**
 * Cache DOM element references for performance
 */
function cacheElements() {
    elements = {
        // Metrics
        bandwidthValue: document.getElementById('bandwidthValue'),
        activeDevicesValue: document.getElementById('activeDevicesValue'),
        packetsValue: document.getElementById('packetsValue'),
        healthScoreValue: document.getElementById('healthScoreValue'),
        healthScoreCard: document.getElementById('healthScoreCard'),
        
        // Top devices table
        topDevicesTable: document.getElementById('topDevicesTable'),
        
        // Status indicators
        statusDot: document.getElementById('statusDot'),
        lastUpdated: document.getElementById('lastUpdated'),
        
        // Loading overlay
        loadingOverlay: document.getElementById('loadingOverlay'),
        
        // Refresh button
        refreshButton: document.getElementById('refreshButton')
    };
}

// ===========================
// 3. Data Update Functions
// ===========================

/**
 * Update real-time metrics
 */
async function updateMetrics() {
    try {
        const response = await NetWatchAPI.getRealtimeStats();
        
        if (response.success && response.data) {
            const { bandwidth_bps, active_devices, packets_per_second } = response.data;
            
            // Update bandwidth (convert to MB/s)
            const bandwidthMbps = (bandwidth_bps / (1024 * 1024)).toFixed(2);
            updateValue(elements.bandwidthValue, bandwidthMbps);
            
            // Update active devices
            updateValue(elements.activeDevicesValue, active_devices);
            
            // Update packets per second
            const packetsFormatted = packets_per_second.toLocaleString();
            updateValue(elements.packetsValue, packetsFormatted);
        }
    } catch (error) {
        console.error('Error updating metrics:', error);
        showError('Failed to update metrics');
    }
}

/**
 * Update health score
 */
async function updateHealthScore() {
    try {
        const response = await NetWatchAPI.getHealthScore();
        
        if (response.success && response.data) {
            const { score, status } = response.data;
            
            // Update score value
            updateValue(elements.healthScoreValue, score);
            
            // Update card styling based on score
            updateHealthScoreCard(score, status);
        }
    } catch (error) {
        console.error('Error updating health score:', error);
    }
}

/**
 * Update health score card styling
 */
function updateHealthScoreCard(score, status) {
    const card = elements.healthScoreCard;
    
    // Remove all status classes
    card.classList.remove('success', 'warning', 'danger');
    
    // Add appropriate class based on score
    if (score >= 80) {
        card.classList.add('success');
    } else if (score >= 60) {
        card.classList.add('warning');
    } else {
        card.classList.add('danger');
    }
}

/**
 * Update bandwidth history chart
 */
async function updateBandwidthHistory() {
    try {
        const response = await NetWatchAPI.getBandwidthHistory(1); // Last 1 hour
        
        if (response.success && response.data && response.data.history) {
            const chart = NetWatchCharts.getBandwidthChart();
            NetWatchCharts.updateBandwidthChart(chart, response.data.history);
        }
    } catch (error) {
        console.error('Error updating bandwidth history:', error);
    }
}

/**
 * Update protocol distribution chart
 */
async function updateProtocolDistribution() {
    try {
        const response = await NetWatchAPI.getProtocols(1); // Last 1 hour
        
        if (response.success && response.data && response.data.protocols) {
            const chart = NetWatchCharts.getProtocolChart();
            NetWatchCharts.updateProtocolChart(chart, response.data.protocols);
        }
    } catch (error) {
        console.error('Error updating protocol distribution:', error);
    }
}

/**
 * Update top devices table
 */
async function updateTopDevices() {
    try {
        const response = await NetWatchAPI.getTopDevices(10);
        
        if (response.success && response.data && response.data.devices) {
            renderTopDevicesTable(response.data.devices);
        }
    } catch (error) {
        console.error('Error updating top devices:', error);
    }
}

/**
 * Render top devices table
 */
function renderTopDevicesTable(devices) {
    const tbody = elements.topDevicesTable;
    if (!tbody) return;
    
    if (devices.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center text-muted">No devices detected</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = devices.map((device, index) => {
        const bandwidth = NetWatchCharts.formatBytes(device.total_bytes);
        const lastSeen = formatLastSeen(device.last_seen);
        const isActive = isDeviceActive(device.last_seen);
        
        return `
            <tr class="fade-in">
                <td>
                    <span class="status-badge ${isActive ? 'active' : 'inactive'}">
                        ${device.ip_address}
                    </span>
                </td>
                <td>${device.hostname || 'Unknown'}</td>
                <td><strong>${bandwidth}</strong></td>
                <td class="text-muted">${lastSeen}</td>
            </tr>
        `;
    }).join('');
}

// ===========================
// 4. Main Update Loop
// ===========================

/**
 * Refresh all dashboard data
 */
async function refreshDashboard() {
    if (isPaused) return;
    
    try {
        // Update all sections in parallel
        await Promise.all([
            updateMetrics(),
            updateHealthScore(),
            updateBandwidthHistory(),
            updateProtocolDistribution(),
            updateTopDevices()
        ]);
        
        // Update timestamp
        updateLastUpdatedTime();
        
        // Update status indicator
        updateStatusIndicator('healthy');
        
    } catch (error) {
        console.error('Error refreshing dashboard:', error);
        updateStatusIndicator('error');
        showError('Failed to refresh dashboard data');
    }
}

/**
 * Start auto-refresh interval
 */
function startAutoRefresh() {
    if (refreshIntervalId) {
        clearInterval(refreshIntervalId);
    }
    
    refreshIntervalId = setInterval(refreshDashboard, REFRESH_INTERVAL);
    console.log(`Auto-refresh started (every ${REFRESH_INTERVAL}ms)`);
}

/**
 * Stop auto-refresh interval
 */
function stopAutoRefresh() {
    if (refreshIntervalId) {
        clearInterval(refreshIntervalId);
        refreshIntervalId = null;
        console.log('Auto-refresh stopped');
    }
}

// ===========================
// 5. Event Listeners
// ===========================

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Manual refresh button
    if (elements.refreshButton) {
        elements.refreshButton.addEventListener('click', async () => {
            elements.refreshButton.disabled = true;
            await refreshDashboard();
            setTimeout(() => {
                elements.refreshButton.disabled = false;
            }, 1000);
        });
    }
    
    // Pause/resume on visibility change
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            isPaused = true;
            console.log('Dashboard paused (tab hidden)');
        } else {
            isPaused = false;
            refreshDashboard(); // Immediate refresh when tab becomes visible
            console.log('Dashboard resumed');
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // R key to refresh
        if (e.key === 'r' || e.key === 'R') {
            if (!e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                refreshDashboard();
            }
        }
    });
}

// ===========================
// 6. Helper Functions
// ===========================

/**
 * Update a value with animation
 */
function updateValue(element, newValue) {
    if (!element) return;
    
    const oldValue = element.textContent;
    if (oldValue !== String(newValue)) {
        element.classList.add('updated');
        element.textContent = newValue;
        
        setTimeout(() => {
            element.classList.remove('updated');
        }, 500);
    }
}

/**
 * Update last updated timestamp
 */
function updateLastUpdatedTime() {
    if (elements.lastUpdated) {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        elements.lastUpdated.textContent = `Last updated: ${timeString}`;
    }
}

/**
 * Update status indicator
 */
function updateStatusIndicator(status) {
    if (elements.statusDot) {
        elements.statusDot.classList.remove('healthy', 'warning', 'critical');
        elements.statusDot.classList.add(status);
    }
}

/**
 * Show loading state
 */
function showLoadingState() {
    if (elements.loadingOverlay) {
        elements.loadingOverlay.style.display = 'flex';
    }
}

/**
 * Hide loading state
 */
function hideLoadingState() {
    if (elements.loadingOverlay) {
        elements.loadingOverlay.style.display = 'none';
    }
}

/**
 * Show error notification
 */
function showError(message) {
    console.error(message);
    // You could implement a toast notification here
    // For now, just console.error
}

/**
 * Format last seen time
 */
function formatLastSeen(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    
    if (diffSecs < 60) {
        return 'Just now';
    } else if (diffMins < 60) {
        return `${diffMins} min ago`;
    } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else {
        return date.toLocaleDateString();
    }
}

/**
 * Check if device is active (seen in last 5 minutes)
 */
function isDeviceActive(lastSeen) {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / (1000 * 60));
    return diffMins < 5;
}

// ===========================
// 7. Initialize on DOM Ready
// ===========================
document.addEventListener('DOMContentLoaded', initDashboard);
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});