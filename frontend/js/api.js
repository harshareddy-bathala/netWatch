/*
api.js - API Communication Module
===================================

This module handles all fetch() calls to the backend API.
*/

const API_BASE_URL = 'http://localhost:5000/api';

/**
 * Helper function to make API calls
 * @param {string} endpoint - API endpoint path
 * @param {object} options - Fetch options
 * @returns {Promise<{success: boolean, data: any, error: string}>}
 */
async function fetchApi(endpoint, options = {}) {
    try {
        const response = await fetch(API_BASE_URL + endpoint, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        return {
            success: response.ok,
            data: response.ok ? data : null,
            error: response.ok ? null : data.error || 'Unknown error'
        };
    } catch (error) {
        console.error('API Error:', error);
        return {
            success: false,
            data: null,
            error: error.message
        };
    }
}

/**
 * Get system status
 * @returns {Promise<{status: string, uptime: number, version: string}>}
 */
async function getStatus() {
    return fetchApi('/status');
}

/**
 * Get realtime statistics
 * @returns {Promise<{bandwidth_bps: number, active_devices: number, packets_per_second: number}>}
 */
async function getRealtimeStats() {
    return fetchApi('/stats/realtime');
}

/**
 * Get top devices by bandwidth
 * @param {number} limit - Number of devices to return
 * @returns {Promise<{devices: Array}>}
 */
async function getTopDevices(limit = 10) {
    return fetchApi(`/devices/top?limit=${limit}`);
}

/**
 * Get protocol distribution
 * @param {number} hours - Number of hours of history
 * @returns {Promise<{protocols: Array}>}
 */
async function getProtocols(hours = 1) {
    return fetchApi(`/protocols?hours=${hours}`);
}

/**
 * Get bandwidth history
 * @param {number} hours - Number of hours of history
 * @returns {Promise<{history: Array}>}
 */
async function getBandwidthHistory(hours = 1) {
    return fetchApi(`/bandwidth/history?hours=${hours}`);
}

/**
 * Get system alerts
 * @param {number} limit - Maximum number of alerts
 * @param {string} severity - Filter by severity (info, warning, critical)
 * @returns {Promise<{alerts: Array}>}
 */
async function getAlerts(limit = 50, severity = null) {
    let url = `/alerts?limit=${limit}`;
    if (severity) {
        url += `&severity=${severity}`;
    }
    return fetchApi(url);
}

/**
 * Get network health score
 * @returns {Promise<{score: number, status: string, factors: object}>}
 */
async function getHealthScore() {
    return fetchApi('/health');
}

/**
 * Update device hostname
 * @param {string} ipAddress - Device IP address
 * @param {string} hostname - New hostname
 * @returns {Promise<{success: boolean, message: string}>}
 */
async function updateDeviceName(ipAddress, hostname) {
    return fetchApi('/devices/update-name', {
        method: 'POST',
        body: JSON.stringify({
            ip_address: ipAddress,
            hostname: hostname
        })
    });
}