/*
charts.js - Chart.js Chart Definitions
========================================

This module creates and updates Chart.js charts for the dashboard.

OWNER: Member 3 (Frontend Developer)
*/

// ===========================
// 1. Chart Configuration
// ===========================

const CHART_COLORS = {
   primary: '#3b82f6',
   success: '#10b981',
   warning: '#f59e0b',
   danger: '#ef4444',
   purple: '#8b5cf6',
   cyan: '#06b6d4',
   pink: '#ec4899',
   orange: '#f97316',
   teal: '#14b8a6',
   indigo: '#6366f1'
};

const PROTOCOL_COLORS = {
   'HTTP': CHART_COLORS.primary,
   'HTTPS': CHART_COLORS.success,
   'DNS': CHART_COLORS.warning,
   'SSH': CHART_COLORS.purple,
   'FTP': CHART_COLORS.orange,
   'SMTP': CHART_COLORS.cyan,
   'TCP': CHART_COLORS.pink,
   'UDP': CHART_COLORS.teal,
   'ICMP': CHART_COLORS.indigo,
   'Other': '#64748b'
};

const DEFAULT_CHART_OPTIONS = {
   responsive: true,
   maintainAspectRatio: false,
   animation: {
       duration: 750,
       easing: 'easeInOutQuart'
   },
   plugins: {
       legend: {
           labels: {
               color: '#f1f5f9',
               font: {
                   size: 12
               }
           }
       },
       tooltip: {
           backgroundColor: 'rgba(15, 23, 42, 0.9)',
           titleColor: '#f1f5f9',
           bodyColor: '#f1f5f9',
           borderColor: '#3b82f6',
           borderWidth: 1,
           padding: 12,
           displayColors: true,
           titleFont: {
               size: 14,
               weight: 'bold'
           },
           bodyFont: {
               size: 13
           }
       }
   }
};

// ===========================
// 2. Chart Instances
// ===========================

let bandwidthChart = null;
let protocolChart = null;

// ===========================
// 3. Chart Creation Functions
// ===========================

/**
* Create bandwidth history line chart
* @param {string} canvasId - ID of the canvas element
* @returns {Chart} - Chart.js instance
*/
function createBandwidthChart(canvasId) {
   const ctx = document.getElementById(canvasId);
   if (!ctx) {
       console.error(`Canvas element ${canvasId} not found`);
       return null;
   }

   const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 400);
   gradient.addColorStop(0, 'rgba(59, 130, 246, 0.3)');
   gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');

   bandwidthChart = new Chart(ctx, {
       type: 'line',
       data: {
           labels: [],
           datasets: [{
               label: 'Bandwidth (MB/s)',
               data: [],
               borderColor: CHART_COLORS.primary,
               backgroundColor: gradient,
               borderWidth: 2,
               fill: true,
               tension: 0.4,
               pointRadius: 3,
               pointHoverRadius: 6,
               pointBackgroundColor: CHART_COLORS.primary,
               pointBorderColor: '#fff',
               pointBorderWidth: 2
           }]
       },
       options: {
           ...DEFAULT_CHART_OPTIONS,
           scales: {
               x: {
                   grid: {
                       color: 'rgba(51, 65, 85, 0.3)',
                       drawBorder: false
                   },
                   ticks: {
                       color: '#94a3b8',
                       maxRotation: 0,
                       autoSkipPadding: 20
                   }
               },
               y: {
                   beginAtZero: true,
                   grid: {
                       color: 'rgba(51, 65, 85, 0.3)',
                       drawBorder: false
                   },
                   ticks: {
                       color: '#94a3b8',
                       callback: function(value) {
                           return value.toFixed(2) + ' MB/s';
                       }
                   }
               }
           },
           plugins: {
               ...DEFAULT_CHART_OPTIONS.plugins,
               tooltip: {
                   ...DEFAULT_CHART_OPTIONS.plugins.tooltip,
                   callbacks: {
                       label: function(context) {
                           return `Bandwidth: ${context.parsed.y.toFixed(2)} MB/s`;
                       }
                   }
               }
           }
       }
   });

   return bandwidthChart;
}

/**
* Create protocol distribution doughnut chart
* @param {string} canvasId - ID of the canvas element
* @returns {Chart} - Chart.js instance
*/
function createProtocolChart(canvasId) {
   const ctx = document.getElementById(canvasId);
   if (!ctx) {
       console.error(`Canvas element ${canvasId} not found`);
       return null;
   }

   protocolChart = new Chart(ctx, {
       type: 'doughnut',
       data: {
           labels: [],
           datasets: [{
               label: 'Packets',
               data: [],
               backgroundColor: [],
               borderColor: '#0f172a',
               borderWidth: 2,
               hoverOffset: 10
           }]
       },
       options: {
           ...DEFAULT_CHART_OPTIONS,
           cutout: '60%',
           plugins: {
               ...DEFAULT_CHART_OPTIONS.plugins,
               legend: {
                   position: 'right',
                   labels: {
                       color: '#f1f5f9',
                       padding: 15,
                       font: {
                           size: 12
                       },
                       generateLabels: function(chart) {
                           const data = chart.data;
                           if (data.labels.length && data.datasets.length) {
                               const total = data.datasets[0].data.reduce((a, b) => a + b, 0);
                               return data.labels.map((label, i) => {
                                   const value = data.datasets[0].data[i];
                                   const percentage = ((value / total) * 100).toFixed(1);
                                   return {
                                       text: `${label}: ${percentage}%`,
                                       fillStyle: data.datasets[0].backgroundColor[i],
                                       hidden: false,
                                       index: i
                                   };
                               });
                           }
                           return [];
                       }
                   }
               },
               tooltip: {
                   ...DEFAULT_CHART_OPTIONS.plugins.tooltip,
                   callbacks: {
                       label: function(context) {
                           const label = context.label || '';
                           const value = context.parsed;
                           const total = context.dataset.data.reduce((a, b) => a + b, 0);
                           const percentage = ((value / total) * 100).toFixed(1);
                           return `${label}: ${value.toLocaleString()} packets (${percentage}%)`;
                       }
                   }
               }
           }
       }
   });

   return protocolChart;
}

// ===========================
// 4. Chart Update Functions
// ===========================

/**
* Update bandwidth chart with new data
* @param {Chart} chart - Chart.js instance
* @param {Array} historyData - Array of {timestamp, bytes_per_second} objects
*/
function updateBandwidthChart(chart, historyData) {
   if (!chart || !historyData) {
       console.warn('Chart or data not available');
       return;
   }

   // Extract and format data
   const labels = historyData.map(item => formatTimestamp(item.timestamp));
   const data = historyData.map(item => item.bytes_per_second / (1024 * 1024)); // Convert to MB/s

   // Update chart
   chart.data.labels = labels;
   chart.data.datasets[0].data = data;
   chart.update('none'); // Use 'none' mode for smoother updates
}

/**
* Update protocol chart with new data
* @param {Chart} chart - Chart.js instance
* @param {Array} protocolData - Array of {protocol, count} objects
*/
function updateProtocolChart(chart, protocolData) {
   if (!chart || !protocolData) {
       console.warn('Chart or data not available');
       return;
   }

   // Extract and format data
   const labels = protocolData.map(item => item.protocol);
   const data = protocolData.map(item => item.count);
   const colors = protocolData.map(item => getProtocolColor(item.protocol));

   // Update chart
   chart.data.labels = labels;
   chart.data.datasets[0].data = data;
   chart.data.datasets[0].backgroundColor = colors;
   chart.update('none');
}

// ===========================
// 5. Utility Functions
// ===========================

/**
* Format bytes to human-readable string
* @param {number} bytes - Number of bytes
* @param {number} decimals - Number of decimal places
* @returns {string} - Formatted string (e.g., "1.5 MB")
*/
function formatBytes(bytes, decimals = 2) {
   if (bytes === 0) return '0 Bytes';

   const k = 1024;
   const dm = decimals < 0 ? 0 : decimals;
   const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

   const i = Math.floor(Math.log(bytes) / Math.log(k));

   return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
* Format timestamp for chart labels
* @param {string} timestamp - ISO timestamp string
* @returns {string} - Formatted time (HH:MM:SS)
*/
function formatTimestamp(timestamp) {
   const date = new Date(timestamp);
   const hours = String(date.getHours()).padStart(2, '0');
   const minutes = String(date.getMinutes()).padStart(2, '0');
   const seconds = String(date.getSeconds()).padStart(2, '0');
   return `${hours}:${minutes}:${seconds}`;
}

/**
* Get consistent color for protocol
* @param {string} protocolName - Protocol name
* @returns {string} - Hex color code
*/
function getProtocolColor(protocolName) {
   return PROTOCOL_COLORS[protocolName] || PROTOCOL_COLORS['Other'];
}

/**
* Format number with thousands separator
* @param {number} num - Number to format
* @returns {string} - Formatted number
*/
function formatNumber(num) {
   return num.toLocaleString();
}

// ===========================
// 6. Export Functions
// ===========================

if (typeof window !== 'undefined') {
   window.NetWatchCharts = {
       createBandwidthChart,
       createProtocolChart,
       updateBandwidthChart,
       updateProtocolChart,
       formatBytes,
       formatTimestamp,
       formatNumber,
       getBandwidthChart: () => bandwidthChart,
       getProtocolChart: () => protocolChart
   };
}