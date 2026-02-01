/*
charts.js - Chart.js Chart Definitions
========================================

This module creates and updates Chart.js charts for the dashboard.

OWNER: Member 3 (Frontend Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Chart configuration objects:
   - Color schemes for charts
   - Default options (responsive, animation, etc.)
   - Tooltip formatting

2. Chart instances (global variables to allow updates):
   - let bandwidthChart = null
   - let protocolChart = null

3. Chart creation functions:

   createBandwidthChart(canvasId)
   - Creates a line chart for bandwidth over time
   - X-axis: Time (HH:MM format)
   - Y-axis: Bandwidth in MB/s
   - Smooth curved line
   - Gradient fill under line
   - Returns the Chart instance
   
   createProtocolChart(canvasId)
   - Creates a doughnut/pie chart for protocol distribution
   - Shows percentage of each protocol
   - Color-coded by protocol type
   - Legend on the side
   - Returns the Chart instance

4. Chart update functions:

   updateBandwidthChart(chart, historyData)
   - Takes bandwidth history array from API
   - Extracts timestamps and values
   - Updates chart.data.labels and chart.data.datasets[0].data
   - Calls chart.update()
   
   updateProtocolChart(chart, protocolData)
   - Takes protocol distribution array from API
   - Extracts names and counts
   - Updates chart labels and data
   - Calls chart.update()

5. Utility functions:
   - formatBytes(bytes): Convert bytes to KB/MB/GB string
   - formatTimestamp(timestamp): Format for chart labels
   - getProtocolColor(protocolName): Return consistent color for protocol

EXAMPLE STRUCTURE:
------------------
let bandwidthChart = null;

function createBandwidthChart(canvasId) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    bandwidthChart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Bandwidth', data: [] }] },
        options: { responsive: true, maintainAspectRatio: false }
    });
    return bandwidthChart;
}

function updateBandwidthChart(chart, historyData) {
    chart.data.labels = historyData.map(d => formatTimestamp(d.timestamp));
    chart.data.datasets[0].data = historyData.map(d => d.bytes_per_second / 1000000);
    chart.update();
}
*/
