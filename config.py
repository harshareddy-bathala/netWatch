# NetWatch Configuration
# This file contains all configuration constants for the NetWatch system.
# Modify these values to customize the behavior of the application.

import os

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# Path to the SQLite database file
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch.db")

# Database connection timeout in seconds
DATABASE_TIMEOUT = 30

# =============================================================================
# NETWORK INTERFACE CONFIGURATION
# =============================================================================

# Default network interface for packet capture
# Windows: Use interface name like "Ethernet" or "Wi-Fi"
# Linux: Use interface name like "eth0", "wlan0", "enp0s3"
# Set to None for Scapy to auto-detect
NETWORK_INTERFACE = None

# Number of packets to capture in each batch (0 = continuous)
PACKET_BATCH_SIZE = 0

# Packet capture timeout in seconds (None = no timeout)
CAPTURE_TIMEOUT = None

# =============================================================================
# FLASK SERVER CONFIGURATION
# =============================================================================

# Host address for the Flask server
FLASK_HOST = "0.0.0.0"

# Port number for the Flask server
FLASK_PORT = 5000

# Enable Flask debug mode (set to False in production)
FLASK_DEBUG = True

# =============================================================================
# ANOMALY DETECTION THRESHOLDS
# =============================================================================

# Bandwidth threshold in bytes per second to trigger warning
BANDWIDTH_WARNING_THRESHOLD = 10_000_000  # 10 MB/s

# Bandwidth threshold in bytes per second to trigger critical alert
BANDWIDTH_CRITICAL_THRESHOLD = 50_000_000  # 50 MB/s

# Number of active devices threshold to trigger warning
DEVICE_COUNT_WARNING = 50

# Number of active devices threshold to trigger critical alert
DEVICE_COUNT_CRITICAL = 100

# Isolation Forest contamination parameter (expected proportion of anomalies)
ISOLATION_FOREST_CONTAMINATION = 0.1

# Minimum number of samples before running anomaly detection
MIN_SAMPLES_FOR_ANOMALY_DETECTION = 100

# =============================================================================
# HEALTH SCORE CONFIGURATION
# =============================================================================

# Weights for health score calculation (must sum to 1.0)
HEALTH_WEIGHT_BANDWIDTH = 0.3
HEALTH_WEIGHT_PACKET_LOSS = 0.25
HEALTH_WEIGHT_LATENCY = 0.25
HEALTH_WEIGHT_ANOMALIES = 0.2

# Health score thresholds
HEALTH_SCORE_GOOD = 80  # Score >= 80 is "Good"
HEALTH_SCORE_WARNING = 50  # Score >= 50 and < 80 is "Warning"
# Score < 50 is "Critical"

# =============================================================================
# DATA RETENTION CONFIGURATION
# =============================================================================

# Number of hours to keep detailed traffic data
TRAFFIC_DATA_RETENTION_HOURS = 24

# Number of days to keep alerts
ALERT_RETENTION_DAYS = 7

# Maximum number of records to keep in traffic_summary table
MAX_TRAFFIC_RECORDS = 1_000_000

# =============================================================================
# REFRESH INTERVALS (in seconds)
# =============================================================================

# How often the anomaly detector should run
ANOMALY_CHECK_INTERVAL = 60

# How often to aggregate traffic statistics
STATS_AGGREGATION_INTERVAL = 60

# How often the frontend should poll for updates (used in documentation)
FRONTEND_REFRESH_INTERVAL = 3

# =============================================================================
# PROTOCOL PORT MAPPINGS
# =============================================================================

PROTOCOL_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "INFO"

# Log file path (None = console only)
LOG_FILE = None

# Log format string
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
