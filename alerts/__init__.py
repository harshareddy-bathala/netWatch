"""
alerts package
==============

This package contains all alert-related functionality for NetWatch:
- Anomaly detection using machine learning
- Alert creation and management
- Alert severity classification and filtering

OWNER: Member 1 (Project Lead)
"""

import logging
from alerts.detector import AnomalyDetector
from alerts.alert_manager import (
    create_alert,
    create_bandwidth_alert,
    create_anomaly_alert,
    create_device_count_alert,
    get_recent_alerts,
    get_alert_by_id,
    update_alert_status,
    delete_alert,
    get_alerts_by_severity,
)

# Package metadata
__version__ = "1.0.0"
__author__ = "NetWatch Team"
__all__ = [
    # Classes
    "AnomalyDetector",
    
    # Functions
    "create_alert",
    "create_bandwidth_alert",
    "create_anomaly_alert",
    "create_device_count_alert",
    "get_recent_alerts",
    "get_alert_by_id",
    "update_alert_status",
    "delete_alert",
    "get_alerts_by_severity",
]

# Configure package logger
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())