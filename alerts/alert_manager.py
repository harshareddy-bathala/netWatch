"""
alert_manager.py - Alert Creation and Management
=================================================

This module handles the creation, storage, and retrieval of system alerts.

OWNER: Member 1 (Project Lead)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from database.db_handler import create_alert as db_create_alert, get_alerts as db_get_alerts
   - from config import *
   - import logging

2. Alert severity constants:
   - SEVERITY_INFO = "info"
   - SEVERITY_WARNING = "warning"
   - SEVERITY_CRITICAL = "critical"

3. Alert type constants:
   - ALERT_BANDWIDTH = "bandwidth"
   - ALERT_ANOMALY = "anomaly"
   - ALERT_DEVICE_COUNT = "device_count"
   - ALERT_HEALTH = "health"

4. Functions:
   - create_alert(alert_type, severity, message): Create and save a new alert
   - create_bandwidth_alert(current_bandwidth, threshold): Create bandwidth threshold alert
   - create_anomaly_alert(details): Create ML-detected anomaly alert
   - get_recent_alerts(limit, severity_filter): Get recent alerts with optional filter
   - resolve_alert(alert_id): Mark an alert as resolved

5. The alert manager should:
   - Log all alerts that are created
   - Prevent duplicate alerts within a short time window
   - Provide formatted alert messages

EXAMPLE FUNCTION SIGNATURES:
----------------------------
def create_alert(alert_type: str, severity: str, message: str) -> int:
    '''Create a new alert and return its ID'''
    pass

def create_bandwidth_alert(current_bandwidth: float, threshold: float) -> int:
    '''Create a bandwidth threshold exceeded alert'''
    pass

def get_recent_alerts(limit: int = 50, severity_filter: str = None) -> list:
    '''Get recent alerts, optionally filtered by severity'''
    pass
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum

from config import (
    ALERT_RETENTION_DAYS,
    NOTIFICATION_THROTTLE_SECONDS,
    ALERT_SEVERITY_LOW,
    ALERT_SEVERITY_MEDIUM,
    ALERT_SEVERITY_HIGH,
    ALERT_SEVERITY_CRITICAL,
    LOG_LEVEL,
)

# Import database functions with graceful fallback
try:
    from database.db_handler import (
        execute_query,
        fetch_one,
        fetch_all,
        commit_transaction,
    )
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    logging.warning("Database module not available, alerts will be logged only")

# Configure module logger
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL))

# =============================================================================
# ALERT CONSTANTS
# =============================================================================

# Alert severity levels
SEVERITY_INFO = ALERT_SEVERITY_LOW
SEVERITY_WARNING = ALERT_SEVERITY_MEDIUM
SEVERITY_HIGH = ALERT_SEVERITY_HIGH
SEVERITY_CRITICAL = ALERT_SEVERITY_CRITICAL

# Alert types
ALERT_BANDWIDTH = "bandwidth"
ALERT_ANOMALY = "anomaly"
ALERT_DEVICE_COUNT = "device_count"
ALERT_HEALTH = "health"
ALERT_PACKET_LOSS = "packet_loss"
ALERT_LATENCY = "latency"

# Alert status
STATUS_ACTIVE = "active"
STATUS_ACKNOWLEDGED = "acknowledged"
STATUS_RESOLVED = "resolved"
STATUS_SUPPRESSED = "suppressed"

# In-memory alert deduplication cache
_alert_cache: Dict[str, datetime] = {}
_cache_lock = __import__('threading').Lock()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_alert_key(alert_type: str, severity: str, details: str) -> str:
    """
    Generate a unique key for alert deduplication.
    
    Args:
        alert_type: Type of alert
        severity: Severity level
        details: Details about the alert
        
    Returns:
        Unique key string
    """
    return f"{alert_type}_{severity}_{hash(details) % 10000}"


def _should_throttle_alert(alert_key: str) -> bool:
    """
    Check if an alert should be throttled based on recent history.
    
    Args:
        alert_key: Unique identifier for the alert
        
    Returns:
        True if alert was recently created, False otherwise
    """
    with _cache_lock:
        now = datetime.now()
        throttle_seconds = NOTIFICATION_THROTTLE_SECONDS
        
        if alert_key in _alert_cache:
            last_time = _alert_cache[alert_key]
            if (now - last_time).total_seconds() < throttle_seconds:
                return True
        
        _alert_cache[alert_key] = now
        return False


def _clean_old_cache_entries() -> None:
    """Remove old entries from alert cache."""
    with _cache_lock:
        now = datetime.now()
        cutoff = now - timedelta(hours=1)
        
        keys_to_delete = [
            key for key, time in _alert_cache.items()
            if time < cutoff
        ]
        
        for key in keys_to_delete:
            del _alert_cache[key]
        
        if keys_to_delete:
            logger.debug(f"Cleaned {len(keys_to_delete)} old alert cache entries")


def _format_alert_message(
    alert_type: str,
    severity: str,
    current_value: Optional[float] = None,
    threshold_value: Optional[float] = None,
    details: Optional[Dict] = None,
) -> str:
    """
    Format a human-readable alert message.
    
    Args:
        alert_type: Type of alert
        severity: Severity level
        current_value: Current metric value
        threshold_value: Threshold that was exceeded
        details: Additional details
        
    Returns:
        Formatted alert message
    """
    severity_label = severity.upper()
    
    if alert_type == ALERT_BANDWIDTH:
        if current_value and threshold_value:
            return (
                f"[{severity_label}] Bandwidth threshold exceeded: "
                f"{current_value / 1_000_000:.2f} MB/s "
                f"(threshold: {threshold_value / 1_000_000:.2f} MB/s)"
            )
        return f"[{severity_label}] Bandwidth anomaly detected"
    
    elif alert_type == ALERT_DEVICE_COUNT:
        if current_value and threshold_value:
            return (
                f"[{severity_label}] Device count threshold exceeded: "
                f"{int(current_value)} devices "
                f"(threshold: {int(threshold_value)})"
            )
        return f"[{severity_label}] Unusual device count detected"
    
    elif alert_type == ALERT_ANOMALY:
        if details and "anomaly_score" in details:
            score = details.get("anomaly_score", 0)
            return (
                f"[{severity_label}] Network anomaly detected "
                f"(confidence: {score:.1%})"
            )
        return f"[{severity_label}] Network anomaly detected"
    
    elif alert_type == ALERT_HEALTH:
        if current_value:
            return f"[{severity_label}] Network health score: {current_value:.0f}/100"
        return f"[{severity_label}] Network health alert"
    
    elif alert_type == ALERT_PACKET_LOSS:
        if current_value:
            return f"[{severity_label}] High packet loss detected: {current_value:.2f}%"
        return f"[{severity_label}] Packet loss detected"
    
    elif alert_type == ALERT_LATENCY:
        if current_value:
            return f"[{severity_label}] High latency detected: {current_value:.0f}ms"
        return f"[{severity_label}] Latency anomaly detected"
    
    else:
        return f"[{severity_label}] Alert: {alert_type}"


# =============================================================================
# CORE ALERT FUNCTIONS
# =============================================================================

def create_alert(
    alert_type: str,
    severity: str,
    message: str,
    details: Optional[Dict] = None,
) -> Optional[int]:
    """
    Create a new alert and save to database.
    
    Args:
        alert_type: Type of alert (bandwidth, anomaly, etc.)
        severity: Severity level (info, warning, high, critical)
        message: Alert message
        details: Additional details as dictionary
        
    Returns:
        Alert ID if successful, None otherwise
    """
    if not message:
        logger.error("Cannot create alert without message")
        return None

    # Check if we should throttle this alert
    alert_key = _get_alert_key(alert_type, severity, message)
    if _should_throttle_alert(alert_key):
        logger.debug(f"Alert throttled: {alert_key}")
        return None

    try:
        timestamp = datetime.now()
        details_json = json.dumps(details) if details else None

        # Log the alert
        logger.warning(f"Alert created [{alert_type}] {severity}: {message}")

        # Save to database if available
        if DB_AVAILABLE:
            query = """
                INSERT INTO alerts 
                (alert_type, severity, message, details, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            
            execute_query(
                query,
                (alert_type, severity, message, details_json, STATUS_ACTIVE, timestamp),
            )
            commit_transaction()
            
            # Get the last inserted ID
            result = fetch_one("SELECT last_insert_rowid() as id")
            alert_id = result[0] if result else None
            
            if alert_id:
                logger.info(f"Alert {alert_id} saved to database")
                return alert_id
        else:
            logger.warning("Database not available, alert not persisted")
            return None

    except Exception as e:
        logger.error(f"Error creating alert: {e}", exc_info=True)
        return None


def create_bandwidth_alert(
    current: float,
    threshold: float,
    severity: str = SEVERITY_WARNING,
) -> Optional[int]:
    """
    Create a bandwidth threshold exceeded alert.
    
    Args:
        current: Current bandwidth in bytes/s
        threshold: Threshold value in bytes/s
        severity: Alert severity
        
    Returns:
        Alert ID or None
    """
    message = _format_alert_message(
        ALERT_BANDWIDTH,
        severity,
        current_value=current,
        threshold_value=threshold,
    )
    
    details = {
        "current_bandwidth": current,
        "threshold_bandwidth": threshold,
        "percentage_over": ((current - threshold) / threshold * 100) if threshold > 0 else 0,
    }
    
    return create_alert(ALERT_BANDWIDTH, severity, message, details)


def create_anomaly_alert(
    severity: str = SEVERITY_HIGH,
    anomaly_score: float = 0.0,
    details: Optional[Dict] = None,
) -> Optional[int]:
    """
    Create a machine learning detected anomaly alert.
    
    Args:
        severity: Alert severity
        anomaly_score: Anomaly confidence score (0-1)
        details: Additional network statistics
        
    Returns:
        Alert ID or None
    """
    alert_details = {"anomaly_score": anomaly_score}
    if details:
        alert_details.update(details)
    
    message = _format_alert_message(
        ALERT_ANOMALY,
        severity,
        details=alert_details,
    )
    
    return create_alert(ALERT_ANOMALY, severity, message, alert_details)


def create_device_count_alert(
    current: int,
    threshold: int,
    severity: str = SEVERITY_WARNING,
) -> Optional[int]:
    """
    Create a device count threshold exceeded alert.
    
    Args:
        current: Current number of devices
        threshold: Threshold number
        severity: Alert severity
        
    Returns:
        Alert ID or None
    """
    message = _format_alert_message(
        ALERT_DEVICE_COUNT,
        severity,
        current_value=float(current),
        threshold_value=float(threshold),
    )
    
    details = {
        "current_device_count": current,
        "threshold_device_count": threshold,
        "percentage_over": ((current - threshold) / threshold * 100) if threshold > 0 else 0,
    }
    
    return create_alert(ALERT_DEVICE_COUNT, severity, message, details)


def create_health_alert(
    health_score: float,
    severity: str = SEVERITY_WARNING,
) -> Optional[int]:
    """
    Create a network health score alert.
    
    Args:
        health_score: Health score (0-100)
        severity: Alert severity
        
    Returns:
        Alert ID or None
    """
    message = _format_alert_message(
        ALERT_HEALTH,
        severity,
        current_value=health_score,
    )
    
    details = {
        "health_score": health_score,
        "health_status": _get_health_status(health_score),
    }
    
    return create_alert(ALERT_HEALTH, severity, message, details)


def create_packet_loss_alert(
    packet_loss_rate: float,
    severity: str = SEVERITY_WARNING,
) -> Optional[int]:
    """
    Create a packet loss alert.
    
    Args:
        packet_loss_rate: Packet loss percentage
        severity: Alert severity
        
    Returns:
        Alert ID or None
    """
    message = _format_alert_message(
        ALERT_PACKET_LOSS,
        severity,
        current_value=packet_loss_rate,
    )
    
    details = {"packet_loss_rate": packet_loss_rate}
    
    return create_alert(ALERT_PACKET_LOSS, severity, message, details)


def create_latency_alert(
    latency_ms: float,
    severity: str = SEVERITY_WARNING,
) -> Optional[int]:
    """
    Create a latency alert.
    
    Args:
        latency_ms: Latency in milliseconds
        severity: Alert severity
        
    Returns:
        Alert ID or None
    """
    message = _format_alert_message(
        ALERT_LATENCY,
        severity,
        current_value=latency_ms,
    )
    
    details = {"latency_ms": latency_ms}
    
    return create_alert(ALERT_LATENCY, severity, message, details)


def _get_health_status(score: float) -> str:
    """Get health status string from score."""
    if score >= 80:
        return "Good"
    elif score >= 50:
        return "Warning"
    else:
        return "Critical"


# =============================================================================
# ALERT RETRIEVAL AND MANAGEMENT
# =============================================================================

def get_recent_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    hours: int = 24,
) -> List[Dict]:
    """
    Get recent alerts with optional filtering.
    
    Args:
        limit: Maximum number of alerts to return
        severity: Filter by severity level
        status: Filter by status (active, resolved, etc.)
        hours: Only get alerts from last N hours
        
    Returns:
        List of alert dictionaries
    """
    if not DB_AVAILABLE:
        logger.warning("Database not available, cannot retrieve alerts")
        return []

    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        query = "SELECT * FROM alerts WHERE created_at >= ?"
        params = [cutoff_time]
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        results = fetch_all(query, params)
        
        alerts = []
        for row in results:
            alerts.append({
                "id": row[0],
                "alert_type": row[1],
                "severity": row[2],
                "message": row[3],
                "details": json.loads(row[4]) if row[4] else {},
                "status": row[5],
                "created_at": row[6],
                "updated_at": row[7],
            })
        
        return alerts

    except Exception as e:
        logger.error(f"Error retrieving recent alerts: {e}", exc_info=True)
        return []


def get_alert_by_id(alert_id: int) -> Optional[Dict]:
    """
    Get a specific alert by ID.
    
    Args:
        alert_id: Alert ID
        
    Returns:
        Alert dictionary or None
    """
    if not DB_AVAILABLE:
        logger.warning("Database not available")
        return None

    try:
        result = fetch_one(
            "SELECT * FROM alerts WHERE id = ?",
            [alert_id],
        )
        
        if result:
            return {
                "id": result[0],
                "alert_type": result[1],
                "severity": result[2],
                "message": result[3],
                "details": json.loads(result[4]) if result[4] else {},
                "status": result[5],
                "created_at": result[6],
                "updated_at": result[7],
            }
        
        return None

    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}", exc_info=True)
        return None


def get_alerts_by_severity(severity: str, limit: int = 100) -> List[Dict]:
    """
    Get alerts filtered by severity.
    
    Args:
        severity: Severity level
        limit: Maximum number to return
        
    Returns:
        List of alerts
    """
    return get_recent_alerts(limit=limit, severity=severity)


def update_alert_status(alert_id: int, status: str) -> bool:
    """
    Update an alert's status.
    
    Args:
        alert_id: Alert ID
        status: New status
        
    Returns:
        True if successful, False otherwise
    """
    if not DB_AVAILABLE:
        logger.warning("Database not available")
        return False

    if status not in [STATUS_ACTIVE, STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_SUPPRESSED]:
        logger.error(f"Invalid status: {status}")
        return False

    try:
        execute_query(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, datetime.now(), alert_id),
        )
        commit_transaction()
        
        logger.info(f"Alert {alert_id} status updated to {status}")
        return True

    except Exception as e:
        logger.error(f"Error updating alert {alert_id}: {e}", exc_info=True)
        return False


def delete_alert(alert_id: int) -> bool:
    """
    Delete an alert.
    
    Args:
        alert_id: Alert ID
        
    Returns:
        True if successful, False otherwise
    """
    if not DB_AVAILABLE:
        logger.warning("Database not available")
        return False

    try:
        execute_query("DELETE FROM alerts WHERE id = ?", [alert_id])
        commit_transaction()
        
        logger.info(f"Alert {alert_id} deleted")
        return True

    except Exception as e:
        logger.error(f"Error deleting alert {alert_id}: {e}", exc_info=True)
        return False


def get_alert_statistics(hours: int = 24) -> Dict:
    """
    Get alert statistics.
    
    Args:
        hours: Time period to analyze
        
    Returns:
        Dictionary with statistics
    """
    if not DB_AVAILABLE:
        logger.warning("Database not available")
        return {}

    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Total alerts
        total = fetch_one(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= ?",
            [cutoff_time],
        )
        total_count = total[0] if total else 0
        
        # By severity
        severity_counts = {}
        for sev in [SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_HIGH, SEVERITY_CRITICAL]:
            result = fetch_one(
                "SELECT COUNT(*) FROM alerts WHERE severity = ? AND created_at >= ?",
                [sev, cutoff_time],
            )
            severity_counts[sev] = result[0] if result else 0
        
        # By type
        type_counts = {}
        for atype in [ALERT_BANDWIDTH, ALERT_ANOMALY, ALERT_DEVICE_COUNT, ALERT_HEALTH]:
            result = fetch_one(
                "SELECT COUNT(*) FROM alerts WHERE alert_type = ? AND created_at >= ?",
                [atype, cutoff_time],
            )
            type_counts[atype] = result[0] if result else 0
        
        return {
            "total": total_count,
            "by_severity": severity_counts,
            "by_type": type_counts,
            "time_period_hours": hours,
        }

    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}", exc_info=True)
        return {}


def cleanup_old_alerts(days: int = ALERT_RETENTION_DAYS) -> int:
    """
    Delete alerts older than specified days.
    
    Args:
        days: Number of days to keep
        
    Returns:
        Number of alerts deleted
    """
    if not DB_AVAILABLE:
        logger.warning("Database not available")
        return 0

    try:
        cutoff_time = datetime.now() - timedelta(days=days)
        
        result = fetch_one(
            "SELECT COUNT(*) FROM alerts WHERE created_at < ?",
            [cutoff_time],
        )
        count = result[0] if result else 0
        
        execute_query(
            "DELETE FROM alerts WHERE created_at < ?",
            [cutoff_time],
        )
        commit_transaction()
        
        logger.info(f"Deleted {count} old alerts (older than {days} days)")
        
        # Clean cache too
        _clean_old_cache_entries()
        
        return count

    except Exception as e:
        logger.error(f"Error cleaning up old alerts: {e}", exc_info=True)
        return 0
