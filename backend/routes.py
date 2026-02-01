"""
routes.py - REST API Endpoint Definitions
==========================================

This module defines all REST API routes for the NetWatch backend.

OWNER: Member 2 (Backend Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from flask import jsonify, request
   - from database.db_handler import (
       get_realtime_stats, get_top_devices, get_protocol_distribution,
       get_bandwidth_history, get_alerts, get_health_score, update_device_name
     )

2. register_routes(app) function that registers all routes with the Flask app

3. API Endpoints to implement:

   GET /api/status
   - Returns: {"status": "running", "uptime": seconds, "version": "1.0.0"}
   
   GET /api/stats/realtime
   - Returns: {"bandwidth_bps": int, "active_devices": int, "packets_per_second": int}
   
   GET /api/devices/top
   - Query params: ?limit=10 (optional, default 10)
   - Returns: {"devices": [{"ip": str, "hostname": str, "bytes": int, "last_seen": str}]}
   
   GET /api/protocols
   - Query params: ?hours=1 (optional, default 1)
   - Returns: {"protocols": [{"name": str, "count": int, "bytes": int, "percentage": float}]}
   
   GET /api/bandwidth/history
   - Query params: ?hours=1 (optional, default 1)
   - Returns: {"history": [{"timestamp": str, "bytes_per_second": int}]}
   
   GET /api/alerts
   - Query params: ?limit=50, ?severity=warning (optional)
   - Returns: {"alerts": [{"id": int, "timestamp": str, "type": str, "severity": str, "message": str}]}
   
   GET /api/health
   - Returns: {"score": int, "status": "good|warning|critical", "factors": {...}}
   
   POST /api/devices/update-name
   - Request body: {"ip_address": str, "hostname": str}
   - Returns: {"success": true, "message": str}

4. Each route should:
   - Call the appropriate database function
   - Handle errors gracefully
   - Return proper HTTP status codes
   - Return JSON responses

EXAMPLE FUNCTION SIGNATURES:
----------------------------
def register_routes(app):
    @app.route('/api/status')
    def get_status():
        return jsonify({'status': 'running', 'version': '1.0.0'})
    
    @app.route('/api/stats/realtime')
    def get_realtime():
        stats = get_realtime_stats()
        return jsonify(stats)
    
    # ... more routes
"""
