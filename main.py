"""
main.py - NetWatch Application Entry Point
============================================

This is the main entry point for the NetWatch application.
It orchestrates and starts all other modules.

OWNER: Member 1 (Project Lead)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements for all modules:
   - from config import *
   - from database.init_db import initialize_database
   - from database.db_handler import *
   - from packet_capture.monitor import NetworkMonitor
   - from alerts.detector import AnomalyDetector
   - from backend.app import create_app

2. A main() function that:
   - Initializes the SQLite database by calling initialize_database()
   - Creates a NetworkMonitor instance and starts it in a background thread
   - Creates an AnomalyDetector instance and starts it in a background thread
   - Creates the Flask app using create_app()
   - Starts the Flask server on the configured host and port

3. Background thread management:
   - Use threading.Thread for background tasks
   - Set daemon=True so threads stop when main program exits
   - Handle graceful shutdown with signal handlers

4. Error handling:
   - Catch and log permission errors for packet capture
   - Catch database initialization errors
   - Provide helpful error messages to users

5. The if __name__ == "__main__": block to run main()

EXAMPLE STRUCTURE:
------------------
import threading
import signal
import sys
from config import *

def main():
    # Initialize database
    # Start packet capture thread
    # Start anomaly detector thread
    # Start Flask server

if __name__ == "__main__":
    main()
"""
