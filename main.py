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

import threading
import signal
import sys
import logging
from config import *

# Will be filled in as modules are ready
from database.init_db import initialize_database
from packet_capture.monitor import NetworkMonitor
from alerts.detector import AnomalyDetector
from backend.app import create_app

logger = logging.getLogger(__name__)
shutdown_event = threading.Event()

def setup_logging():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT
    )

def signal_handler(signum, frame):
    logger.info("Shutdown signal received")
    shutdown_event.set()

def main():
    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Initializing database...")
    try:
        initialize_database()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)
    
    logger.info("Starting packet capture...")
    monitor = NetworkMonitor()
    monitor_thread = threading.Thread(target=monitor.run, daemon=True)
    monitor_thread.start()
    
    logger.info("Starting anomaly detector...")
    detector = AnomalyDetector()
    detector_thread = threading.Thread(target=detector.run, daemon=True)
    detector_thread.start()
    
    logger.info(f"Starting Flask server on {FLASK_HOST}:{FLASK_PORT}")
    app = create_app()
    try:
        app.run(host=FLASK_HOST, port=FLASK_PORT)
    except Exception as e:
        logger.error(f"Flask server failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()