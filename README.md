# NetWatch - Intelligent Network Traffic Analysis System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

NetWatch is a real-time network traffic monitoring and analysis system designed for campus or LAN environments. It captures network packets, analyzes traffic patterns, identifies bandwidth-heavy devices, detects anomalies using machine learning, and displays everything on a live web dashboard.

**Key Features:**
- 🔍 Real-time packet capture and analysis
- 📊 Live dashboard with bandwidth charts and device statistics
- 🎯 Protocol detection (HTTP, HTTPS, DNS, SSH, FTP, etc.)
- 🏥 Network health score calculation (0-100)
- 🚨 Anomaly detection using Isolation Forest ML algorithm
- 📱 Responsive design for desktop, tablet, and mobile
- 💾 Local SQLite database - no cloud dependency

## Quick Start

### Prerequisites
- Python 3.10 or higher
- Administrator/root privileges (required for packet capture)
- Network interface access

### Installation

```bash
# Clone the repository
git clone https://github.com/your-team/netwatch.git
cd netwatch

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python database/init_db.py
```

### Running NetWatch

```bash
# Run with administrator privileges
# Windows (Run as Administrator):
python main.py

# Linux/Mac:
sudo python main.py
```

Once running, open your browser and navigate to: **http://localhost:5000**

## Project Structure

```
netWatch/
├── main.py                 # Application entry point
├── config.py               # Configuration constants
├── requirements.txt        # Python dependencies
├── alerts/                 # Anomaly detection module
│   ├── detector.py         # ML-based anomaly detector
│   └── alert_manager.py    # Alert creation and management
├── backend/                # Flask REST API
│   ├── app.py              # Flask application factory
│   └── routes.py           # API endpoint definitions
├── frontend/               # Web dashboard
│   ├── index.html          # Main dashboard
│   ├── devices.html        # Device list page
│   ├── alerts.html         # Alerts feed page
│   ├── css/styles.css      # Custom styles
│   └── js/                 # JavaScript modules
├── packet_capture/         # Network monitoring
│   ├── monitor.py          # Packet capture engine
│   ├── parser.py           # Packet parsing logic
│   └── protocols.py        # Protocol detection
├── database/               # Data layer
│   ├── schema.sql          # Database schema
│   ├── init_db.py          # Database initialization
│   └── db_handler.py       # Database operations
└── docs/                   # Documentation
    ├── ARCHITECTURE.md     # System architecture
    ├── API_DOCS.md         # API documentation
    ├── SETUP_GUIDE.md      # Installation guide
    ├── USER_MANUAL.md      # User guide
    └── guides/             # Team member guides
```

## Team

| Role | Responsibilities |
|------|-----------------|
| Project Lead | Integration, ML/Anomaly Detection, DevOps |
| Backend Developer | Flask REST API, Endpoints |
| Frontend Developer | Dashboard, Visualization |
| Packet Capture Dev | Network Monitoring, Scapy |
| Database + Docs | Data Layer, Documentation |

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [API Documentation](docs/API_DOCS.md)
- [Setup Guide](docs/SETUP_GUIDE.md)
- [User Manual](docs/USER_MANUAL.md)
- [Contributing Guidelines](docs/CONTRIBUTING.md)

## Tech Stack

- **Backend:** Python 3.10+, Flask, Scapy
- **Database:** SQLite
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
- **ML:** scikit-learn (Isolation Forest)
- **Data Processing:** pandas, numpy

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Scapy library for packet capture capabilities
- Chart.js for beautiful data visualizations
- Bootstrap for responsive UI components
