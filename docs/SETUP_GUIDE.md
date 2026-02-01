# NetWatch Setup Guide

This guide provides step-by-step instructions for setting up NetWatch on Windows, macOS, and Linux.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Windows Setup](#windows-setup)
3. [macOS Setup](#macos-setup)
4. [Linux Setup](#linux-setup)
5. [Virtual Environment Setup](#virtual-environment-setup)
6. [Database Initialization](#database-initialization)
7. [Running NetWatch](#running-netwatch)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before installing NetWatch, ensure you have:

| Requirement | Minimum Version | Check Command |
|-------------|-----------------|---------------|
| Python | 3.10+ | `python --version` |
| pip | 21.0+ | `pip --version` |
| Git | 2.0+ | `git --version` |
| Admin Rights | Required | For packet capture |

**Disk Space:** ~200 MB for dependencies + database storage

---

## Windows Setup

### Step 1: Install Python

1. Download Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. Run the installer
3. **IMPORTANT:** Check "Add Python to PATH"
4. Click "Install Now"

Verify installation:
```powershell
python --version
# Should show: Python 3.10.x or higher
```

### Step 2: Install Npcap (Required for Scapy)

Scapy requires Npcap on Windows for packet capture:

1. Download Npcap from [npcap.com](https://npcap.com/#download)
2. Run the installer
3. Check "Install Npcap in WinPcap API-compatible Mode"
4. Complete installation

### Step 3: Clone the Repository

```powershell
cd C:\Users\YourName\Projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
```

### Step 4: Create Virtual Environment

```powershell
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt.

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Initialize Database

```powershell
python database/init_db.py
```

### Step 7: Run NetWatch (As Administrator)

**IMPORTANT:** You must run as Administrator for packet capture.

1. Right-click on PowerShell or Command Prompt
2. Select "Run as Administrator"
3. Navigate to project folder
4. Activate virtual environment
5. Run:

```powershell
cd C:\Users\YourName\Projects\netwatch
venv\Scripts\activate
python main.py
```

---

## macOS Setup

### Step 1: Install Homebrew (if not installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2: Install Python

```bash
brew install python@3.10
```

Verify installation:
```bash
python3 --version
```

### Step 3: Clone the Repository

```bash
cd ~/Projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
```

### Step 4: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Initialize Database

```bash
python database/init_db.py
```

### Step 7: Run NetWatch (With sudo)

```bash
sudo python main.py
```

**Note:** You'll be prompted for your password. Scapy requires root privileges for packet capture.

---

## Linux Setup

### Ubuntu/Debian

#### Step 1: Update System and Install Python

```bash
sudo apt update
sudo apt install python3.10 python3.10-venv python3-pip git
```

#### Step 2: Install libpcap (Required for Scapy)

```bash
sudo apt install libpcap-dev
```

#### Step 3: Clone the Repository

```bash
cd ~/projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
```

#### Step 4: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

#### Step 6: Initialize Database

```bash
python database/init_db.py
```

#### Step 7: Run NetWatch (With sudo)

```bash
sudo $(which python) main.py
```

**Note:** Using `$(which python)` ensures sudo uses your virtual environment's Python.

---

### CentOS/RHEL/Fedora

#### Step 1: Install Python and Dependencies

```bash
# Fedora
sudo dnf install python3.10 python3-pip git libpcap-devel

# CentOS/RHEL
sudo yum install python3 python3-pip git libpcap-devel
```

Follow Steps 3-7 from Ubuntu section above.

---

## Virtual Environment Setup

### Why Use a Virtual Environment?

- Isolates project dependencies
- Prevents conflicts with system Python
- Makes the project reproducible

### Creating the Environment

```bash
# Create
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Deactivate (when done)
deactivate
```

### Verifying Activation

When activated, your prompt should show `(venv)`:
```
(venv) user@machine:~/netwatch$
```

---

## Database Initialization

The database must be initialized before first run:

```bash
# From project root
python database/init_db.py
```

This creates `netwatch.db` with all required tables.

### Resetting the Database

To start fresh (deletes all data):

```bash
python database/init_db.py --reset
```

---

## Running NetWatch

### Starting the Application

```bash
# Windows (Run as Administrator)
python main.py

# Linux/macOS
sudo python main.py
```

### Accessing the Dashboard

Once running, open your browser:
```
http://localhost:5000
```

### Stopping the Application

Press `Ctrl+C` in the terminal.

---

## Troubleshooting

### Common Issues

#### "Permission denied" or "Operation not permitted"

**Cause:** Packet capture requires admin/root privileges.

**Solution:**
- Windows: Run terminal as Administrator
- Linux/macOS: Use `sudo`

---

#### "No module named 'scapy'"

**Cause:** Dependencies not installed or wrong Python.

**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Reinstall dependencies
pip install -r requirements.txt
```

---

#### "Npcap not installed" (Windows)

**Cause:** Scapy needs Npcap on Windows.

**Solution:** Download and install Npcap from [npcap.com](https://npcap.com)

---

#### "No interface available" or "Cannot find interface"

**Cause:** Wrong network interface configured.

**Solution:**
1. List available interfaces:
   ```python
   from scapy.all import get_if_list
   print(get_if_list())
   ```
2. Update `NETWORK_INTERFACE` in `config.py`

---

#### "Address already in use" (Port 5000)

**Cause:** Another application is using port 5000.

**Solution:**
1. Find and stop the other application, OR
2. Change `FLASK_PORT` in `config.py`

---

#### "Database is locked"

**Cause:** Multiple processes accessing SQLite.

**Solution:**
1. Stop all NetWatch processes
2. Delete `netwatch.db`
3. Re-initialize: `python database/init_db.py`

---

### Getting Help

1. Check this troubleshooting section
2. Read the [ARCHITECTURE.md](ARCHITECTURE.md) for system understanding
3. Ask your Project Lead (Member 1)
4. Use AI assistance with specific error messages

---

## Next Steps

After successful setup:

1. Read [USER_MANUAL.md](USER_MANUAL.md) to learn the dashboard
2. Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand the system
3. Read your role-specific guide in `docs/guides/`
