# Mini Intrusion Detection System using Python

A real-time Network Intrusion Detection System built with Python. This system uses Signature-based detection for known threats and Machine Learning (Isolation Forest) to identify network anomalies.

## Features:

**Live Packet Sniffing:** Captures IP/TCP traffic using Scapy.

**Hybrid Detection:** Utilizes Signature and Anomaly-based detection methods to identify threats.

**ML Anomaly:** Learns "normal" traffic patterns to spot unusual spikes.

**Interactive Dashboard:** Visualizes the logs and live security alerts.

**Automated Logging:** Saves detailed threat data to JSON-formatted logs and CSVs

## Installation and Setup:

**1.Requirements:**

**-Python 3.10 or higher**

**Npcap(Windows-only):** Required for raw packet capturing. Ensure "WinPcap API-compatible Mode" is checked during installation.

**2. Environment Setup**

    # Create and activate virtual environment
    python -m venv .venv
    .\.venv\Scripts\activate  # Windows
    source .venv/bin/activate # Mac/Linux

    # Install dependencies
    pip install -r requirements.txt
