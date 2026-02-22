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

## How to run:

In order to execute the system, you need to open **two terminal windows.**

**Step 1: Start the IDS engine**

**Important:** You must run this terminal as an **Administrator** to allow packet sniffing.

    python miniIntrusionDetectionSystem.py

**Phase 1(5s):** The system collects baseline traffic. Try opening a website to generate data.

**Phase 2:** Monitoring becomes active.

**Step 2: Launching the Dashboard**

In a second terminal, type:

    streamlit run dashboard.py

## Additional Tip:

1. Make sure to have your `requirements.txt` file ready by running `pip freeze > requirements.txt` inside your `.venv`.

2. Network interface names differ depending on the operating system. Before running the IDS, ensure that the interface parameter in the code matches your system’s active network interface. Make sure to select **en0** interface for Mac and **Wi-Fi** interface for Windows.
