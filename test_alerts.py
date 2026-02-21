import numpy as np
from detectionEngine import detectionEngine
from alertSystem import alertSystem

# Initialize engine
engine = detectionEngine()
alerts = alertSystem(log_file="test_alerts.log")

# Train the anomaly detector with mock normal traffic
normal_traffic = np.array([
    [60, 10, 600],   # packet_size, packet_rate, byte_rate
    [70, 12, 840],
    [65, 8, 520]
])
engine.train_anomaly_detector(normal_traffic)

# Example features that will trigger signature-based alert
features = {
    'packet_size': 60,
    'packet_rate': 120,  # > 100 triggers SYN flood rule
    'byte_rate': 720,
    'tcp_flags': 2  # SYN flag
}

# Detect threats
threats = engine.detect_threats(features)

# Generate alerts
for threat in threats:
    packet_info = {
        'source_ip': '192.168.1.5',
        'destination_ip': '192.168.1.3'
    }
    alerts.generate_alert(threat, packet_info)

print("Alerts generated. Check test_alerts.log")