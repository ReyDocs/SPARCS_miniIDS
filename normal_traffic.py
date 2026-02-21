# normal_traffic.py
from detectionEngine import detectionEngine

# Example: manually defined normal traffic features
normal_traffic_data = [
    [60, 10, 600],  # packet_size, packet_rate, byte_rate
    [70, 12, 840],
    [65, 8, 520],
    [75, 15, 1125]
]

engine = detectionEngine()
engine.train_anomaly_detector(normal_traffic_data)