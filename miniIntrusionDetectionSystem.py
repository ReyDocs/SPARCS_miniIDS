from alertSystem import alertSystem
from detectionEngine import detectionEngine
from packetCapture import packetCapture 
from trafficAnalyzer import trafficAnalyzer 
import queue
from scapy.all import IP, TCP
import pandas as pd
import numpy as np  # needed for feature arrays

class intrusionDetectionSystem:
    def __init__(self, interface='en0'):
        self.packet_capture = packetCapture()
        self.traffic_analyzer= trafficAnalyzer()
        self.detection_engine = detectionEngine()
        self.alert_system = alertSystem()
        
        self.interface = interface

        # --------------------------
        # Train anomaly detector from CSV
        # --------------------------
        try:
            df = pd.read_csv("simulated_auth_logs.csv")
            df['packet_size'] = df['status'].apply(lambda x: 1 if x == 'fail' else 0)
            packet_counts = df.groupby('ip_address').cumcount() + 1
            df['packet_rate'] = packet_counts
            df['byte_rate'] = packet_counts  # simple placeholder
            training_data = df[['packet_size', 'packet_rate', 'byte_rate']].values
            self.detection_engine.train_anomaly_detector(training_data)
            print("Anomaly detector trained from simulated_auth_logs.csv")
        except FileNotFoundError:
            print("simulated_auth_logs.csv not found. Anomaly detection will not work.")

    def start(self):
        print(f"Starting IDS on Interface {self.interface}")
        self.packet_capture.start_capture(self.interface)
        
        while True:
            try:
                packet=self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                
                if features:
                    threats = self.detection_engine.detect_threats(features)
                    
                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS.....")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = intrusionDetectionSystem()
    ids.start()