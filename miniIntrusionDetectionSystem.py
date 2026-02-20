from alertSystem import alertSystem
from detectionEngine import detectionEngine
from packetCapture import packetCapture 
from trafficAnalyzer import trafficAnalyzer 
import queue
from scapy.all import IP, TCP

class intrusionDetectionSystem:
    def __init__(self, interface="Wi-Fi"):
        self.packet_capture = packetCapture()
        self.traffic_analyzer= trafficAnalyzer()
        self.detection_engine = detectionEngine()
        self.alert_system = alertSystem()
        
        self.interface = interface
    
    def start(self):
        print(f"Starting IDS on Interface {self.interface}")
        self.packet_capture.start_capture(self.interface)
        
        training_samples = []
        is_trained = False # Flag to prevent premature detection
        import time
        start_time = time.time()

        print("Phase 1: Collecting baseline traffic (5 seconds)...")
        
        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                
                if features:
                    # Check if we are still in the training phase
                    if not is_trained:
                        training_samples.append([
                            features['packet_size'],
                            features['packet_rate'],
                            features['byte_rate']
                        ])
                        
                        # Once we have 5 seconds of data, train the model
                        if time.time() - start_time > 5:
                            print(f"Training model on {len(training_samples)} packets...")
                            self.detection_engine.train_anomaly_detector(training_samples)
                            is_trained = True
                            print("Phase 2: IDS is now ACTIVE.")
                    
                    # Only run detection if the model is ready
                    else:
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