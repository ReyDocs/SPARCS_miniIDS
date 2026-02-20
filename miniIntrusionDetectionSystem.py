from alertSystem import alertSystem
from detectionEngine import detectionEngine
from packetCapture import packetCapture 
from trafficAnalyzer import trafficAnalyzer 
import queue
from scapy.all import IP, TCP

class intrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        self.packet_capture = packetCapture()
        self.traffic_analyzer= trafficAnalyzer()
        self.detection_engine = detectionEngine()
        self.alert_system = alertSystem()
        
        self.interface = interface
    
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