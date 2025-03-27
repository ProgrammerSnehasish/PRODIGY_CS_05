# Python Code for Network Packet Analyzer.  

from scapy.all import sniff, wrpcap, IP
import signal
import sys

# List to store captured packets
captured_packets = []
pcap_filename = "captured_packets.pcap"

# Function to process captured packets
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload

        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")
        print(f"Payload: {payload}\n")

        # Store packet in list
        captured_packets.append(packet)

# Signal handler to save packets on exit
def signal_handler(sig, frame):
    print("\nStopping packet sniffer...")
    if captured_packets:
        wrpcap(pcap_filename, captured_packets)
        print(f"Captured packets saved to {pcap_filename}")
    sys.exit(0)

# Bind signal handler for graceful exit
signal.signal(signal.SIGINT, signal_handler)

# Start sniffing packets
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
