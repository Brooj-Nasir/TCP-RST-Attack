from scapy.all import *
import time

# Define the target IP and port
target_ip = "192.168.100.50"  # Replace with the IP of your VM running Suricata
target_port = 80  # Replace with the port you want to target

# Define the number of packets and the interval
packet_count = 15  # Number of packets to send
interval = 0.1     # Interval between packets in seconds

# Create and send TCP RST packets
print(f"Starting RST flood attack on {target_ip}:{target_port}")
for i in range(packet_count):
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="R")
    send(pkt, verbose=0)
    print(f"Sent RST packet {i+1}/{packet_count}")
    time.sleep(interval)

print("Attack completed.")
