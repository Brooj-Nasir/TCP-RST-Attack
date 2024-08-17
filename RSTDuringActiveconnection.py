
from scapy.all import *

# Define the IP and TCP layer parameters
# Here, we specify the source IP address and destination IP address
src_ip = "192.168.100.51"
dst_ip = "192.168.100.50"

# Create an IP layer with the specified source and destination addresses
ip = IP(src=src_ip, dst=dst_ip)
print(f"IP Layer: {ip.summary()}")

# Define the TCP layer parameters
# Here, we specify the source port, destination port, and the TCP flag
src_port = 12345
dst_port = 12345
tcp_flag = "R"  # 'R' indicates a TCP Reset (RST) flag

# Create a TCP layer with the specified parameters
tcp = TCP(sport=src_port, dport=dst_port, flags=tcp_flag)
print(f"TCP Layer: {tcp.summary()}")

# Create the packet by stacking the IP and TCP layers
pkt = ip/tcp
print(f"Packet: {pkt.summary()}")
