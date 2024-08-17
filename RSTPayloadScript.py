from scapy.all import *

def send_rst_with_large_payload(target_ip, target_port):
    # Define a larger payload
    large_payload = b'\x00\x01\x02\x03' * 50  # 200 bytes of payload
    
    # Create a packet with RST flag and the large payload
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags='R', seq=1, ack=1) / Raw(large_payload)
    
    # Print packet details
    print(f"Sending packet to {target_ip}:{target_port}")
    print(f"Payload (first 50 bytes): {large_payload[:50]}")
    print(f"Packet details:\n{packet.show(dump=True)}")
    
    # Send the packet
    send(packet, verbose=1)  # Set verbose to 1 to see the packet details

# Replace with the IP address of your target
target_ip = "192.168.100.50"  # The IP address of the VM running Suricata
target_port = 80

send_rst_with_large_payload(target_ip, target_port)
