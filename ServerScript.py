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
