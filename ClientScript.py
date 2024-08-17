import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.100.50', 12345))  # Replace 'Server_IP' with the server VM's IP address
client_socket.sendall(b'Hello, server!')
client_socket.close()
