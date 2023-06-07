import socket
import threading
import json

from cryptography.hazmat.primitives import serialization

from part1 import public_private_generator, load_private_key, load_public_key, generate_signature

# Define the server address and port
server_address = ('localhost', 1234)

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Socket created")

# Bind the socket to the server address and port
s.bind(server_address)
print("Socket bound to {}:{}".format(*server_address))

# Listen for incoming connections
s.listen(5)
print("Socket is listening for connections")

# Server's public-private key pair
server_username = "server"
public_private_generator(server_username)
server_private_key = load_private_key(server_username + "_private.pem")
server_public_key = load_public_key(server_username + "_public.pem")

# Dictionary to store the certificates
certificates = {}


def handle_client(client_socket, client_address):
    while True:
        # Receive data from the client
        data = client_socket.recv(1024)
        if not data:
            # No more data from the client
            break

        # Parse the received JSON data
        json_data = json.loads(data.decode())
        client_username = json_data["username"]
        client_public_key = json_data["public_key"]

        # Generate a certificate for the client
        client_certificate = {
            "client_username": client_username,
            "client_public_key": client_public_key,
            "server_public_key": server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
        }

        # Sign the client's public key using the server's private key
        client_public_key_bytes = client_public_key.encode()
        signature = generate_signature(client_public_key_bytes, server_private_key)
        client_certificate["signature"] = signature.decode()

        # Store the certificate
        certificates[client_username] = client_certificate

        # Send the certificate to the client
        client_socket.sendall(json.dumps(client_certificate).encode())

    # Close the client connection
    client_socket.close()
    print("Connection closed with {}:{}".format(*client_address))


while True:
    # Accept a client connection
    client_socket, client_address = s.accept()
    print("Connected to {}:{}".format(*client_address))

    # Create a new thread for the client
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()
