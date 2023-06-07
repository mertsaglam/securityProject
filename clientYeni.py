import socket
import json
from cryptography.hazmat.primitives import serialization


from part1 import load_public_key, verify_signature,public_private_generator

# Create public-private key pair for the client
client_username = input("Enter your username: ")
public_private_generator(client_username)

# Load client's public key
client_public_key = load_public_key(client_username + "_public.pem")
serialized_public_key = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    # Connect to the server
    server_address = ('localhost', 1234)
    client_socket.connect(server_address)
    print("Connected to {}:{}".format(*server_address))

    # Send the client's username and public key to the server
    client_data = {
        "username": client_username,
        "public_key": serialized_public_key.decode(),
    }
    client_socket.sendall(json.dumps(client_data).encode())

    # Receive the certificate from the server
    client_certificate = json.loads(client_socket.recv(4096).decode())

    # Verify the certificate
    server_public_key = load_public_key("server_public.pem")
    signature = client_certificate["signature"]
    client_public_key_bytes = client_certificate["client_public_key"].encode()
    verification_result = verify_signature(client_public_key_bytes, signature, server_public_key)

    if verification_result:
        print("Certificate verification successful")
        # Check if the server's public key matches the known server's public key
        if client_certificate["server_public_key"] == server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode():
            print("Server's public key match successful")
        else:
            print("Server's public key match failed")
    else:
        print("Certificate verification failed")

    client_socket.close()
