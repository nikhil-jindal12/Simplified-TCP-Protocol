import os
import random
import string
from transport import TransportSocket, ReadMode

def generate_random_data(size):
    """
    Generate a random string of specified size.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def client_main():
    # Initialize the client socket
    client_socket = TransportSocket()
    client_socket.socket(sock_type="TCP_INITIATOR", port=54321, server_ip="127.0.0.1")

    # Send a file to the server
    file_name = "alice.txt"
    with open(file_name, "rb") as f:
        file_data = f.read()
        print(f"Client: Sending file '{file_name}' to the server...")
        client_socket.send(file_data)

    # Send randomly generated data to the server
    random_data = generate_random_data(128)
    print(f"Client: Sending randomly generated data to the server...")
    client_socket.send(random_data)

    # Receive data from the server
    print("Client: Waiting to receive data from the server...")
    buf = [b""]
    client_socket.recv(buf, 1024, flags=ReadMode.NO_FLAG)
    print(f"Client: Received data from server:\n{buf[0].decode()}")

    # Close the client socket
    client_socket.close()

if __name__ == "__main__":
    client_main()

