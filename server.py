import os
import random
import string
from transport import TransportSocket, ReadMode

def generate_random_data(size):
    """
    Generate a random string of specified size.
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def server_main():
    # Initialize the server socket
    server_socket = TransportSocket()
    server_socket.socket(sock_type="TCP_LISTENER", port=54321)

    # Receive data from the client
    print("Server: Waiting to receive data from the client...")
    buf = [b""]
    server_socket.recv(buf, 1024, flags=ReadMode.NO_FLAG)
    print(f"Server: Received data from client:\n{buf[0].decode()}")

    # Send a file to the client
    file_name = "server_data.txt"
    with open(file_name, "w") as f:
        f.write("This is a test file from the server.")
    
    with open(file_name, "rb") as f:
        file_data = f.read()
        print(f"Server: Sending file '{file_name}' to the client...")
        server_socket.send(file_data)

    # Send randomly generated data to the client
    random_data = generate_random_data(128)
    print(f"Server: Sending randomly generated data to the client...")
    server_socket.send(random_data)

    # Close the server socket
    server_socket.close()

if __name__ == "__main__":
    server_main()

