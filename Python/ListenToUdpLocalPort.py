import socket

def listen_udp(port):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the specified port
    sock.bind(('localhost', port))

    print(f"Listening for UDP messages on port {port}...")

    while True:
        # Receive data from the socket
        data, addr = sock.recvfrom(1024)

        # Decode the received data as text
        message = data.decode('utf-8')

        # Display the received message
        print(f"Received message: {message}")

# Call the function to start listening on UDP port 5505
listen_udp(5505)