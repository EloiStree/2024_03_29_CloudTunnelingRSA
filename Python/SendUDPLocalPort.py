import socket
import random
import time

def send_udp_message(message, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, ('localhost', port))
    sock.close()

port=9876
while True:
    random_binary = bytes([random.randint(0, 255) for _ in range(16)])    
    random_number = random.randint(0, 100)
    send_udp_message(f"UDPT:{random_number}:{str(random_number)}", port)
    time.sleep(3)
    send_udp_message(f'UDPT::{str(random_number)}', port)
    time.sleep(3)
    print("Sending random binary: "+str(random_binary))
    send_udp_message(random_binary, port)
    time.sleep(3)