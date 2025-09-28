import socket
import sys

def sent_data(ip_address: str, port:int, clipboard_data:str) -> bool:
    #Attempts to send clipboard data to a peer over a single TCP connection
    try:
        #encode string data to bytes
        payload_bytes = clipboard_data.encode("utf-8")
        payload_length = len(payload_bytes)
        #open a socket connection (AF_INET = IPv4, SOCK_STREAM = TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip_address, port))
            #send 8-byte length header
            length_header = payload_length.to_bytes(8,byteorder="big")
            s.sendall(length_header)
            #send data
            s.sendall(payload_bytes)
        return True
    except socket.timeout:
        print(f"Connection attempt to {ip_address}:{port} timed out")