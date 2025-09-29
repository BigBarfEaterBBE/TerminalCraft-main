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
    except ConnectionRefusedError:
        print(f"Connection to {ip_address}:{port} was refused")
    except Exception as e:
        print(f"Error during send to {ip_address}:{port}: {e}")
    
    return False
def start_listener(ip:str, port:int, max_connections: int = 1) -> socket.socket | None:
    #non-blocking TCP socket to listen for incoming connections
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) #immediate resuse
        listener.setblocking(False)
        listener.bind((ip,port))
        listener.listen(max_connections)
        return listener
    except Exception as e:
        print(f"Could not start listener on port {port}: {e}")
        return None
def receive_data(listener:socket.socket) -> str | None:
    #checks listener for incoming connection, reads data, + returns str
    try:
        conn, addr = listener.accept()
        print(f"[NETWORK]: Incoming connection from {addr[0]}:{addr[1]}")
        with conn:
            #1 recieve header
            length_header = conn.recv(8)
            if not length_header:
                return None
            payload_length = int.from_bytes(length_header, byteorder = "big")
            #2 recieve unencrypted payload
            recieved_bytes = b''
            bytes_recieved = 0
            while bytes_recieved < payload_length:
                chunk = conn.recv(payload_length - bytes_recieved)
                if not chunk:
                    break
                recieved_bytes += chunk
                bytes_recieved += len(chunk)
            if bytes_recieved == payload_length:
                return recieved_bytes.decode('utf-8')
            else:
                print("Recieved incomplete payload")
                return None
    except socket.error as e:
        #error when no connection is pending
        if e.errno in (10035, 11):
            return None
        elif hasattr(e, "winerror") and e.winerror == 10035:
            return None
        else:
            print(f"Socket error while reciever: {e}")
            return None
    except Exception as e:
        print(f"Error during recieve operation: {e}")
        return None