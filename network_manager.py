import socket
import logging
import select
import json
import time

#load config manager
try:
    import config_manager
except ImportError:
    logging.error("config_manager.py not found.")
    raise

#CONSTANTS
SEPARATOR = b"<CLIPPER_DELIMETER>"
#max size for clipboard date
MAX_CLIP_SIZE = 1024*1024
MAX_RECIEVE_BUFFER = MAX_CLIP_SIZE * 5

def send_data(ip_address,port,payload_type, payload_data):
    config = config_manager.load_config()
    secret_key = config.get('secret_key', '')
    if not secret_key:
        logging.error("[NETWORK] Cannot send data. Secret key is not configured.")
        return False
    #PREPARE PAYLOAD
    try:
        json_payload = json.dumps({
            "type": payload_type,
            "data": payload_data
        }).encode('utf-8')
        auth_key_b = secret_key.encode('utf-8')
        payload = auth_key_b + SEPARATOR + json_payload
    except Exception as e:
        logging.error(f"[NETWORK] Failed to encode payload. Error: {e}")
        return False
    #SEND DATA
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip_address,port))
        sock.sendall(payload)
        logging.info(f"[NETWORK] '{payload_type}' sent successfully to {ip_address}:{port}")
        return True
    except socket.timeout:
        logging.warning(f"[NETOWRK] Timeout connecting to {ip_address}:{port}")
        return False
    except socket.error as e:
        logging.warning(f"[NETWORK] Connection error sending data to {ip_address}:{port}. Error: {e}")
        return False
    except Exception as e:
        logging.error(f"[NETWORK] Unexpected error during transmission: {e}")
        return False
    finally:
        if sock:
            sock.close()


def start_listener(ip_address,port):
    #non-blocking TCP socket to listen for incoming connections
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #immediate resuse
        listener.setblocking(False)
        listener.bind((ip_address,port))
        listener.listen(5)
        listener.setblocking(False)
        return listener
    except Exception as e:
        print(f"Could not start listener on port {port}: {e}")
        return None
    


def receive_data(listener_socket):
    #checks listener for incoming connection, reads data, + returns str
    #use elect to check if listener has pending connection
    ready_to_read, _, _ = select.select([listener_socket], [], [], 0)
    if not ready_to_read:
        return None
    conn = None
    try:
        conn, addr = listener_socket.accept()
        conn.settimeout(5)
        print(f"[NETWORK]: Incoming connection from {addr[0]}:{addr[1]}")
        recieved_stream = conn.recv(MAX_RECIEVE_BUFFER)
        if SEPARATOR not in recieved_stream:
            logging.warning("[NETWORK] Recieved incomplete or malformed data stream")
            return None
        
        #split stream into PSK and payload
        auth_key_b, payload_data_b = recieved_stream.split(SEPARATOR, 1)
        #check PSK
        config = config_manager.load_config()
        expected_key = config.get('secret_key', '').encode('utf-8')

        if auth_key_b != expected_key:
            logging.warning(f"[NETWORK] Authentication failed for peer {addr[0]}. PSK mismatch")
            return None
        logging.info(f"[NETOWKR] Authentication successful for peer {addr[0]}")
        #DECODE JSON PAYLOAD
        payload_data = payload_data_b.decode('utf-8')
        payload = json.loads(payload_data)
        if not isinstance(payload,dict) or 'type' not in payload or 'data' not in payload:
            logging.warning("[NETWORK] Recieved valid PSK but invalid JSON payload structure")
            return None
        return payload
    except socket.timeout:
        logging.warning("[NETWORK] Connection timeout during data reception")
        return None
    except socket.error as e:
        logging.warning(f"[NETWORK] Socket error during recieve: {e}")
        return None
    except json.JSONDecodeError:
        logging.warning("[NETOWRK] Failed to decode JSON paload.")
        return None
    except Exception as e:
        logging.error(f"[NETWORK] Unhandled error during data reception: {e}")
        return None
    finally:
        if conn:
            conn.close()