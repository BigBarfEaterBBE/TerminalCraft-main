import socket
import logging
import select
import json
import time
import os
import importlib.util
import base64
from hashlib import sha256
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

#discover constants
DISCOVERY_PORT = 55556
DISCOVERY_MSG = "CLIPPER_PEER_QUERY_V1"



#E2EE FUNCTIONS
def derive_key(secret_key):
    #Derives fernet encryption key from user's PSK
    #Use PBKDF2 derived from PSK to be consistent across devices
    if not secret_key:
        raise ValueError("Secret key cannot be empty")
    salt = sha256(secret_key.encode()).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=4800,
    )
    key = base64.urlsafe_b64decode(kdf.derive(secret_key.encode()))
    return key

#DATA FUNCTIONS

def send_data(ip_address,port,payload_type, payload_data):
    config = config_manager.load_config()
    secret_key = config.get('secret_key', '')
    if not secret_key:
        logging.error("[NETWORK] Cannot send data. Secret key is not configured.")
        return False
    try:
        #derive encryption key
        key = derive_key(secret_key)
        f = Fernet(key)

        #encrypt payload data
        if payload_type=="CLIP_SYNC" or payload_type.endswith("_RESPONSE"):
            data_to_encrypt =json.dumps(payload_data) if isinstance(payload_data, list) else str(payload_data)
            encrypted_data = f.encrypt(data_to_encrypt.encode('utf-8')).decode('utf-8')
        else:
            #for HISTORY_REQUEST skip encryption
            encrypted_data = json.dumps(payload_data)
    except Exception as e:
        logging.error(f"[NETWORK] Failed to encrypt payload. Error: {e}")
        return False

    #PREPARE PAYLOAD
    try:
        json_payload = json.dumps({
            "type": payload_type,
            "data": encrypted_data
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

def receive_data(listener_socket):
    #checks listener for incoming connection, reads data, + returns str
    #use elect to check if listener has pending connection
    ready_to_read, _, _ = select.select([listener_socket], [], [], 0)
    if not ready_to_read:
        return None
    conn = None
    try:
        conn, addr = listener_socket.accept() #addr is (ip, port)
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
        secret_key = config.get('secret_key', '')
        expected_key = secret_key.encode('utf-8')


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
        
        p_type = payload['type']
        encrypted_data = payload['data']
        if p_type == "CLIP_SYNC" or p_type.endswith("_RESPONSE"):
            key = derive_key(secret_key)
            f = Fernet(key)
            decrypted_bytes = f.decrypt(encrypted_data.encode('utf-8'))
            decrypted_data = decrypted_bytes.decode('utf-8')
            #if data was a list (for history) need to load back from JSON
            if p_type.endswith("_RESPONSE") and decrypted_data.startswith('['):
                payload['data'] = json.loads(decrypted_data)
            else:
                payload['data'] = decrypted_data
            logging.info(f"[NETWORK] Successfully decrypted payload: {p_type}") 
        payload['source_ip'] = addr[0]
        return payload
    except InvalidToken:
        logging.error(f"[NETWORK] Successfully decoded payload: {p_type}")
        return None
    except socket.timeout:
        logging.warning("[NETWORK] Connection timeout during data reception")
        return None
    except socket.error as e:
        logging.warning(f"[NETWORK] Socket error during recieve: {e}")
        return None
        
    except Exception as e:
        logging.error(f"[NETWORK] Unhandled error during data reception: {e}")
        return None
        
    finally:
        if conn:
            conn.close()


#LISTENING FUNCTIONS

def start_discovery_listener(ip_address='0.0.0.0'):
    #non-blocking UDP socket to listen for peer broadcasts
    try:
        disc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        disc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        disc_socket.bind((ip_address, DISCOVERY_PORT))
        disc_socket.setblocking(False)
        return disc_socket
    except Exception as e:
        logging.error(f"[DISCOVER] Could not start up UDP listener on port {DISCOVERY_PORT}: {e}")
        return None

def send_discovery_broadcast(listen_port):
    #broadcast discovery msg to find peers on local network
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        payload = f"{DISCOVERY_MSG}:{listen_port}".encode('utf-8')
        sock.sendto(payload, ('<broadcast', DISCOVERY_PORT))
        sock.close()
        #logging.debug("[DEBUG] Broadcast sent")
    except Exception as e:
        logging.warning(f"[DISCOVERY] Failed to send broadcast: {e}")

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
    

