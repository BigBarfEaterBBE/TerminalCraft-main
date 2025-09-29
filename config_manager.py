import json
import os
from pathlib import Path
#configuration file management
def get_config_dir():
    '''
    returns platform-specific configuration directory path
    keeps config seperate from application files
    '''
    if os.name == "nt": #windoes
        # use APPDATA enviro variable for Windows
        path = Path(os.getenv("APPDATA")) /"Clipper"
    else: #unix/mac
        #Follow XDG
        path = Path.home() /"config." /"clipper"
    
    #create dir if doesnt exist
    path.mkdir(parents = True,exist_ok = True)
    return path
#golbals
CONFIG_FILE = get_config_dir() /"config.json"


def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {
            "secret_key": None,
            "listen_port": 55555,
            #prevent sync loop
            "last_synced_content": "",
            "peer_ips": ["127.0.0.1"]
        }
    if "peer_ips" not in config:
        config["peer_ips"] = ["127.0.0.1"]
    return config

def save_config(config):
    #saves current configration to file
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent = 4)
        return True
    except IOError as e:
        print(f"Error saving configuration: {e}")
        return False

def set_secret_key(key):
    #Updates + saves secret key (PSK)
    config = load_config()
    config["secret_key"] = key
    return save_config(config)

def set_listen_port(port):
    config = load_config()
    config["listen_port"] = int(port)
    return save_config(config)

def update_last_synced_content(content):
    config = load_config()
    config["last_synced_content"] = content
    return save_config(config)