import argparse
import sys
import os
import time
import pyperclip
import importlib.util
import logging
from subprocess import Popen, DEVNULL

# add cmd to show current clipboard

PID_FILE = '.clipper.pid'
LOG_FILE = 'clipper.log'
# import config manager
try:
    # 1. Get the absolute path to the file we know exists
    config_path = os.path.join(os.getcwd(), 'config_manager.py')
    
    # 2. Create a module spec from the path
    spec = importlib.util.spec_from_file_location("config_manager", config_path)
    
    # 3. Create the module object
    config_manager = importlib.util.module_from_spec(spec)
    
    # 4. Execute the module to populate it (i.e., run the script)
    spec.loader.exec_module(config_manager)
    #import config_manager.py
except ImportError:
    print("config_manager.py not found. Make sure it is in the same directory.")
    sys.exit(1)


#import network manager
try:
    network_path = os.path.join(os.getcwd(), 'network_manager.py')
    spec = importlib.util.spec_from_file_location("network_manager", network_path)
    network_manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(network_manager)
except ImportError:
    print("network_manager.py not found. Make sure it is in the same directory.")
    sys.exit(1)


#setup logging
def setup_daemon_logging():
    if logging.getLogger().hasHandlers():
        logging.getLogger().handlers.clear()

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logging.getLogger().addHandler(console_handler)



def cmd_config(args):
    """Handles the 'config' command to set the secret key, port, and peer list."""
    config = config_manager.load_config()
    
    set_port = getattr(args, 'set_port', None)
    set_key = getattr(args, 'set_key', None)
    set_peers = getattr(args, 'set_peers', None)

    if set_port is not None:
        if 1024 <= set_port <= 65535:
            config['listen_port'] = set_port
            print(f"✅ Listen port set to {set_port}.")
        else:
            print("❌ Invalid port. Must be between 1024 and 65535.")

    if set_key:
        key = set_key.strip()
        if len(key) >= 5: 
            config['secret_key'] = key
            print("✅ Secret key updated successfully.")
        else:
            print("❌ Secret key must be at least 5 characters long. Security is still advised even without encryption.")

    if set_peers:
        new_peers = [ip.strip() for ip in set_peers.split(',') if ip.strip()]
        if new_peers:
            config['peer_ips'] = new_peers
            print(f"✅ Peer IP list updated. Now synchronizing with {len(new_peers)} peers.")
        else:
            print("❌ Peer IP list empty. Peers were not updated.")


    if set_key is not None or set_port is not None or set_peers is not None:
        config_manager.save_config(config)

    # Display current configuration
    config = config_manager.load_config() # Reload after potential save
    
    if config['secret_key']:
        secret_display = config['secret_key'][:1] + '...' + config['secret_key'][-1:]
    else:
        secret_display = "❌ NOT SET"
    # ----------------------------------------------------------------

    peer_list_display = ', '.join(config['peer_ips']) if config['peer_ips'] else 'None configured'
    
    print("\n[CURRENT CONFIGURATION]")
    print(f"Secret Key (PSK): {secret_display}")
    print(f"Listen Port: {config['listen_port']}")
    print(f"Peer IPs: {peer_list_display}")
    print(f"Config File: {config_manager.CONFIG_FILE}")

def run_daemon_loop(config):
    if not config["secret_key"]:
        logging.error("Secret key is not configured. Run 'clipper config --key <SECRET>' first.")
        return
    

    listen_port = config['listen_port']
    listener_socket = network_manager.start_listener('0.0.0.0', listen_port)
    if listener_socket is None:
        return
    

    logging.info(f"Clipper daemon starting on port {config["listen_port"]}...")
    logging.info(f"Authentication Key: ***{config["secret_key"][-4:]}")
    logging.info(f"Currently running in foreground for testing")

    current_clipboard = ""
    last_synced_content = config.get("last_synced_content", "")
    while True:
        try:
            #clipboard monitoring
            try:
                #use pyperclip to read actual OS clipboard
                new_content = pyperclip.paste()
            except pyperclip.PyperclipException as e:
                #case where clipboard is inaccessible
                logging.warning(f"Could not access clipboard. {e}")
                new_content = current_clipboard
            
            #SYNCHRONIZATION LOGIC:
            if new_content and new_content != current_clipboard and new_content != last_synced_content:
                logging.info(f"\n[LOCAL CHANGE]: copy detected '{new_content[:50]}{"..." if len(new_content) > 50 else ""}'")

                for peer_ip in config['peer_ips']:
                    success = network_manager.send_data(
                        ip_address=peer_ip,
                        port=listen_port,
                        clipboard_data = new_content
                    )

                    if success:
                        logging.info(f"[NETWORK]: Data sent to {peer_ip}:{listen_port}")
                        config_manager.update_last_synced_content(new_content)
                        last_synced_content = new_content
                        break
                    else:
                        logging.warning(f"[NEWTORK]: Failed to send data to {peer_ip}:{listen_port}")
            
            received_content = network_manager.receive_data(listener_socket)
            if received_content is not None and received_content != last_synced_content:
                logging.info(f"[NETWORK]: Incoming data received: '{received_content[:50]}{'...' if len(received_content) > 50 else ''}'")
                pyperclip.copy(received_content)
                config_manager.update_last_synced_content(received_content)
                last_synced_content = received_content
                current_clipboard = received_content

            current_clipboard = new_content
            time.sleep(0.1)
        except KeyboardInterrupt:
            logging.info("\n Clipper daemon shutting down")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}. Retrying in 5secs.")
            time.sleep(5)

def cmd_start(args):
    if os.path.exists(PID_FILE):
        with open(PID_FILE, 'r') as f:
            pid = f.read().strip()
        print(f"Already running with PID: {pid}. Use clipper.py to stop")
        return

    if not getattr(args, '_daemon_child', False):
        command = [sys.executable, sys.argv[0], 'start', '--_daemon_child'] #adds internal flag
        try:
            #use Popen to start child process
            #DEVNULL to silene the child's cries in the terminal
            Popen(command,
                  stdout = DEVNULL,
                  stderr = DEVNULL,
                  stdin = DEVNULL,
                  close_fds=True
                )
            print(f"✅ ClipBridge Daemon launched in the background.")
            print("Use 'python clipper.py status' to check its state and 'python clipper.py stop' to terminate it.")
            return
        except Exception as e:
            print(f"Failed to launch daemon process in bg: {e}")
            return
    
    config = config_manager.load_config()
    print("Starting Clipper...(currently running in foreground for dev)")
    pid = os.getpid()
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(pid))
        print(f"PID file created at {PID_FILE} (PID: {pid})")
        run_daemon_loop(config)
    except Exception as e:
        print(f"An unexpected error happened during daemon startup: {e}")
    finally:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            print(f"PID file {PID_FILE} cleaned up.")


def cmd_status(args):
    #handles status cmd
    config = config_manager.load_config()
    print("\n---Clipper Status---")
    print("Daemon Status: Stopped (run 'start' to launch)")
    print(f"Config file:    {config_manager.CONFIG_FILE}")
    print(f"Config port:    {config["listen_port"]}")
    print(f"Secret Key Set: {'Yes' if config["secret_key"] else 'No'}")
    print("-------------------------\n")

def cmd_stop(args):
    if not os.path.exists(PID_FILE):
        print("Daemon is not running (PID file not found)")
        return
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid,15)
        time.sleep(1)
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            print(f"Successfully sent termination signal to PID {pid}. Forced PID file cleanup.")
        else:
            print(f"Daemon stopped")
    except ProcessLookupError:
        print(f"Daemon process (PID {pid}) not found.")
        os.remove(PID_FILE)
        print(f"Cleaned up PID file: {PID_FILE}")
    except Exception as e:
        print(f"Error stopping daemon: {e}")

def main():
    #entry point for CLI
    parser = argparse.ArgumentParser(
        description = "Clipper: A universal terminal clipboard synchronization tool",
        epilog = "Use 'python clipper.py <command> --help' for command-specific options"
    )

    #subparsers for commands
    subparsers = parser.add_subparsers(dest="command", required = True)

    #Config command parser
    config_parser = subparsers.add_parser("config", help = "Configure application settings (PSK, port)")
    config_parser.add_argument("-k", "--key", dest="set_key", type = str, default = None, help = "Set pre-shared secret key (PSK) for authentication (min 16 chars)")
    config_parser.add_argument("-p", "--port", dest = "set_port", type = int, default = None, help = "Set listening port for peer communication")
    config_parser.add_argument("-r", "--peers", dest = "set_peers", type = str, default = None, help = "Comma-separated list of peer IP adresses to send  clipboard content to e.g.(192.168.1.5,10.0.0.2)")
    config_parser.set_defaults(func = cmd_config)

    #status command parser
    status_parser = subparsers.add_parser("status", help = "Show current status of daemon and configuration.")
    status_parser.set_defaults(func = cmd_config)

    #start parser
    start_parser = subparsers.add_parser("start", help = "Start backround sync")
    start_parser.add_argument('--_daemon_child', action='store_true', help = argparse.SUPPRESS)
    start_parser.set_defaults(func = cmd_start)

    #stop command parser
    stop_parser = subparsers.add_parser("stop", help = "Stop running Clipper daemon")
    stop_parser.set_defaults(func = cmd_stop)

    #parse arguments and run function associated with command
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()