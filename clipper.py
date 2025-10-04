import argparse
import sys
import os
import time
import pyperclip
import importlib.util
import logging
from subprocess import Popen, DEVNULL

#WHEN PACKAGING:
'''
RUN:  install -r requirements.txt
AND THEN: pyinstaller --onefile --hidden-import config_manager --hidden-import network_manager --hidden-import history_manager clipper.py
'''

PID_FILE = '.clipper.pid'
LOG_FILE = 'clipper.log'

if os.getcwd() != sys.path[0]:
    sys.path.insert(0,os.getcwd())

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

#import history_manager
try:
    history_path = os.path.join(os.getcwd(), 'history_manager.py')
    hist_spec = importlib.util.spec_from_file_location("history_manager", history_path)
    history_manager = importlib.util.module_from_spec(hist_spec)
    hist_spec.loader.exec_module(history_manager)
except Exception as e:
    print(f"Failed to load history_manager.py. Reason: {e}")
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

def cmd_clipboard(args):
    try:
        content = pyperclip.paste()
        if content:
            print("\n[CURRENT CLIPBOARD CONTENT]")
            print("-" * 30)
            # use repr() to show invisible chars
            print(repr(content)[1:-1])
            print("-"*30)
        else:
            print("Clipboard is currently empty or contains non-text data.")
    except pyperclip.PyperclipException as e:
        print(f"Error accessing clipboard: {e}.")

def cmd_history(args):
    history = history_manager.load_history()
    print(f"\n[CLIPBOARD HISTORY (Last {history_manager.MAX_HISTORY_SIZE} clips)]")
    print("-" * 85)
    if not history:
        print("History is empty. Copy something to start tracking!")
    else:
        for i, content in enumerate(history):
            #display content #, first 80 chars, +cleaning up new lines for cleaner output
            display_content = content.replace("\n", "\\n").replace("\t", "\\t")
            print(f"[{i:02d}] {display_content[:80]}{'...' if len(display_content) > 80 else ''}")
    print("-"*85)

    if args.set_index is not None:
        if not history:
            print("\n Cannot set: history is empty")
            return
        try:
            index = int(args.set_index)
            if 0<=index>len(history):
                selected_content = history[index]
                pyperclip.copy(selected_content)
                history_manager.add_to_history(selected_content)
                print(f"\n Item [{index:02d}] copied back to clipboard.")
            else:
                print(f"\n Invalid index: {index}. Must be between 0 and {len(history)} - 1")
        except ValueError:
            print(f"\nInvalid index format. Must be an int")

def cmd_sync(args):
    config = config_manager.load_config()
    target_ip = args.ip
    listen_port = config['listen_port']

    print(f"\nRequesting history from peer at {target_ip}:{listen_port}...")

    success = network_manager.send_data(
        ip_address = target_ip,
        port=listen_port,
        payload_type="HISTORY_REQUEST",
        payload_data={
            "max_clips":history_manager.MAX_HISTORY_SIZE
        }
    )

    if success:
        print(f"History request sent to {target_ip}.")
    else:
        print(f"Failed to send history requestion to {target_ip}.")

def run_daemon_loop(config):
    if not config["secret_key"]:
        logging.error("Secret key is not configured. Run 'clipper config --key <SECRET>' first.")
        return
    

    listen_port = config['listen_port']
    peer_ips = config['peer_ips']
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
            if new_content and new_content != current_clipboard:
                if len(new_content.encode('utf-8')) > network_manager.MAX_CLIP_SIZE:
                    logging.warning(f"Clip ignored: Too large ({len(new_content)} bytes). Max is 1MB")
                    current_clipboard = new_content #still update local but skip network sync
                    continue
                #type check
                if not isinstance(new_content, str):
                    logging.warning("Clip ignored: non-text data type")
                    current_clipboard = new_content
                    continue
                history_manager.add_to_history(new_content)
                logging.info(f"\n[LOCAL CHANGE]: Copy detected and saved to history: '{new_content[:50]}{'...' if len(new_content) > 50 else ''}'")
                
                if new_content != last_synced_content:

                    for peer_ip in config['peer_ips']:
                        success = network_manager.send_data(
                            ip_address=peer_ip,
                            port=listen_port,
                            payload_type="CLIP_SYNC",
                            payload_data = new_content
                        )

                        if success:
                            logging.info(f"[NETWORK]: Data sent to {peer_ip}:{listen_port}")
                            config_manager.update_last_synced_content(new_content)
                            last_synced_content = new_content
                            break
                        else:
                            logging.warning(f"[NEWTORK]: Failed to send data to {peer_ip}:{listen_port}")
            
            recieved_payload = network_manager.receive_data(listener_socket)
            if recieved_payload:
                p_type = recieved_payload.get('type')
                p_data = recieved_payload.get('data')
                if p_type == "CLIP_SYNC":
                    if p_data is not None and p_data != last_synced_content:
                        logging.info(f"[NETWORK]: Incoming CLIP_SYNC recieved")
                        pyperclip.copy(p_data)
                        config_manager.update_last_synced_content(p_data)
                        last_synced_content=p_data
                        current_clipboard=p_data
                        history_manager.add_to_history(p_data)
                elif p_type == "HISTORY_REQUEST":
                    logging.info(f"[NETWORK]: Incoming HISTORY_REQUEST recieved.")
                    local_history = history_manager.load_history()
                    #NOTE: In real, send to specific requesting peer
                    #simplified by sending to all known
                    for peer_ip in peer_ips:
                        network_manager.send_data(
                            ip_address=peer_ip,
                            port=listen_port,
                            payload_type="HISTORY_RESPONSE",
                            payload_data=local_history
                        )
                elif p_type == "HISTORY_RESPONSE":
                    if isinstance(p_data,list):
                        logging.info(f"[NETWORK]: Incoming HISTORY_RESPONSE recieved")
                        history_manager.merge_history(p_data)
                    else:
                        logging.warning("[NETWORK]: Recieved HISTORY_RESPONSE with invalid data type")
                else:
                    logging.warning(f"[NETWORK]: Unknown command type recieved {p_type}.")
            current_clipboard = new_content
            time.sleep(0.1)
        except KeyboardInterrupt:
            logging.info("\n Daemon shutting down...")
            if listener_socket:
                listener_socket.close()
            break
        except Exception as e:
            logging.erro(f"Unexpected error: {e}. Retrying in 5secs")
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
            print("Use 'python clipper.py status' to check its state, 'python clipper.py stop' to terminate it, and 'python clipper.py help' for commands.")
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
    config = config_manager.load_config()
    daemon_status = "STOPPED"
    pid = "N/A"
    #1 check daemons tatus
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
        except Exception as e:
            daemon_status = "MALFORMED PID FILE"
        if pid is not None and is_process_running(pid):
            daemon_status = f"RUNNING (PID: {pid})"
        elif pid is not None:
            daemon_status = f"STALE PID FILE (PID: {pid}) - run clipper.py stop"

    #2 configuration details
    secret_key = config.get("secret_key")
    if secret_key:
        key_display = f"Yes (Ends in: ...{secret_key[-3:]})"
    else:
        key_display = "NO KEY SET"
    peers_display = ', '.join(config['peer_ips']) if config['peer_ips'] else 'None configured'
    #3 last synced content
    last_content = config.get("last_synced_content", "")
    if last_content:
        display_clip = last_content.replace('\n', '\\n')
        display_clip = f"'{display_clip[:40]}{'...' if len(display_clip) > 40 else ''}'"
    else:
        display_clip = "N/A"

    #handles status cmd
    config = config_manager.load_config()
    print("\n---Clipper Status---")
    print(f"Daemon Status:  {daemon_status}")
    print(f"Listening Port:    {config['listen_port']}")
    print(f"Secret Key Set:    {key_display}")
    print("------------------------------")
    print(f"Configured Peers:   {peers_display}")
    print(f"Last Synced Clip:   {display_clip}")
    print(f"Config File:    {config_manager.CONFIG_FILE}")
    print("------------------------------")

#helper function for platform-independent PID tracking
def is_process_running(pid):
    if pid is None:
        return False
    if os.name == 'posix':
        try:
            os.kill(pid,0)
            return True
        except ProcessLookupError:
            return False
        except Exception:
            return False
    elif os.name == 'nt':
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            else:
                return False
        except Exception:
            return False
    return False


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
        epilog = "Use 'python clipper.py <command> --help or python clipper.py help' for command-specific options"
    )

    #subparsers for commands
    subparsers = parser.add_subparsers(dest="command", required = True)

    #clipboard parser
    clipboard_parser = subparsers.add_parser("clipboard", help = "Displays current content of local OS clipboard.")
    clipboard_parser.set_defaults(func=cmd_clipboard)

    #Config command parser
    config_parser = subparsers.add_parser("config", help = "Configure application settings (PSK, port)")
    config_parser.add_argument("-k", "--key", dest="set_key", type = str, default = None, help = "Set pre-shared secret key (PSK) for authentication (min 16 chars)")
    config_parser.add_argument("-p", "--port", dest = "set_port", type = int, default = None, help = "Set listening port for peer communication")
    config_parser.add_argument("-r", "--peers", dest = "set_peers", type = str, default = None, help = "Comma-separated list of peer IP adresses to send  clipboard content to e.g.(192.168.1.5,10.0.0.2)")
    config_parser.set_defaults(func = cmd_config)

    #history
    history_parser= subparsers.add_parser('history', help = 'Displays and manages clipboard history.')
    history_parser.add_argument('-s', '--set', dest = 'set_index', type = int, default = None, help = 'Index of the history itemto copy back to the local clipboard')
    history_parser.set_defaults(func = cmd_history)

    #sync
    sync_parser = subparsers.add_parser('sync', help = 'Requests clipboard history from a specified peer IP')
    sync_parser.add_argument('ip', type=str, help="The IP adrdress of the peer to request history from ")
    sync_parser.set_defaults(func=cmd_sync)

    #help
    help_parser = subparsers.add_parser('help', help='Shows available commands')
    help_parser.set_defaults(func = lambda args: parser.print_help())

    #status command parser
    status_parser = subparsers.add_parser("status", help = "Show current status of daemon and configuration.")
    status_parser.set_defaults(func = cmd_status)

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