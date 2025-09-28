import argparse
import sys
import os
import time
import pyperclip
import importlib.util

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

def cmd_config(args):
    #handles config command to set secret key + port
    config = config_manager.load_config()
    print("\n Clipper Configuration")
    print(f"Configuration file location: {config_manager.CONFIG_FILE}")

    if args.set_key:
        key = args.set_key.strip()
        if len(key) < 16:
            print("Key should be atlast 16 characters")
            return
        if config_manager.set_secret_key(key):
            print("Secret key set successfully.")
    
    if args.set_port:
        try:
            port = int(args.set_port)
            if 1024 <= port <= 65535:
                if config_manager.set_listen_port(port):
                    print(f"Listening port set to {port}")
            else:
                print("Port number must be between 1024 and 65535")
        except ValueError:
            print("Port must be a valid number.")
            return
    
    #display current config
    config = config_manager.load_config() #reload
    secret_display = config["secret_key"][:4] + "..." + config["secret_key"][-4:] if config["secret_key"] else "NOT SET"
    print("\nCURRENT SETTINGS")
    print(f"    Secret Key (PSK): {secret_display}")
    print(f"    Listen Port:      {config["listen_port"]}")
    print("\nUse 'python.clipper.py config --key <SECRET>' and 'python clipper.py config --port <PORT>' to set them")

def run_daemon_loop(config):
    if not config["secret_key"]:
        print("Secret key is not configured. Run 'clipper config --key <SECRET>' first.")
        sys.exit(1)
    print(f"Clipper daemon starting on port {config["listen_port"]}...")
    print(f"Authentication Key: ***{config["secret_key"][-4:]}")
    print(f"Currently running in foreground for testing")
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
                print(f"Could not access clipboard. {e}")
                new_content = current_clipboard
            
            #SYNCHRONIZATION LOGIC:
            if new_content and new_content != current_clipboard and new_content != last_synced_content:
                print(f"\n[LOCAL CHANGE]: copy detected '{new_content[:50]}{"..." if len(new_content) > 50 else ""}'")
                print("[NETWORK]: sending data to known peers...")

                #on sucess transmit cache
                config_manager.update_last_synced_content(new_content)
                last_synced_content = new_content
            #2 TODO: NETWORK LISTENING (SERVER SIDE)
            current_clipboard = new_content
            time.sleep(1)
        except KeyboardInterrupt:
            print("\n Clipper daemon shutting down")
            break
        except Exception as e:
            print(f"Unexpected error: {e}. Retrying in 5secs.")
            time.sleep(5)

def cmd_start(args):
    config = config_manager.load_config()
    print("Starting Clipper...(currently running in foreground for dev)")
    run_daemon_loop(config)

def cmd_status(args):
    #handles status cmd
    config = config_manager.load_config()
    print("\n---Clipper Status---")
    print("Daemon Status: Stopped (run 'start' to launch)")
    print(f"Config file:    {config_manager.CONFIG_FILE}")
    print(f"Config port:    {config["listen_port"]}")
    print(f"Secret Key Set: {'Yes' if config["secret_key"] else 'No'}")
    print("-------------------------\n")

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
    config_parser.add_argument("-k", "--key", dest="set_key", type = str, help = "Set pre-shared secret key (PSK) for authentication (min 16 chars)")
    config_parser.add_argument("-p", "--port", dest = "set_port", type = int, help = "Set listening port for peer communication")
    config_parser.set_defaults(func = cmd_config)

    #start command parser
    status_parser = subparsers.add_parser("status", help = "Show current status of daemon and configuration.")
    status_parser.set_defaults(func = cmd_config)

    #stop command parser
    stop_parser = subparsers.add_parser("stop", help = "Stop running Clipper daemon")
    stop_parser.set_defaults(func = lambda args: print("Stop command logic will be added after daemonization logic is added. Press ctrl+c for now"))

    #parse arguments and run function associated with command
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()