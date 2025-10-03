import json
import os
import sys
import logging
HISTORY_FILE = 'clipper_history.json'
MAX_HISTORY_SIZE = 20

def load_history():
    #loads clipboard hist from local json file
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
                if isinstance(history, list):
                    return history
                else:
                    print(f"History file contents are invalid. Starting new history.", file=sys.stderr)
                    return []
        except (json.JSONDecodeError, IOError) as e:
            print(f"Could not read or decode history file: {e}. Starting new history.", file = sys.stderr)
            return []
    return []
def save_history(history):
    #saves current clipboard history back to JSON
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
    except IOError as e:
        print(f"Could not save history file: {e}", file = sys.stderr)

def add_to_history(content):
    #adds new content to history, ensures new content is unique, trims list to max size
    if not content or not isinstance(content, str):
        return
    history = load_history()
    try:
        history.remove(content)
    except ValueError:
        pass
    history.insert(0,content)
    if len(history) > MAX_HISTORY_SIZE:
        history = history[:MAX_HISTORY_SIZE]
    save_history(history)

def merge_history(remote_history):
    if not isinstance(remote_history, list):
        logging.error("Invalid history")
        return
    local_history = load_history()

    local_set = set(local_history)
    new_clips = []
    for clip in remote_history:
        if clip not in local_set:
            new_clips.append(clip)
    
    updated_history = new_clips + local_history
    final_history = []
    seen=set()
    for clip in updated_history:
        if clip not in seen:
            final_history.append(clip)
            seen.add(clip)
    
    final_history = final_history[:MAX_HISTORY_SIZE]

    save_history(final_history)
    logging.info(f"History merged. Added {len(new_clips)} unique clips. Final size: {len(final_history)}")
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format='%(message)s')