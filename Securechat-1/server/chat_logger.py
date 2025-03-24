import os
from datetime import datetime

LOGS_DIR = "logs"

# Ensure the logs directory exists
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

def get_log_path(sender, recipient):
    # Consistent filename based on sorted usernames
    users = sorted([sender, recipient])
    filename = f"{users[0]}_to_{users[1]}.txt"
    return os.path.join(LOGS_DIR, filename)

def log_message(sender, recipient, message):
    if not sender or not recipient or not message:
        return

    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    entry = f"{timestamp} {sender} -> {recipient}: {message}\n"

    log_file = get_log_path(sender, recipient)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(entry)
