import os
from datetime import datetime

LOG_DIR = "simulation_results"
LOG_FILE = os.path.join(LOG_DIR, "logs.txt")

def _write_log(level, message):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Millisecond precision
    line = f"[{level}] {timestamp} - {message}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[LOGGER ERROR] Failed to write log: {e}")

def log_info(msg): _write_log("INFO", msg)
def log_warning(msg): _write_log("WARNING", msg)
def log_attack(msg): _write_log("ATTACK", msg)
def log_blocked(msg): _write_log("BLOCKED", msg)