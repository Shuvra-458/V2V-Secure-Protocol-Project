import os
from datetime import datetime

LOG_FILE = os.path.join("simulation_results", "logs.txt")

def _write_log(level, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{level}] {timestamp} - {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def log_info(msg): _write_log("INFO", msg)
def log_warning(msg): _write_log("WARNING", msg)
def log_attack(msg): _write_log("ATTACK", msg)
def log_blocked(msg): _write_log("BLOCKED", msg)
