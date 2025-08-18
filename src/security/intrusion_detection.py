"""
Intrusion Detection System (IDS) for V2V
----------------------------------------
Detects replay, sybil, and DoS attacks.
"""

import time
from collections import defaultdict
from src.utils.logger import log_attack, log_warning

# Store last seen timestamps for replay detection
last_seen_timestamps = {}

# Store message counts per sender for DoS detection
message_counts = defaultdict(list)  # {sender_id: [timestamps]}

# Keep track of vehicles already flagged for DoS
dos_alerted = {}  # {vehicle_id: last_alert_time}


def detect_replay(vehicle_id, timestamp):
    """Detect replay attacks by checking if timestamp already seen."""
    if vehicle_id in last_seen_timestamps and last_seen_timestamps[vehicle_id] == timestamp:
        log_attack(f"Replay attack detected from {vehicle_id}")
        return True
    last_seen_timestamps[vehicle_id] = timestamp
    return False


def detect_sybil(valid_signature, vehicle_id):
    """Detect Sybil attack if signature is invalid."""
    if not valid_signature:
        log_attack(f"Sybil attack detected! Fake ID: {vehicle_id}")
        return True
    return False


def detect_dos(vehicle_id, threshold=5, window=3, cooldown=10):
    """
    Detect DoS attack:
    - If more than `threshold` messages arrive from the same ID within `window` seconds.
    - Only warn once per `cooldown` seconds per vehicle.
    """
    now = time.time()
    message_counts[vehicle_id].append(now)

    # Keep only recent timestamps within window
    message_counts[vehicle_id] = [t for t in message_counts[vehicle_id] if now - t <= window]

    if len(message_counts[vehicle_id]) > threshold:
        last_alert = dos_alerted.get(vehicle_id, 0)
        if now - last_alert > cooldown:  # avoid spamming logs
            log_warning(f"Possible DoS attack from {vehicle_id} (too many msgs/sec)")
            dos_alerted[vehicle_id] = now
        return True
    return False
