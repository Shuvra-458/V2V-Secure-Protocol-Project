# src/attacks/dos_attack.py

import json
import time
from src.network.socket_comm import send_message

def launch_dos(port, count=20):
    """Flood the server with too many messages in a short time."""
    for i in range(count):
        msg = {
            "id": "V1",   # same sender, flooding
            "event": f"Noise_{i}",
            "speed": 0,
            "location": "FloodZone",
            "timestamp": str(time.time())
        }
        send_message(port, json.dumps(msg).encode("utf-8"))
