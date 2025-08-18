# src/attacks/sybil_attack.py

import json
from src.network.socket_comm import send_message

def launch_sybil(port):
    """Send a fake message with a spoofed vehicle ID."""
    fake_msg = {
        "id": "FakeCar123",  # fake ID
        "event": "Fake traffic update",
        "speed": 999,
        "location": "Nowhere",
        "timestamp": "2099-01-01T00:00:00Z"
    }
    send_message(port, json.dumps(fake_msg).encode("utf-8"))
