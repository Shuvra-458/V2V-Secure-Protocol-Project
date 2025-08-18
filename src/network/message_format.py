"""
Message Format for V2V
----------------------
Defines JSON message schema with id, event, speed, location, timestamp.
"""

import json
from datetime import datetime


def create_message(vehicle_id, event, speed, location):
    message = {
        "id": vehicle_id,
        "event": event,
        "speed": speed,
        "location": location,
        "timestamp": datetime.utcnow().isoformat()
    }
    return json.dumps(message)


def parse_message(message_json):
    try:
        return json.loads(message_json)
    except json.JSONDecodeError:
        return None
