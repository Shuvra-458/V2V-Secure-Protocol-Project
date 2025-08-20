"""
Message Format for V2V
----------------------
Defines JSON message schema with id, event, speed, location, timestamp.
Includes validation and robust parsing.
"""

import json
from datetime import datetime

def create_message(vehicle_id, event, speed, location, timestamp=None):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    message = {
        "id": str(vehicle_id),
        "event": str(event),
        "speed": float(speed),
        "location": str(location),
        "timestamp": timestamp
    }
    return json.dumps(message)

def parse_message(message_json):
    try:
        msg = json.loads(message_json)
        # Basic schema validation
        required_fields = {"id", "event", "speed", "location", "timestamp"}
        if not required_fields.issubset(msg.keys()):
            return None
        return msg
    except (json.JSONDecodeError, TypeError, ValueError):
        return None