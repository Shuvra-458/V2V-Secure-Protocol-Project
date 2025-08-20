# src/attacks/sybil_attack.py
import json
import threading
from src.network.socket_comm import send_message

def sybil_flood(port, fake_msg, fake_ids, count):
    for i in range(count):
        msg = fake_msg.copy()
        msg["id"] = fake_ids[i % len(fake_ids)]
        send_message(port, json.dumps(msg).encode("utf-8"))

def launch_sybil(port, fake_msg, fake_ids=None, count=50, threads=3):
    """
    Launch a Sybil attack by sending the fake message
    from multiple fake IDs using multiple threads.
    """
    if fake_ids is None:
        fake_ids = [f"Sybil_{i}" for i in range(10)]  # default IDs
    
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=sybil_flood, args=(port, fake_msg, fake_ids, count))
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join()
