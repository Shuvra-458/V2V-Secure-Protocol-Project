"""
Replay Attack Simulation
------------------------
Resends an old valid encrypted message multiple times to simulate a realistic replay attack.
"""

import time
import threading
from src.network.socket_comm import send_message

def replay_flood(port, old_encrypted_msg, count, delay=0.01):
    for _ in range(count):
        send_message(port, old_encrypted_msg)
        time.sleep(delay)

def launch_replay(port, old_encrypted_msg, count=50, threads=3, delay=0.01):
    """Replay the same message many times using multiple threads."""
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=replay_flood, args=(port, old_encrypted_msg, count, delay))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()