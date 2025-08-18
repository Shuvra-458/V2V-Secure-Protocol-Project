"""
Replay Attack Simulation
------------------------
Resends an old valid encrypted message.
"""

from src.network.socket_comm import send_message


def launch_replay(port, old_encrypted_msg):
    send_message(port, old_encrypted_msg)
