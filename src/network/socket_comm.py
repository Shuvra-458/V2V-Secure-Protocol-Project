"""
Socket Communication Module
---------------------------
Implements TCP socket send/receive for demo.
"""

import socket
import threading


def start_server(port, handler):
    """Start a simple TCP server that calls handler(data) for each connection."""
    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("localhost", port))
            s.listen()
            print(f"[SERVER] Listening on port {port}")
            while True:  # <- keep listening forever
                conn, _ = s.accept()
                with conn:
                    data = conn.recv(4096)
                    if data:
                        handler(data)
    thread = threading.Thread(target=server, daemon=True)
    thread.start()


def send_message(port, data):
    """Send data to server at given port"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", port))
        s.sendall(data)
