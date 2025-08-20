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
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("localhost", port))
            s.listen()
            print(f"[SERVER] Listening on port {port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr, handler), daemon=True).start()

    def handle_client(conn, addr, handler):
        with conn:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if data:
                handler(data)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()

def send_message(port, data, retries=3, timeout=2):
    """Send data to server at given port with basic retry and timeout."""
    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(("localhost", port))
                s.sendall(data)
            break
        except (ConnectionRefusedError, socket.timeout) as e:
            if attempt == retries - 1:
                print(f"[CLIENT] Failed to send after {retries} attempts: {e}")
            else:
                continue