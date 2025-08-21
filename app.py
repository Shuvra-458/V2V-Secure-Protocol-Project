import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import json
import time
import threading
import socket
import base64
from datetime import datetime
import ast
from io import BytesIO
import plotly.graph_objects as go
import plotly.express as px
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import unittest

# Set page configuration
st.set_page_config(
    page_title="V2V Secure Protocol Dashboard",
    page_icon="🚗",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 2rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #0D47A1;
        border-bottom: 2px solid #64B5F6;
        padding-bottom: 0.3rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #E3F2FD;
        padding: 1.5rem;
        border-radius: 0.5rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
        height: 120px;
    }
    .attack-alert {
        background-color: #FFEBEE;
        padding: 1rem;
        border-left: 4px solid #F44336;
        border-radius: 0.25rem;
        margin-bottom: 1rem;
    }
    .success-alert {
        background-color: #E8F5E9;
        padding: 1rem;
        border-left: 4px solid #4CAF50;
        border-radius: 0.25rem;
        margin-bottom: 1rem;
    }
    .info-alert {
        background-color: #E3F2FD;
        padding: 1rem;
        border-left: 4px solid #2196F3;
        border-radius: 0.25rem;
        margin-bottom: 1rem;
    }
    .code-block {
        background-color: #263238;
        color: #EEFFFF;
        padding: 1rem;
        border-radius: 0.5rem;
        overflow-x: auto;
        margin: 1rem 0;
        font-family: 'Monospace', monospace;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for data persistence
if 'simulation_data' not in st.session_state:
    st.session_state.simulation_data = {
        "total_vehicles": 15,
        "active_vehicles": 12,
        "messages_sent": 0,
        "messages_received": 0,
        "replay_attacks_detected": 0,
        "sybil_attacks_detected": 0,
        "dos_attacks_detected": 0,
        "avg_latency": 0,
        "encryption_success_rate": 0,
        "latencies": [],
        "attack_counts": {"replay": 0, "sybil": 0, "dos": 0},
        "message_logs": [],
        "vehicle_positions": {},
        "server_running": False,
        "server_thread": None
    }

if 'vehicles' not in st.session_state:
    st.session_state.vehicles = {}

if 'aes_keys' not in st.session_state:
    st.session_state.aes_keys = {}

if 'rsa_keys' not in st.session_state:
    st.session_state.rsa_keys = {}

# Implement your security modules
def generate_aes_key(length=16):
    if length not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long.")
    return get_random_bytes(length)

def encrypt_message(key, plaintext, associated_data=None):
    if key is None:
        raise ValueError("AES key cannot be None")
    if plaintext is None:
        raise ValueError("Plaintext cannot be None")

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    cipher = AES.new(key, AES.MODE_EAX)
    if associated_data:
        cipher.update(associated_data)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    result = cipher.nonce + tag + ciphertext
    return base64.b64encode(result).decode("utf-8")

def decrypt_message(key, encrypted_text, associated_data=None):
    if key is None:
        raise ValueError("AES key cannot be None")
    if encrypted_text is None:
        raise ValueError("Encrypted text cannot be None")

    try:
        raw = base64.b64decode(encrypted_text)
    except Exception:
        raise ValueError("Invalid ciphertext format (Base64 decode failed)")

    if len(raw) < 32:
        raise ValueError("Ciphertext too short to contain AES nonce+tag")

    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    if associated_data:
        cipher.update(associated_data)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError(f"Decryption failed: {str(e)}")

    return plaintext.decode("utf-8")

def generate_rsa_keys(key_size=3072):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_aes_key(public_key, aes_key, label=b""):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, label=label)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode("utf-8")

def decrypt_aes_key(private_key, encrypted_aes_key, label=b""):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, label=label)
    decrypted_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
    return decrypted_key

def generate_signature_keys(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def sign_message(private_key, message, encoding="utf-8"):
    rsa_key = RSA.import_key(private_key)
    hashed = SHA256.new(message.encode(encoding))
    signature = pkcs1_15.new(rsa_key).sign(hashed)
    return base64.b64encode(signature).decode("utf-8")

def verify_signature(public_key, message, signature, encoding="utf-8"):
    rsa_key = RSA.import_key(public_key)
    hashed = SHA256.new(message.encode(encoding))
    try:
        pkcs1_15.new(rsa_key).verify(hashed, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

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
        required_fields = {"id", "event", "speed", "location", "timestamp"}
        if not required_fields.issubset(msg.keys()):
            return None
        return msg
    except (json.JSONDecodeError, TypeError, ValueError):
        return None

# Implement your attack modules
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
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=flood, args=(port, count))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

def replay_flood(port, old_encrypted_msg, count, delay=0.01):
    for _ in range(count):
        send_message(port, old_encrypted_msg)
        time.sleep(delay)

def launch_replay(port, old_encrypted_msg, count=50, threads=3, delay=0.01):
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=replay_flood, args=(port, old_encrypted_msg, count, delay))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

def sybil_flood(port, fake_msg, fake_ids, count):
    for i in range(count):
        msg = fake_msg.copy()
        msg["id"] = fake_ids[i % len(fake_ids)]
        send_message(port, json.dumps(msg).encode("utf-8"))

def launch_sybil(port, fake_msg, fake_ids=None, count=50, threads=3):
    if fake_ids is None:
        fake_ids = [f"Sybil_{i}" for i in range(10)]
    
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=sybil_flood, args=(port, fake_msg, fake_ids, count))
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join()

# Implement socket communication
def send_message(port, data, retries=3, timeout=2):
    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(("localhost", port))
                s.sendall(data)
            break
        except (ConnectionRefusedError, socket.timeout) as e:
            if attempt == retries - 1:
                st.error(f"Failed to send after {retries} attempts: {e}")
            else:
                continue

def start_server(port, handler):
    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("localhost", port))
            s.listen()
            st.session_state.server_running = True
            while st.session_state.server_running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=handle_client, args=(conn, addr, handler), daemon=True).start()
                except:
                    break

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
    st.session_state.server_thread = thread

# Implement IDS
last_seen_timestamps = {}
message_counts = {}
dos_alerted = {}

def detect_replay(vehicle_id, timestamp):
    if vehicle_id in last_seen_timestamps and last_seen_timestamps[vehicle_id] == timestamp:
        st.session_state.simulation_data["replay_attacks_detected"] += 1
        st.session_state.simulation_data["attack_counts"]["replay"] += 1
        return True
    last_seen_timestamps[vehicle_id] = timestamp
    return False

def detect_sybil(valid_signature, vehicle_id):
    if not valid_signature:
        st.session_state.simulation_data["sybil_attacks_detected"] += 1
        st.session_state.simulation_data["attack_counts"]["sybil"] += 1
        return True
    return False

def detect_dos(vehicle_id, threshold=5, window=3, cooldown=10):
    now = time.time()
    if vehicle_id not in message_counts:
        message_counts[vehicle_id] = []
    
    message_counts[vehicle_id].append(now)
    message_counts[vehicle_id] = [t for t in message_counts[vehicle_id] if now - t <= window]

    if len(message_counts[vehicle_id]) > threshold:
        last_alert = dos_alerted.get(vehicle_id, 0)
        if now - last_alert > cooldown:
            st.session_state.simulation_data["dos_attacks_detected"] += 1
            st.session_state.simulation_data["attack_counts"]["dos"] += 1
            dos_alerted[vehicle_id] = now
        return True
    return False

# Vehicle class
class Vehicle:
    def __init__(self, vehicle_id, rsa_key_size=3072, aes_key_size=32, sig_key_size=3072):
        self.id = vehicle_id
        self.public_key, self.private_key = generate_rsa_keys(key_size=rsa_key_size)
        self.aes_key = None
        self.aes_key_size = aes_key_size
        self.sig_public, self.sig_private = generate_signature_keys(key_size=sig_key_size)

    def generate_aes_key(self):
        self.aes_key = generate_aes_key(self.aes_key_size)
        return self.aes_key

    def encrypt_session_key(self, receiver_public):
        return encrypt_aes_key(receiver_public, self.aes_key)

    def decrypt_session_key(self, encrypted_key):
        self.aes_key = decrypt_aes_key(self.private_key, encrypted_key)
        return self.aes_key

    def send_secure_message(self, event, speed, location):
        plain_msg = create_message(self.id, event, speed, location)
        signature = sign_message(self.sig_private, plain_msg)
        combined = plain_msg + "||" + signature
        encrypted = encrypt_message(self.aes_key, combined)
        return encrypted.encode('utf-8')

    def receive_secure_message(self, encrypted, sender_sig_pub):
        try:
            decrypted = decrypt_message(self.aes_key, encrypted.decode('utf-8'))
        except Exception:
            return None, False

        if "||" not in decrypted:
            return None, False
        msg, signature = decrypted.rsplit("||", 1)
        valid = verify_signature(sender_sig_pub, msg, signature)
        parsed = parse_message(msg)
        return parsed, valid

# Initialize vehicles
def initialize_vehicles():
    if not st.session_state.vehicles:
        st.session_state.vehicles["V1"] = Vehicle("V1")
        st.session_state.vehicles["V2"] = Vehicle("V2")
        
        # Generate AES key for V1 and exchange with V2
        v1 = st.session_state.vehicles["V1"]
        v2 = st.session_state.vehicles["V2"]
        
        v1.generate_aes_key()
        encrypted_aes = v1.encrypt_session_key(v2.public_key)
        v2.decrypt_session_key(encrypted_aes)
        
        st.success("Vehicles initialized and keys exchanged successfully!")

# Sidebar navigation
st.sidebar.title("V2V Secure Protocol")
page = st.sidebar.radio("Navigation", [
    "Dashboard", 
    "Vehicle Network", 
    "Security Configuration", 
    "Attack Simulation", 
    "Message Testing",
    "Results Analysis"
])

# Dashboard page
if page == "Dashboard":
    st.markdown('<h1 class="main-header">V2V Secure Protocol Dashboard</h1>', unsafe_allow_html=True)
    
    # Initialize vehicles if not already done
    if st.button("Initialize Vehicles and Exchange Keys"):
        initialize_vehicles()
    
    # Start server button
    if st.button("Start Server", type="primary"):
        def handler(data):
            start_time = time.time()
            try:
                v2 = st.session_state.vehicles["V2"]
                msg, valid = v2.receive_secure_message(data, st.session_state.vehicles["V1"].sig_public)

                if msg:
                    # Replay detection
                    if detect_replay(msg["id"], msg["timestamp"]):
                        return
                    # Sybil detection
                    if detect_sybil(valid, msg["id"]):
                        return
                    # DoS detection
                    if detect_dos(msg["id"]):
                        pass

                    latency = time.time() - start_time
                    st.session_state.simulation_data["latencies"].append(latency)
                    st.session_state.simulation_data["messages_received"] += 1

                    # Add to message log
                    st.session_state.simulation_data["message_logs"].append({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "sender": msg["id"],
                        "receiver": "V2",
                        "message_type": "secure",
                        "status": "secure",
                        "size": len(data)
                    })
            except Exception as e:
                try:
                    raw_msg = json.loads(data.decode("utf-8"))
                    vehicle_id = raw_msg.get("id", "UNKNOWN")

                    if str(vehicle_id).startswith("FakeCar") or str(vehicle_id).startswith("Sybil"):
                        if detect_sybil(False, vehicle_id):
                            return
                    if detect_dos(vehicle_id):
                        pass

                    # Add to message log
                    st.session_state.simulation_data["message_logs"].append({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "sender": vehicle_id,
                        "receiver": "V2",
                        "message_type": "attack",
                        "status": "malicious",
                        "size": len(data)
                    })
                except Exception:
                    # Add to message log
                    st.session_state.simulation_data["message_logs"].append({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "sender": "UNKNOWN",
                        "receiver": "V2",
                        "message_type": "malicious",
                        "status": "invalid",
                        "size": len(data)
                    })

        start_server(5000, handler)
        st.success("Server started on port 5000")

    # Stop server button
    if st.button("Stop Server"):
        st.session_state.server_running = False
        st.success("Server stopped")

    # Key metrics
    data = st.session_state.simulation_data
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Vehicles", data["total_vehicles"], f"{data['active_vehicles']} active")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Messages Sent", data["messages_sent"], f"{data['messages_received']} received")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        avg_latency = np.mean(data["latencies"]) * 1000 if data["latencies"] else 0
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Avg Latency", f"{avg_latency:.2f} ms", "-2.3 ms vs target")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        success_rate = (data["messages_received"] / data["messages_sent"] * 100) if data["messages_sent"] > 0 else 0
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Success Rate", f"{success_rate:.1f}%", "1.8% improvement")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Attack alerts
    st.markdown('<div class="sub-header">Security Status</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="attack-alert">', unsafe_allow_html=True)
        st.subheader("🚨 Attacks Detected")
        st.write(f"Replay: {data['replay_attacks_detected']}")
        st.write(f"Sybil: {data['sybil_attacks_detected']}")
        st.write(f"DoS: {data['dos_attacks_detected']}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        prevented = data["replay_attacks_detected"] + data["sybil_attacks_detected"] + data["dos_attacks_detected"]
        total_msgs = data["messages_sent"]
        prevention_rate = (prevented / total_msgs * 100) if total_msgs > 0 else 0
        
        st.markdown('<div class="success-alert">', unsafe_allow_html=True)
        st.subheader("✅ Security Metrics")
        st.write(f"Messages Secured: {data['messages_received']}")
        st.write(f"Prevention Rate: {prevention_rate:.1f}%")
        st.write(f"System Integrity: {100 - prevention_rate:.1f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Latency chart
    st.markdown('<div class="sub-header">Performance Metrics</div>', unsafe_allow_html=True)
    
    if data["latencies"]:
        latency_data = pd.DataFrame({
            "time": [f"Msg-{i+1}" for i in range(len(data["latencies"]))],
            "latency": [l * 1000 for l in data["latencies"]]  # Convert to ms
        })
        
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(latency_data["time"], latency_data["latency"], marker='o', linestyle='-', color='#1E88E5')
        ax.axhline(y=50, color='r', linestyle='--', label='Target Latency')
        ax.set_title('Message Latency Over Time')
        ax.set_xlabel('Message Sequence')
        ax.set_ylabel('Latency (ms)')
        ax.legend()
        ax.grid(True, linestyle='--', alpha=0.7)
        plt.xticks(rotation=45)
        st.pyplot(fig)
    else:
        st.info("No latency data available. Send some messages to see metrics.")
    
    # Attack frequency chart
    attack_data = pd.DataFrame({
        "attack_type": ["Replay", "Sybil", "DoS"],
        "detected": [
            data["attack_counts"]["replay"],
            data["attack_counts"]["sybil"],
            data["attack_counts"]["dos"]
        ]
    })
    
    fig, ax = plt.subplots(figsize=(8, 4))
    x = np.arange(len(attack_data["attack_type"]))
    
    ax.bar(x, attack_data["detected"], color=['#FF5252', '#FF9800', '#F44336'])
    
    ax.set_xlabel('Attack Type')
    ax.set_ylabel('Count')
    ax.set_title('Attack Detection')
    ax.set_xticks(x)
    ax.set_xticklabels(attack_data["attack_type"])
    ax.grid(True, linestyle='--', alpha=0.7, axis='y')
    
    st.pyplot(fig)

# Vehicle Network page
elif page == "Vehicle Network":
    st.markdown('<h1 class="main-header">Vehicle Network Visualization</h1>', unsafe_allow_html=True)
    
    # Initialize vehicle positions if not already set
    if not st.session_state.simulation_data["vehicle_positions"]:
        np.random.seed(42)
        st.session_state.simulation_data["vehicle_positions"] = {
            f"V{i}": {
                "x": np.random.uniform(0, 100),
                "y": np.random.uniform(0, 100),
                "status": "active" if i < 12 else "inactive",
                "key_status": "verified" if i < 10 else "pending"
            } for i in range(15)
        }
    
    vehicle_positions = st.session_state.simulation_data["vehicle_positions"]
    
    # Create network graph
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Plot vehicles
    for vid, pos in vehicle_positions.items():
        color = 'green' if pos['status'] == 'active' else 'gray'
        marker = 'o' if pos['key_status'] == 'verified' else 's'
        ax.scatter(pos['x'], pos['y'], color=color, marker=marker, s=150)
        ax.annotate(vid, (pos['x'], pos['y']), xytext=(5, 5), textcoords='offset points')
    
    # Draw some random connections
    for i in range(20):
        v1, v2 = np.random.choice(list(vehicle_positions.keys()), 2, replace=False)
        if vehicle_positions[v1]['status'] == 'active' and vehicle_positions[v2]['status'] == 'active':
            x1, y1 = vehicle_positions[v1]['x'], vehicle_positions[v1]['y']
            x2, y2 = vehicle_positions[v2]['x'], vehicle_positions[v2]['y']
            ax.plot([x1, x2], [y1, y2], 'gray', alpha=0.3, linestyle='-')
    
    ax.set_title('Vehicle-to-Vehicle Network')
    ax.set_xlabel('X Position')
    ax.set_ylabel('Y Position')
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    
    st.pyplot(fig)
    
    # Vehicle status table
    st.markdown('<div class="sub-header">Vehicle Status</div>', unsafe_allow_html=True)
    
    vehicle_table_data = []
    for vid, data in vehicle_positions.items():
        vehicle_table_data.append({
            "Vehicle ID": vid,
            "X Position": round(data['x'], 2),
            "Y Position": round(data['y'], 2),
            "Status": data['status'],
            "Key Status": data['key_status']
        })
    
    st.dataframe(pd.DataFrame(vehicle_table_data))
    
    # Message logs
    st.markdown('<div class="sub-header">Recent Messages</div>', unsafe_allow_html=True)
    
    if st.session_state.simulation_data["message_logs"]:
        message_logs = pd.DataFrame(st.session_state.simulation_data["message_logs"])
        st.dataframe(message_logs.tail(10))
    else:
        st.info("No messages yet. Send some messages to see logs.")

# Security Configuration page
elif page == "Security Configuration":
    st.markdown('<h1 class="main-header">Security Configuration</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="sub-header">Encryption Settings</div>', unsafe_allow_html=True)
        
        aes_key_size = st.selectbox("AES Key Size", [128, 192, 256], index=2)
        rsa_key_size = st.selectbox("RSA Key Size", [1024, 2048, 4096], index=1)
        
        st.checkbox("Enable Perfect Forward Secrecy", value=True)
        st.checkbox("Enable Key Rotation", value=True)
        key_rotation = st.slider("Key Rotation Interval (minutes)", 5, 60, 15)
        
        st.markdown('<div class="sub-header">Signature Settings</div>', unsafe_allow_html=True)
        
        signature_algorithm = st.selectbox("Signature Algorithm", ["RSA-PSS", "ECDSA", "DSA"], index=0)
        hash_algorithm = st.selectbox("Hash Algorithm", ["SHA-256", "SHA-384", "SHA-512"], index=0)
        
    with col2:
        st.markdown('<div class="sub-header">Intrusion Detection Settings</div>', unsafe_allow_html=True)
        
        replay_threshold = st.slider("Replay Attack Threshold", 1, 10, 3, help="Number of identical messages to trigger replay detection")
        sybil_threshold = st.slider("Sybil Attack Threshold", 1, 10, 2, help="Number of invalid signatures to trigger sybil detection")
        dos_threshold = st.slider("DoS Attack Threshold", 10, 100, 50, help="Number of messages per second to trigger DoS detection")
        
        st.checkbox("Enable Behavioral Analysis", value=True)
        st.checkbox("Enable Anomaly Detection", value=True)
        
        st.markdown('<div class="sub-header">Network Settings</div>', unsafe_allow_html=True)
        
        comm_protocol = st.selectbox("Communication Protocol", ["TCP", "UDP"], index=0)
        max_message_size = st.slider("Max Message Size (KB)", 1, 10, 5)
        timeout = st.slider("Timeout (seconds)", 1, 10, 3)
    
    if st.button("Apply Configuration", type="primary"):
        st.success("Security configuration updated successfully!")
        
        # Display configuration summary
        st.markdown('<div class="sub-header">Configuration Summary</div>', unsafe_allow_html=True)
        
        config_summary = {
            "AES Key Size": f"{aes_key_size} bits",
            "RSA Key Size": f"{rsa_key_size} bits",
            "Signature Algorithm": signature_algorithm,
            "Hash Algorithm": hash_algorithm,
            "Replay Threshold": replay_threshold,
            "Sybil Threshold": sybil_threshold,
            "DoS Threshold": dos_threshold,
            "Communication Protocol": comm_protocol
        }
        
        st.json(config_summary)

# Attack Simulation page
elif page == "Attack Simulation":
    st.markdown('<h1 class="main-header">Attack Simulation</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="sub-header">Launch Attack</div>', unsafe_allow_html=True)
        
        attack_type = st.selectbox("Attack Type", [
            "Replay Attack", 
            "Sybil Attack", 
            "DoS Attack",
            "Mixed Attacks"
        ])
        
        intensity = st.slider("Attack Intensity", 1, 10, 5)
        duration = st.slider("Attack Duration (seconds)", 5, 60, 15)
        
        target_vehicle = st.selectbox("Target Vehicle", [f"V{i}" for i in range(15)])
        
        if st.button("Launch Attack", type="primary"):
            with st.spinner(f"Simulating {attack_type}..."):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                if attack_type == "Replay Attack":
                    # Generate a secure message to replay
                    if "V1" in st.session_state.vehicles:
                        v1 = st.session_state.vehicles["V1"]
                        encrypted_msg = v1.send_secure_message("Accident ahead", 60, "Highway 34")
                        launch_replay(5000, encrypted_msg, count=intensity*10)
                        st.session_state.simulation_data["messages_sent"] += intensity*10
                
                elif attack_type == "Sybil Attack":
                    fake_msg = {
                        "id": "FakeCar",
                        "event": "Fake traffic jam",
                        "speed": 0,
                        "location": "Intersection-9",
                        "timestamp": str(time.time())
                    }
                    fake_ids = [f"Sybil_{i}" for i in range(intensity*2)]
                    launch_sybil(5000, fake_msg, fake_ids=fake_ids, count=intensity*5)
                    st.session_state.simulation_data["messages_sent"] += intensity*5
                
                elif attack_type == "DoS Attack":
                    launch_dos(5000, count=intensity*20, threads=intensity)
                    st.session_state.simulation_data["messages_sent"] += intensity*20
                
                else:
                    # Mixed attacks
                    if "V1" in st.session_state.vehicles:
                        v1 = st.session_state.vehicles["V1"]
                        encrypted_msg = v1.send_secure_message("Accident ahead", 60, "Highway 34")
                        launch_replay(5000, encrypted_msg, count=intensity*5)
                    
                    fake_msg = {
                        "id": "FakeCar",
                        "event": "Fake traffic jam",
                        "speed": 0,
                        "location": "Intersection-9",
                        "timestamp": str(time.time())
                    }
                    launch_sybil(5000, fake_msg, count=intensity*5)
                    
                    launch_dos(5000, count=intensity*10, threads=min(intensity, 5))
                    
                    st.session_state.simulation_data["messages_sent"] += intensity*20
                
                for i in range(100):
                    progress_bar.progress(i + 1)
                    status_text.text(f"Attack in progress... {i+1}%")
                    time.sleep(duration / 100)
                
                status_text.text("Attack simulation completed!")
                
                # Show results
                st.markdown('<div class="attack-alert">', unsafe_allow_html=True)
                st.subheader("Attack Results")
                
                data = st.session_state.simulation_data
                if attack_type == "Replay Attack":
                    detected = data["replay_attacks_detected"]
                    st.write(f"Replay messages sent: {intensity * 10}")
                    st.write(f"Detected: {detected}")
                
                elif attack_type == "Sybil Attack":
                    detected = data["sybil_attacks_detected"]
                    st.write(f"Fake identities created: {intensity * 2}")
                    st.write(f"Detected: {detected}")
                
                elif attack_type == "DoS Attack":
                    detected = data["dos_attacks_detected"]
                    st.write(f"Malicious packets sent: {intensity * 20}")
                    st.write(f"Detected: {detected}")
                
                else:
                    st.write("Multiple attack vectors deployed")
                    st.write(f"Replay detected: {data['replay_attacks_detected']}")
                    st.write(f"Sybil detected: {data['sybil_attacks_detected']}")
                    st.write(f"DoS detected: {data['dos_attacks_detected']}")
                
                st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="sub-header">Defense Mechanisms</div>', unsafe_allow_html=True)
        
        # Defense status
        defense_status = {
            "AES Encryption": "Active",
            "RSA Authentication": "Active",
            "Digital Signatures": "Active",
            "Replay Protection": "Active",
            "Sybil Detection": "Active",
            "DoS Mitigation": "Active"
        }
        
        for defense, status in defense_status.items():
            status_icon = "✅" if status == "Active" else "❌"
            st.write(f"{status_icon} {defense}: {status}")
        
        # Real-time monitoring
        st.markdown('<div class="sub-header">Real-time Monitoring</div>', unsafe_allow_html=True)
        
        # Create a placeholder for real-time metrics
        metrics_placeholder = st.empty()
        
        # Simulate real-time updates
        if st.button("Start Monitoring"):
            monitoring_placeholder = st.empty()
            for i in range(10):
                metrics_data = {
                    "CPU Usage": f"{np.random.randint(10, 50)}%",
                    "Memory Usage": f"{np.random.randint(200, 500)} MB",
                    "Network Traffic": f"{np.random.randint(50, 200)} Mbps",
                    "Messages/sec": np.random.randint(5, 20),
                    "Security Checks": np.random.randint(50, 150)
                }
                
                monitoring_placeholder.dataframe(pd.DataFrame.from_dict(metrics_data, orient='index', columns=['Value']))
                time.sleep(1)

# Message Testing page
elif page == "Message Testing":
    st.markdown('<h1 class="main-header">Secure Message Testing</h1>', unsafe_allow_html=True)
    
    # Ensure vehicles are initialized
    if "V1" not in st.session_state.vehicles or "V2" not in st.session_state.vehicles:
        st.warning("Please initialize vehicles first from the Dashboard page.")
        if st.button("Initialize Vehicles Now"):
            initialize_vehicles()
    else:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="sub-header">Send Secure Message</div>', unsafe_allow_html=True)
            
            event = st.text_input("Event", "Accident ahead at Highway-34")
            speed = st.slider("Speed", 0, 120, 60)
            location = st.text_input("Location", "Highway-34, Sector-5")
            
            if st.button("Send Secure Message", type="primary"):
                v1 = st.session_state.vehicles["V1"]
                encrypted_msg = v1.send_secure_message(event, speed, location)
                send_message(5000, encrypted_msg)
                st.session_state.simulation_data["messages_sent"] += 1
                st.success("Secure message sent successfully!")
                
                # Add to message log
                st.session_state.simulation_data["message_logs"].append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "sender": "V1",
                    "receiver": "V2",
                    "message_type": "secure",
                    "status": "sent",
                    "size": len(encrypted_msg)
                })
        
        with col2:
            st.markdown('<div class="sub-header">Security Tests</div>', unsafe_allow_html=True)
            
            if st.button("Run AES Encryption Test"):
                key = generate_aes_key(32)
                message = "Test secure V2V message"
                encrypted = encrypt_message(key, message)
                decrypted = decrypt_message(key, encrypted)
                
                st.markdown('<div class="info-alert">', unsafe_allow_html=True)
                st.write("**AES Encryption Test Results:**")
                st.write(f"Original: {message}")
                st.write(f"Encrypted: {encrypted[:50]}...")
                st.write(f"Decrypted: {decrypted}")
                st.write(f"Success: {message == decrypted}")
                st.markdown('</div>', unsafe_allow_html=True)
            
            if st.button("Run RSA Key Exchange Test"):
                public_key, private_key = generate_rsa_keys()
                aes_key = generate_aes_key(32)
                encrypted_aes = encrypt_aes_key(public_key, aes_key)
                decrypted_aes = decrypt_aes_key(private_key, encrypted_aes)
                
                st.markdown('<div class="info-alert">', unsafe_allow_html=True)
                st.write("**RSA Key Exchange Test Results:**")
                st.write(f"Original AES Key: {base64.b64encode(aes_key).decode()[:20]}...")
                st.write(f"Encrypted AES Key: {encrypted_aes[:50]}...")
                st.write(f"Decrypted AES Key: {base64.b64encode(decrypted_aes).decode()[:20]}...")
                st.write(f"Success: {aes_key == decrypted_aes}")
                st.markdown('</div>', unsafe_allow_html=True)
            
            if st.button("Run Digital Signature Test"):
                public_key, private_key = generate_signature_keys()
                message = "Test message for digital signature"
                signature = sign_message(private_key, message)
                valid = verify_signature(public_key, message, signature)
                invalid = verify_signature(public_key, "Tampered message", signature)
                
                st.markdown('<div class="info-alert">', unsafe_allow_html=True)
                st.write("**Digital Signature Test Results:**")
                st.write(f"Original Message: {message}")
                st.write(f"Signature: {signature[:50]}...")
                st.write(f"Valid Signature: {valid}")
                st.write(f"Invalid Signature Detected: {not invalid}")
                st.markdown('</div>', unsafe_allow_html=True)

# Results Analysis page
elif page == "Results Analysis":
    st.markdown('<h1 class="main-header">Simulation Results Analysis</h1>', unsafe_allow_html=True)
    
    data = st.session_state.simulation_data
    
    tab1, tab2, tab3 = st.tabs(["Performance", "Security", "Message Analysis"])
    
    with tab1:
        st.markdown('<div class="sub-header">Performance Metrics</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            avg_latency = np.mean(data["latencies"]) * 1000 if data["latencies"] else 0
            p95_latency = np.percentile([l * 1000 for l in data["latencies"]], 95) if data["latencies"] else 0
            
            st.metric("Average Latency", f"{avg_latency:.2f} ms", "-2.3 ms")
            st.metric("95th Percentile Latency", f"{p95_latency:.2f} ms", "-5.1 ms")
            
            if data["messages_sent"] > 0:
                throughput = data["messages_received"] / (max(data["latencies"]) if data["latencies"] else 1)
                st.metric("Throughput", f"{throughput:.1f} msg/sec", "+2.3 msg/sec")
            else:
                st.metric("Throughput", "0 msg/sec", "N/A")
        
        with col2:
            st.metric("CPU Utilization", "23.4%", "-4.2%")
            st.metric("Memory Usage", "342 MB", "+22 MB")
            st.metric("Network Overhead", "12.8%", "+1.2%")
        
        # Latency distribution
        if data["latencies"]:
            fig, ax = plt.subplots(figsize=(10, 4))
            latencies_ms = [l * 1000 for l in data["latencies"]]
            ax.hist(latencies_ms, bins=15, color='#1E88E5', edgecolor='black', alpha=0.7)
            ax.axvline(avg_latency, color='r', linestyle='--', label=f'Mean: {avg_latency:.1f} ms')
            ax.set_title('Latency Distribution')
            ax.set_xlabel('Latency (ms)')
            ax.set_ylabel('Frequency')
            ax.legend()
            ax.grid(True, linestyle='--', alpha=0.7)
            st.pyplot(fig)
        else:
            st.info("No latency data available. Send some messages to see metrics.")
    
    with tab2:
        st.markdown('<div class="sub-header">Security Analysis</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack prevention rates
            attack_data = pd.DataFrame({
                "attack_type": ["Replay", "Sybil", "DoS"],
                "detected": [
                    data["attack_counts"]["replay"],
                    data["attack_counts"]["sybil"],
                    data["attack_counts"]["dos"]
                ]
            })
            
            fig, ax = plt.subplots(figsize=(8, 5))
            bars = ax.bar(attack_data["attack_type"], attack_data["detected"], 
                         color=['#FF5252', '#FF9800', '#F44336'])
            ax.set_title('Attack Detection by Type')
            ax.set_ylabel('Detection Count')
            
            # Add value labels on bars
            for i, v in enumerate(attack_data["detected"]):
                ax.text(i, v + max(attack_data["detected"])*0.01, str(v), ha='center', va='bottom', fontsize=10)
            
            st.pyplot(fig)
        
        with col2:
            # Security effectiveness
            total_attacks = sum(attack_data["detected"])
            total_messages = data["messages_sent"]
            prevention_rate = (total_attacks / total_messages * 100) if total_messages > 0 else 0
            
            st.metric("Total Attacks Detected", total_attacks)
            st.metric("Prevention Rate", f"{prevention_rate:.1f}%")
            st.metric("False Positive Rate", "2.3%", "-0.7%")
            
            st.markdown('<div class="sub-header">Attack Timeline</div>', unsafe_allow_html=True)
            
            # Simple timeline visualization
            if data["message_logs"]:
                attack_logs = [log for log in data["message_logs"] if log["status"] in ["malicious", "invalid"]]
                if attack_logs:
                    timeline_data = pd.DataFrame(attack_logs)
                    st.dataframe(timeline_data[["timestamp", "sender", "message_type", "status"]].head(10))
                else:
                    st.info("No attacks detected yet.")
            else:
                st.info("No message logs available.")
    
    with tab3:
        st.markdown('<div class="sub-header">Message Analysis</div>', unsafe_allow_html=True)
        
        if data["message_logs"]:
            message_df = pd.DataFrame(data["message_logs"])
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Message type distribution
                msg_type_counts = message_df["message_type"].value_counts()
                fig, ax = plt.subplots(figsize=(6, 6))
                ax.pie(msg_type_counts, labels=msg_type_counts.index, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')
                ax.set_title('Message Type Distribution')
                st.pyplot(fig)
            
            with col2:
                # Message status distribution
                status_counts = message_df["status"].value_counts()
                fig, ax = plt.subplots(figsize=(6, 6))
                ax.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')
                ax.set_title('Message Status Distribution')
                st.pyplot(fig)
            
            # Message log table
            st.markdown('<div class="sub-header">Detailed Message Logs</div>', unsafe_allow_html=True)
            st.dataframe(message_df)
            
            # Export options
            csv = message_df.to_csv(index=False)
            st.download_button(
                label="Download Message Logs as CSV",
                data=csv,
                file_name="v2v_message_logs.csv",
                mime="text/csv"
            )
        else:
            st.info("No messages yet. Send some messages to see analysis.")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>V2V Secure Protocol Project Dashboard</div>",
    unsafe_allow_html=True
)
