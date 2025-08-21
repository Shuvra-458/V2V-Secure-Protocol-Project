import streamlit as st
import time
import json
import os
from src.vehicles.vehicle import Vehicle
from src.network.socket_comm import send_message
from src.security import intrusion_detection as IDS
from src.attacks.replay_attack import launch_replay
from src.attacks.sybil_attack import launch_sybil
from src.attacks.dos_attack import launch_dos
from src.utils import plotter

# Global logs list
if "logs" not in st.session_state:
    st.session_state.logs = []

def log_event(tag, msg, log_placeholder):
    """Push logs to both Streamlit and memory"""
    full_msg = f"[{tag}] {time.strftime('%H:%M:%S')} - {msg}"
    st.session_state.logs.append(full_msg)
    log_placeholder.text_area("Logs", "\n".join(st.session_state.logs), height=300)


def main():
    st.set_page_config(page_title="🚗 V2V Secure Protocol Simulator", layout="wide")
    st.title("🚗 Secure Communication Protocols for Vehicle-to-Vehicle Networks")

    st.sidebar.header("⚙️ Simulation Controls")

    # Placeholder for logs
    log_placeholder = st.empty()

    # Initialize vehicles only once
    if "v1" not in st.session_state:
        st.session_state.v1 = Vehicle("V1")
        st.session_state.v2 = Vehicle("V2")

        v1, v2 = st.session_state.v1, st.session_state.v2
        v1.generate_aes_key()
        encrypted_aes = v1.encrypt_session_key(v2.public_key)
        v2.decrypt_session_key(encrypted_aes)
        log_event("INFO", "AES session key securely exchanged between V1 and V2", log_placeholder)

    # Simulation Controls
    if st.sidebar.button("▶️ Send Normal Message"):
        v1, v2 = st.session_state.v1, st.session_state.v2
        encrypted_msg = v1.send_secure_message("Accident ahead at Highway-34", 60, "Highway-34, Sector-5")
        send_message(5000, encrypted_msg)
        log_event("INFO", "Vehicle1 sent secure message.", log_placeholder)

    if st.sidebar.button("🔁 Launch Replay Attack"):
        v1 = st.session_state.v1
        encrypted_msg = v1.send_secure_message("Replay Attack Packet", 40, "Sector-7")
        launch_replay(5000, encrypted_msg)
        log_event("ATTACK", "Replay Attack launched.", log_placeholder)

    if st.sidebar.button("👥 Launch Sybil Attack"):
        fake_msg = {
            "id": "FakeCar",
            "event": "Fake traffic jam",
            "speed": 0,
            "location": "Intersection-9",
            "timestamp": str(time.time())
        }
        fake_ids = [f"Sybil_{i}" for i in range(5)]
        launch_sybil(5000, fake_msg, fake_ids)
        log_event("ATTACK", "Sybil Attack launched.", log_placeholder)

    if st.sidebar.button("🌐 Launch DoS Attack"):
        launch_dos(5000, count=20)
        log_event("ATTACK", "DoS Attack launched.", log_placeholder)

    # -----------------------------
    # Results Section
    # -----------------------------
    st.subheader("📊 Simulation Results")
    if os.path.exists("simulation_results/latency.png") and os.path.exists("simulation_results/attacks.png"):
        st.image("simulation_results/latency.png", caption="Latency Graph")
        st.image("simulation_results/attacks.png", caption="Attack Detection Graph")

    if st.sidebar.button("📈 Generate Results"):
        plotter.plot_latency([10, 20, 30, 40], [12, 18, 35, 55])
        plotter.plot_attacks({"Replay": 3, "Sybil": 5, "DoS": 7})
        log_event("RESULTS", "Graphs generated and saved.", log_placeholder)


if __name__ == "__main__":
    main()
