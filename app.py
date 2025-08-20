# app.py - Refined Streamlit Frontend for V2V Secure Protocol Project

import streamlit as st
import subprocess
import os
import time
from pathlib import Path

st.set_page_config(
    page_title="V2V Secure Protocol",
    page_icon="🚗",
    layout="wide",
)

# ========================
# HEADER
# ========================
st.title("🚦 V2V Secure Protocol Simulation")
st.markdown(
    """
    ### Vehicle-to-Vehicle (V2V) Secure Communication
    This dashboard simulates **encrypted communication between vehicles** 
    with detection of cyberattacks like:
    - 🌀 **Replay Attack**
    - 🕵️ **Sybil Attack**
    - 💥 **DoS Attack**
    
    Use the configuration panel to define attack parameters and launch simulations.
    """
)

# ========================
# SIDEBAR - CONFIGURATION
# ========================
st.sidebar.header("⚙️ Attack Configuration")

sybil_event = st.sidebar.text_input("Sybil Event", "Fake traffic jam")
sybil_speed = st.sidebar.number_input("Sybil Speed (km/h)", min_value=0.0, max_value=200.0, value=0.0, step=1.0)
sybil_location = st.sidebar.text_input("Sybil Location", "Intersection-9")

fake_ids_input = st.sidebar.text_area("Fake IDs (comma-separated)", "FakeCar123, FakeCar456")
fake_ids = [id.strip() for id in fake_ids_input.split(",") if id.strip()]

# ========================
# MAIN AREA - TABS
# ========================
tabs = st.tabs(["▶️ Run Simulation", "📜 Live Logs", "📊 Results"])

with tabs[0]:
    st.subheader("▶️ Run Simulation")

    st.markdown(
        """
        Press the button below to start the simulation.  
        The system will exchange AES keys, send secure messages, 
        and then launch Replay, Sybil, and DoS attacks.
        """
    )

    if st.button("🚀 Start Simulation"):
        st.write("⏳ Running simulation...")

        process = subprocess.Popen(
            ["python", "-m", "src.main"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        log_area = st.empty()
        logs = ""

        # Live log streaming
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                logs += output
                with tabs[1]:
                    log_area.text_area("📜 Live Logs", logs, height=400)
            time.sleep(0.1)

        # Capture errors if any
        stderr_output = process.stderr.read()
        if stderr_output:
            logs += "\n[ERRORS]\n" + stderr_output
            with tabs[1]:
                log_area.text_area("📜 Live Logs", logs, height=400)

        st.success("✅ Simulation completed! Check the **Results** tab.")

with tabs[2]:
    st.subheader("📊 Simulation Results")

    results_path = Path("simulation_results")
    if results_path.exists():
        latency_img = results_path / "latency.png"
        attacks_img = results_path / "attacks.png"

        if latency_img.exists():
            st.image(str(latency_img), caption="⏱ Latency Over Time", use_column_width=True)
        if attacks_img.exists():
            st.image(str(attacks_img), caption="⚠️ Attack Detections", use_column_width=True)

        st.info("📂 All results are saved in the `simulation_results/` folder.")
    else:
        st.warning("⚠️ No simulation results found. Please run a simulation first.")
