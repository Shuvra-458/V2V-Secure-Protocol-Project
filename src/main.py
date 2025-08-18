import time
import json
from src.vehicles.vehicle import Vehicle
from src.network.socket_comm import start_server, send_message
from src.utils.logger import log_info, log_warning
from src.utils.plotter import save_graphs   # NEW
from src.security import intrusion_detection as IDS
from src.attacks.replay_attack import launch_replay
from src.attacks.sybil_attack import launch_sybil
from src.attacks.dos_attack import launch_dos

# Global metrics storage
latencies = []
attack_counts = {"replay": 0, "sybil": 0, "dos": 0}


def run_demo():
    v1 = Vehicle("V1")
    v2 = Vehicle("V2")

    # Step 1: Key exchange
    v1.generate_aes_key()
    encrypted_aes = v1.encrypt_session_key(v2.public_key)
    v2.decrypt_session_key(encrypted_aes)
    log_info("AES session key securely exchanged between V1 and V2")

    # Step 2: Define handler for incoming packets
    def handler(data):
        start_time = time.time()
        try:
            msg, valid = v2.receive_secure_message(data, v1.sig_public)

            if msg:
                # Replay detection
                if IDS.detect_replay(msg["id"], msg["timestamp"]):
                    attack_counts["replay"] += 1
                    return
                # Sybil detection
                if IDS.detect_sybil(valid, msg["id"]):
                    attack_counts["sybil"] += 1
                    return
                # DoS detection
                if IDS.detect_dos(msg["id"]):
                    attack_counts["dos"] += 1

                latency = time.time() - start_time
                latencies.append(latency)

                log_info(f"Vehicle2 received: {msg}")
                return

        except Exception as e:
            try:
                raw_msg = json.loads(data.decode("utf-8"))
                vehicle_id = raw_msg.get("id", "UNKNOWN")

                if str(vehicle_id).startswith("FakeCar"):
                    if IDS.detect_sybil(False, vehicle_id):
                        attack_counts["sybil"] += 1
                        return
                if IDS.detect_dos(vehicle_id):
                    attack_counts["dos"] += 1

            except Exception:
                log_warning(f"Invalid / malicious data received ({str(e)})")

    # Step 3: Start server for V2
    start_server(5000, handler)

    # Step 4: Normal secure message
    encrypted_msg = v1.send_secure_message(
        "Accident ahead at Highway-34", 60, "Highway-34, Sector-5"
    )
    send_message(5000, encrypted_msg)
    log_info("Vehicle1 sent secure message.")
    time.sleep(1)

    # Step 5: Replay Attack
    launch_replay(5000, encrypted_msg)
    attack_counts["replay"] += 1
    time.sleep(1)

    # Step 6: Sybil Attack
    launch_sybil(5000)
    attack_counts["sybil"] += 1
    time.sleep(1)

    # Step 7: DoS Attack
    launch_dos(5000, count=10)
    attack_counts["dos"] += 1
    time.sleep(2)

    # Step 8: Save graphs
    save_graphs(latencies, attack_counts)


if __name__ == "__main__":
    run_demo()
