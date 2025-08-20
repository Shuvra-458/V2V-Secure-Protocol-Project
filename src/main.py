import time
import json
from src.vehicles.vehicle import Vehicle
from src.network.socket_comm import start_server, send_message
from src.utils.logger import log_info, log_warning
from src.utils.plotter import save_graphs
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

    # Step 4: Normal secure message (user input for realism)
    print("Enter event for secure message (e.g., 'Accident ahead at Highway-34'):")
    event = input("> ").strip()
    print("Enter speed (e.g., 60):")
    try:
        speed = float(input("> ").strip())
    except ValueError:
        speed = 60.0
    print("Enter location (e.g., 'Highway-34, Sector-5'):")
    location = input("> ").strip()

    encrypted_msg = v1.send_secure_message(event, speed, location)
    send_message(5000, encrypted_msg)
    log_info("Vehicle1 sent secure message.")
    time.sleep(1)

    # Step 5: Replay Attack (user can choose count)
    print("Enter number of replay attack messages to send (default 50):")
    try:
        replay_count = int(input("> ").strip())
    except ValueError:
        replay_count = 50
    launch_replay(5000, encrypted_msg, count=replay_count)
    attack_counts["replay"] += 1
    time.sleep(1)

        # Step 6: Sybil Attack (user can provide fake message and IDs)
    print("Enter message for Sybil attack (e.g., 'Fake traffic jam'):")
    sybil_event = input("> ").strip()
    print("Enter speed for Sybil attack (e.g., 0):")
    try:
        sybil_speed = float(input("> ").strip())
    except ValueError:
        sybil_speed = 0.0
    print("Enter location for Sybil attack (e.g., 'Intersection-9'):")
    sybil_location = input("> ").strip()

    fake_msg = {
        "id": "FakeCar",
        "event": sybil_event,
        "speed": sybil_speed,
        "location": sybil_location,
        "timestamp": str(time.time())
    }

    print("Enter comma-separated fake IDs for Sybil attack (or press Enter for default):")
    fake_ids_input = input("> ").strip()

    if fake_ids_input:
        fake_ids = [id.strip() for id in fake_ids_input.split(",") if id.strip()]
        print(f"[INFO] Using custom fake IDs: {fake_ids}")
    else:
        fake_ids = None
        default_ids = [f"Sybil_{i}" for i in range(10)]
        print(f"[INFO] No IDs entered, using default fake IDs: {default_ids}")

    launch_sybil(5000, fake_msg, fake_ids=fake_ids)
    attack_counts["sybil"] += 1
    time.sleep(1)

    # Step 7: DoS Attack (user can choose count and threads)
    print("Enter number of DoS attack messages per thread (default 10):")
    try:
        dos_count = int(input("> ").strip())
    except ValueError:
        dos_count = 10
    print("Enter number of threads for DoS attack (default 5):")
    try:
        dos_threads = int(input("> ").strip())
    except ValueError:
        dos_threads = 5
    launch_dos(5000, count=dos_count, threads=dos_threads)
    attack_counts["dos"] += 1
    time.sleep(2)

    # Step 8: Save graphs
    save_graphs(latencies, attack_counts)


if __name__ == "__main__":
    run_demo()