# src/utils/plotter.py
import matplotlib.pyplot as plt
import os

def save_graphs(latencies, attack_counts, out_dir="simulation_results"):
    os.makedirs(out_dir, exist_ok=True)

    # 1. Latency graph
    plt.figure()
    plt.plot(latencies, marker="o")
    plt.title("Latency per Secure Message")
    plt.xlabel("Message #")
    plt.ylabel("Latency (s)")
    plt.savefig(os.path.join(out_dir, "latency.png"))
    plt.close()

    # 2. Attack counts bar graph
    plt.figure()
    labels = list(attack_counts.keys())
    values = list(attack_counts.values())
    plt.bar(labels, values, color=["red", "orange", "blue"])
    plt.title("Detected Attacks")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    plt.savefig(os.path.join(out_dir, "attacks.png"))
    plt.close()

    print(f"[RESULTS] Graphs saved in {out_dir}/ (latency.png, attacks.png)")
