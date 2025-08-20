import matplotlib.pyplot as plt
import os
import numpy as np

def save_graphs(latencies, attack_counts, out_dir="simulation_results"):
    os.makedirs(out_dir, exist_ok=True)

    # 1. Latency graph (with moving average for realism)
    plt.figure()
    plt.plot(latencies, marker="o", label="Latency")
    if len(latencies) >= 5:
        window = min(10, len(latencies))
        moving_avg = np.convolve(latencies, np.ones(window)/window, mode='valid')
        plt.plot(range(window-1, len(latencies)), moving_avg, color="green", linestyle="--", label=f"Moving Avg ({window})")
    plt.title("Latency per Secure Message")
    plt.xlabel("Message #")
    plt.ylabel("Latency (s)")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "latency.png"))
    plt.close()

    # 2. Attack counts bar graph (with value labels)
    plt.figure()
    labels = list(attack_counts.keys())
    values = list(attack_counts.values())
    colors = ["red", "orange", "blue", "purple", "green"]
    plt.bar(labels, values, color=colors[:len(labels)])
    plt.title("Detected Attacks")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    for i, v in enumerate(values):
        plt.text(i, v + max(values)*0.01, str(v), ha='center', va='bottom', fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "attacks.png"))
    plt.close()

    print(f"[RESULTS] Graphs saved in {out_dir}/ (latency.png, attacks.png)")