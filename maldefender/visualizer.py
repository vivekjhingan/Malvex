import csv
from datetime import datetime
import matplotlib.pyplot as plt
import os

def visualize_performance():
    filepath = "maldefender_stats.csv"
    if not os.path.exists(filepath):
        print("No scan data found. Run a scan first.")
        return

    timestamps = []
    files_scanned = []
    threats_found = []

    with open(filepath, newline='') as csvfile:
        all_rows = list(csv.reader(csvfile))
        last_n_rows = all_rows[-10:]  # Only show last 10 scans
        reader = iter(last_n_rows)
        for row in reader:
            try:
                timestamps.append(datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                files_scanned.append(int(row[1]))
                threats_found.append(int(row[2]))
            except Exception as e:
                print(f"Skipping bad row: {row} | Error: {e}")

    if not timestamps:
        print("No valid data to display.")
        return

    fig, ax1 = plt.subplots(figsize=(10, 6))

    ax1.set_xlabel('Scan Time')
    ax1.set_ylabel('Files Scanned', color='tab:blue')
    ax1.plot(timestamps, files_scanned, color='tab:blue', marker='o', linewidth=2, label='Files Scanned')
    ax1.tick_params(axis='y', labelcolor='tab:blue')

    for i, val in enumerate(files_scanned):
        ax1.text(timestamps[i], val, str(val), color='tab:blue', fontsize=8)

    ax2 = ax1.twinx()
    ax2.set_ylabel('Threats Found', color='tab:red')
    ax2.set_yscale('log')
    ax2.plot(timestamps, threats_found, color='tab:red', marker='x', linestyle='--', linewidth=2, label='Threats Found')
    ax2.tick_params(axis='y', labelcolor='tab:red')
    ax2.set_ylim(0.1, max(threats_found + [1]))

    for i, val in enumerate(threats_found):
        ax2.text(timestamps[i], val, str(val), color='tab:red', fontsize=8)

    plt.title("MalDefender Scan Performance Over Time")
    fig.tight_layout()
    plt.grid(True)

    # Save the plot instead of showing it
    output_path = os.path.join("maldefender", "logs", "scan_performance.png")
    try:
        plt.savefig(output_path, dpi=150)
        print(f"[✓] Saved graph as '{output_path}'")
    except Exception as e:
        print(f"[✗] Failed to save image: {e}")
    finally:
        plt.close(fig)

def log_scan_stats(files_scanned: int, threats_found: int):
    with open("maldefender_stats.csv", "a") as f:
        f.write(f"{datetime.now()},{files_scanned},{threats_found}\n")
    save_scan_stats(files_scanned, threats_found)

def load_scan_stats_history(limit=10):
    import json
    from pathlib import Path

    json_path = Path("maldefender/logs/scan_stats.json")
    if not json_path.exists():
        return []

    try:
        with json_path.open("r") as f:
            stats = json.load(f)
            return stats[-limit:]
    except Exception as e:
        print(f"[ERROR] Could not read scan stats: {e}")
        return []

def save_scan_stats(files_scanned, threats_found):
    import json
    from pathlib import Path
    from datetime import datetime

    json_path = Path("maldefender/logs/scan_stats.json")
    stats = []

    if json_path.exists():
        with json_path.open("r") as f:
            try:
                stats = json.load(f)
            except json.JSONDecodeError:
                stats = []

    stats.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files_scanned": files_scanned,
        "threats_found": threats_found
    })

    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w") as f:
        json.dump(stats, f, indent=2)
        
def display_performance_table():
    import json
    from pathlib import Path
    import pandas as pd

    log_path = Path("maldefender/logs/performance_log.json")
    if not log_path.exists():
        print("[✗] No performance log found.")
        return

    with log_path.open("r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("[✗] Error parsing performance log.")
            return

    if not data:
        print("[!] No entries found in performance log.")
        return

    df = pd.DataFrame(data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp", ascending=False)

    print(df[[
        "timestamp",
        "scan_type",
        "duration",
        "files_scanned",
        "avg_per_file",
        "cpu_percent",
        "memory_mb",
        "io_read_mb",
        "io_write_mb"
    ]].to_string(index=False))


