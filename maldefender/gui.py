import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import platform
import threading
from pathlib import Path
import os

from .app_config import config
from .app_logger import Logger
from .malware_scanner import MalwareScanner

# --- THEME COLORS AND FONTS ---
PRIMARY_BG = "#121212"
PRIMARY_FG = "#00bcd4"
ACCENT = "#0288d1"
SUCCESS = "#00e5ff"   # Replaced green with soft cyan
DANGER = "#ef5350"
WARNING = "#fbc02d"
FONT = ("Segoe UI", 10)
FONT_HEADER = ("Segoe UI", 14, "bold")


class AntivirusGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{config.app_name} v{config.version}")
        self.root.geometry("980x720")
        self.root.configure(bg=PRIMARY_BG)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configure_styles()

        self.logger = Logger(self.log_to_gui)
        self.scanner = MalwareScanner(self.logger)

        self.scan_progress = tk.DoubleVar()
        self.realtime_status = tk.BooleanVar(value=False)
        self.log_visible = False

        self._build_layout()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        if config.demo_mode:
            self.logger.log("⚠️ Demo Mode Active: All detections are simulated.", "WARNING")


    def _configure_styles(self):
        self.style.configure("TFrame", background=PRIMARY_BG)
        self.style.configure("TLabel", background=PRIMARY_BG, foreground=PRIMARY_FG, font=FONT)
        self.style.configure("Accent.TButton", font=FONT, padding=10, relief="flat", borderwidth=0,
                             background="#1e1e1e", foreground=PRIMARY_FG)
        self.style.map("Accent.TButton",
                       background=[('active', "#00bcd4"), ('pressed', "#007c91")],
                       foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        self.style.configure("Header.TLabel", font=FONT_HEADER, foreground=ACCENT,
                             background=PRIMARY_BG, anchor="center")
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=22,
                             background="#1e1e1e", fieldbackground="#1e1e1e", foreground=PRIMARY_FG)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"),
                             background=ACCENT, foreground="#ffffff")
        self.style.map("Treeview", background=[("selected", "#3949ab")])

    def _build_layout(self):
        container = ttk.Frame(self.root)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Malvex Antivirus", style="Header.TLabel").pack(pady=(20, 10))

        # Scan Buttons (Horizontal Layout)
        btn_frame = ttk.Frame(container)
        btn_frame.pack(pady=10, padx=20, fill="x")

        for name, cmd in [
            ("Quick Scan", self.quick_scan),
            ("Full Scan", self.full_scan),
            ("Custom Scan", self.custom_scan),
            ("Stop Scan", self.stop_scan),
            ("Scan Graph", self.visualize_performance),
            ("Performance Benchmarks", self.show_performance_benchmarks),
            ("Benchmark Table", self.show_benchmark_table),

        ]:
            ttk.Button(btn_frame, text=name, command=cmd, style="Accent.TButton").pack(
                side="left", expand=True, fill="x", padx=6
            )

        # Real-Time Protection Status
        realtime_frame = ttk.Frame(container)
        realtime_frame.pack(fill="x", padx=20, pady=(15, 0))

        ttk.Label(realtime_frame, text="Real-Time Protection:").pack(side="left")
        self.realtime_label = ttk.Label(realtime_frame, text="Disabled", font=FONT_HEADER)
        self.realtime_label.pack(side="left", padx=(10, 0))

        self.toggle_button = ttk.Button(realtime_frame, text="Enable", command=self.toggle_realtime,
                                        style="Accent.TButton")
        self.toggle_button.pack(side="right")
        
         # --- Demo Mode Toggle UI ---
        demo_frame = ttk.Frame(container)
        demo_frame.pack(fill="x", padx=20, pady=(5, 0))

        ttk.Label(demo_frame, text="Demo Mode:").pack(side="left")
        self.demo_label = ttk.Label(demo_frame, text="Enabled" if config.demo_mode else "Disabled", font=FONT_HEADER)
        self.demo_label.pack(side="left", padx=(10, 0))
        self.demo_button = ttk.Button(demo_frame, text="Disable" if config.demo_mode else "Enable",
                                      command=self.toggle_demo_mode, style="Accent.TButton")
        self.demo_button.pack(side="right")


        # Progress bar
        ttk.Label(container, text="Progress:").pack(anchor='w', pady=(10, 0), padx=20)
        self.progress = ttk.Progressbar(container, variable=self.scan_progress, maximum=100, mode="determinate")
        self.progress.pack(fill=tk.X, padx=20)

        self.scan_status_label = ttk.Label(container, text="Status: Idle")
        self.scan_status_label.pack(anchor="w", pady=6, padx=20)

        # Results Table
        columns = ("File", "Status", "Details")
        self.results_tree = ttk.Treeview(container, columns=columns, show="headings")
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=300 if col == "Details" else 150)
        self.results_tree.pack(fill="both", expand=True, pady=5, padx=20)

        self.results_tree.tag_configure("infected", foreground=DANGER, font=(FONT[0], 10, 'bold'))
        self.results_tree.tag_configure("ok", foreground=SUCCESS)
        self.results_tree.tag_configure("error", foreground=WARNING)

        # Log viewer
        self.log_text = scrolledtext.ScrolledText(container, height=10, wrap=tk.WORD, state=tk.DISABLED,
                                                  background="#1e1e1e", foreground=PRIMARY_FG)
        self.log_text.pack(fill="both", expand=True, padx=20, pady=10)
        self.log_text.pack_forget()

        self.log_text.tag_config("ERROR", foreground=DANGER)
        self.log_text.tag_config("WARNING", foreground=WARNING)
        self.log_text.tag_config("INFO", foreground=PRIMARY_FG)
        self.log_text.tag_config("DEBUG", foreground="gray")

        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", anchor="w", relief="sunken",
                                    background=ACCENT, foreground="white")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_logs(self):
        if self.log_visible:
            self.log_text.pack_forget()
            self.log_toggle_btn.config(text="Show Logs")
        else:
            self.log_text.pack(fill="both", expand=True, padx=20, pady=10)
            self.log_toggle_btn.config(text="Hide Logs")
        self.log_visible = not self.log_visible

    def log_to_gui(self, message: str, level: str):
        def update():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n", level.upper())
            self.log_text.config(state=tk.DISABLED)
            self.log_text.see(tk.END)
            self.status_bar.config(text=message)
        self.root.after(0, update)

    def _start_scan(self, path: Path, label: str):
        if not path.exists():
            self.root.after(0, lambda: messagebox.showerror("Path Error", f"Directory not found:\n{path}"))
            return

        self.root.after(0, lambda: self.scan_progress.set(0))
        self.root.after(0, lambda: self.scan_status_label.config(text=f"Scanning: {label}"))
        self.root.after(0, lambda: self.results_tree.delete(*self.results_tree.get_children()))

        def scan_task():
            def progress_cb(p, f):
                self.root.after(0, lambda: self.scan_progress.set(p))

            results = self.scanner.scan_directory(path, progress_cb)

            try:
                from maldefender.visualizer import log_scan_stats
                log_scan_stats(len(results), sum(1 for r in results if r["status"] == "infected"))
            except Exception as e:
                self.logger.log(f"Failed to log scan stats: {e}", "WARNING")

            self.root.after(0, lambda: self.display_results(results))
            self.root.after(0, lambda: self.scan_status_label.config(text="Status: Done"))
            self.root.after(0, lambda: messagebox.showinfo("Scan Complete", f"Scan finished. {len(results)} files scanned."))

        threading.Thread(target=scan_task, daemon=True).start()

    def display_results(self, results):
        for r in results:
            file = Path(r["file"]).name
            status = r["status"]
            tag = "ok" if status == "clean" else "infected" if status == "infected" else "error"
            self.results_tree.insert("", tk.END, values=(file, status.title(), r.get("details", "")), tags=(tag,))

    def quick_scan(self):
        self._start_scan(Path.home() / "Downloads", "Quick Scan")

    def full_scan(self):
        home = Path.home() if platform.system() != "Windows" else Path(os.environ.get("USERPROFILE", "C:\\"))
        self._start_scan(home, "Full Scan")

    def custom_scan(self):
        path = filedialog.askdirectory(title="Select Folder to Scan")
        if path:
            self._start_scan(Path(path), "Custom Scan")

    def stop_scan(self):
        self.scanner.scanning = False
        self.scan_status_label.config(text="Status: Cancelling...")

    def toggle_realtime(self):
        if self.realtime_status.get():
            try:
                self.scanner.stop_realtime_protection()
                self.realtime_status.set(False)
                self.realtime_label.config(text="Disabled")
                self.toggle_button.config(text="Enable")
                self.status_bar.config(text="Real-time protection disabled.")
            except Exception as e:
                self.logger.log(f"Disable failed: {e}", "ERROR")
        else:
            try:
                self.scanner.start_realtime_protection()
                self.realtime_status.set(True)
                self.realtime_label.config(text="Enabled")
                self.toggle_button.config(text="Disable")
                self.status_bar.config(text="Real-time protection enabled.")
            except Exception as e:
                self.logger.log(f"Enable failed: {e}", "ERROR")

    def visualize_performance(self):
        stats = self.scanner.get_recent_scan_stats(limit=10)
        if not stats:
           messagebox.showinfo("Visualization", "No recent scans available to visualize.")
           return

        timestamps = [s["timestamp"] for s in stats]
        files = [s["files_scanned"] for s in stats]
        threats = [s["threats_found"] for s in stats]

        import matplotlib.pyplot as plt
        from matplotlib.ticker import LogLocator

        fig, ax = plt.subplots()
        ax.plot(timestamps, files, label="Files Scanned", marker="o", color="#00e5ff")
        ax.plot(timestamps, threats, label="Threats Found", marker="x", color="#ef5350")
        ax.set_xlabel("Timestamp")
        ax.set_ylabel("Count")
        ax.set_title("Scan Performance (Last 10 Scans)")
        ax.legend()
        ax.set_yscale("log")  # Optional for large ranges
        ax.yaxis.set_major_locator(LogLocator(base=10.0, numticks=10))
        fig.autofmt_xdate()

        plt.tight_layout()
        from pathlib import Path
        output_path = Path("maldefender/logs/scan_performance.png")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            plt.savefig(output_path, dpi=150)
            self.logger.log(f"Saved graph as: {output_path}", "INFO")
        except Exception as e:
            self.logger.log(f"Failed to save visualization: {e}", "ERROR")
        finally:
            plt.close()

    def show_performance_benchmarks(self):
        from matplotlib import pyplot as plt
        from pathlib import Path
        import json

        log_path = Path("maldefender/logs/performance_log.json")
        if not log_path.exists():
           messagebox.showinfo("Performance Benchmarks", "No benchmark logs found.")
           return

        try:
            with log_path.open("r") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load benchmark logs:\n{e}")
            return

        if not data:
            messagebox.showinfo("Performance Benchmarks", "No performance data available.")
            return

        # Show in matplotlib table
        fig, ax = plt.subplots(figsize=(10, 6))
        table_data = [["Time", "Scan Type", "Duration (s)", "Files", "Avg/File"]]
        for entry in data[-10:]:
            table_data.append([
                entry["timestamp"].split("T")[0],
                entry["scan_type"],
                entry["duration"],
                entry["files_scanned"],
                entry["avg_per_file"]
            ])

        table = ax.table(cellText=table_data, loc='center', cellLoc='center', colWidths=[0.2]*5)
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 2)
        ax.axis("off")
        plt.title("Malvex Performance Benchmarks (Last 10 Scans)")
        plt.tight_layout()
        plt.show()

    def show_benchmark_table(self):
        from pathlib import Path
        import json
        import tkinter as tk
        from tkinter import ttk

        log_path = Path("maldefender/logs/performance_log.json")
        if not log_path.exists():
            messagebox.showinfo("No Data", "No performance log found.")
            return

        try:
            with log_path.open("r") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load benchmark data:\n{e}")
            return

        # Create new window
        table_window = tk.Toplevel(self.root)
        table_window.title("Performance Benchmarks")
        table_window.geometry("720x400")
        table_window.configure(bg=PRIMARY_BG)

        columns = ("timestamp", "scan_type", "duration", "files_scanned", "avg_per_file")
        tree = ttk.Treeview(table_window, columns=columns, show="headings", height=15)
        for col in columns:
            tree.heading(col, text=col.replace("_", " ").title())
            tree.column(col, anchor="center")

        for row in data[-20:]:
            tree.insert("", tk.END, values=(
                row.get("timestamp", ""),
                row.get("scan_type", ""),
                row.get("duration", ""),
                row.get("files_scanned", ""),
                row.get("avg_per_file", "")
            ))

        tree.pack(fill="both", expand=True, padx=10, pady=10)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_window, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        
    def toggle_demo_mode(self):
        config.demo_mode = not config.demo_mode
        config.save_config()

        self.demo_label.config(text="Enabled" if config.demo_mode else "Disabled")
        self.demo_button.config(text="Disable" if config.demo_mode else "Enable")

        self.logger.log(
            f"Demo Mode toggled: {'Enabled' if config.demo_mode else 'Disabled'}",
            "INFO"
        )


    def on_close(self):
        if messagebox.askokcancel("Exit Malvex", "Are you sure you want to quit?"):
            self.root.destroy()

__all__ = ["MalvexGUI"]
