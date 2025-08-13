# maldefender/gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
import platform
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any
import shutil
import os

from .app_config import config
from .app_logger import Logger
from .malware_scanner import MalwareScanner
from typing import Tuple

class AntivirusGUI:
    """Modern GUI for the antivirus"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{config.app_name} v{config.version}")
        self.root.minsize(800, 600)
        try:
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            w, h = 900, 700
            x = (screen_width // 2) - (w // 2)
            y = (screen_height // 2) - (h // 2)
            self.root.geometry(f"{w}x{h}+{x}+{y}")
        except tk.TclError:
            self.root.geometry("900x700")

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10, "bold"), padding=5)
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"), foreground="#333")
        self.style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        self.style.configure("Red.TLabel", foreground="red", background="#f0f0f0")
        self.style.configure("Green.TLabel", foreground="green", background="#f0f0f0")

        # Components
        self.logger = Logger(self.log_to_gui_scrolledtext)
        self.scanner = MalwareScanner(self.logger)

        # GUI vars
        self.scan_progress_var = tk.DoubleVar()
        self.realtime_status_var = tk.StringVar(value="Initializing...")
        self.current_scan_path_var = tk.StringVar(value="N/A")
        self.scan_thread: Optional[threading.Thread] = None
        self.scanner = MalwareScanner(self.logger)
        self.scanner.notify_threat = self._notify_threat_from_realtime  # NEW


        self.setup_gui()
        self.update_realtime_status_display()
        self.load_initial_logs()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ---------- Window lifecycle ----------
    def on_closing(self):
        if self.scan_thread and self.scan_thread.is_alive():
            if messagebox.askyesno("Scan in Progress", "A scan is currently in progress. Are you sure you want to exit?"):
                self.scanner.scanning = False
                if self.scan_thread:
                    self.scan_thread.join(timeout=2)
                self.cleanup_and_destroy()
            else:
                return
        else:
            self.cleanup_and_destroy()

    def cleanup_and_destroy(self):
        self.logger.log("MalDefender GUI closing...")
        # If needed, explicit stop of realtime can be added here.
        self.root.destroy()

    def load_initial_logs(self):
        if config.log_file.exists():
            try:
                with open(config.log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines[-100:]:
                        self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
            except Exception as e:
                self.logger.log(f"Could not load initial logs: {e}", "ERROR")

    # ---------- Layout ----------
    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(main_frame, text=config.app_name, style="Header.TLabel")
        title_label.pack(pady=(0, 20), anchor="center")

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Scan
        scan_frame = ttk.Frame(notebook, padding="10")
        notebook.add(scan_frame, text=" Scanner ")
        self.setup_scan_tab(scan_frame)

        # Real-time
        realtime_frame = ttk.Frame(notebook, padding="10")
        notebook.add(realtime_frame, text=" Real-Time Protection ")
        self.setup_realtime_tab(realtime_frame)

        # Quarantine
        quarantine_frame = ttk.Frame(notebook, padding="10")
        notebook.add(quarantine_frame, text=" Quarantine ")
        self.setup_quarantine_tab(quarantine_frame)

        # Settings
        settings_frame = ttk.Frame(notebook, padding="10")
        notebook.add(settings_frame, text=" Settings ")
        self.setup_settings_tab(settings_frame)

        # Logs
        log_frame = ttk.Frame(notebook, padding="10")
        notebook.add(log_frame, text=" Logs ")
        self.setup_log_tab(log_frame)

    def setup_scan_tab(self, parent: ttk.Frame):
        options_frame = ttk.LabelFrame(parent, text="Scan Options", padding="10")
        options_frame.pack(fill=tk.X, pady=5)

        ttk.Button(options_frame, text="Quick Scan (Downloads)", command=self.quick_scan).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        ttk.Button(options_frame, text="Full System Scan", command=self.full_scan).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        ttk.Button(options_frame, text="Custom Scan...", command=self.custom_scan).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        ttk.Button(options_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

        progress_frame = ttk.LabelFrame(parent, text="Scan Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=5)

        self.scan_status_label = ttk.Label(progress_frame, text="Status: Ready to scan.")
        self.scan_status_label.pack(pady=(0, 5), anchor="w")

        self.current_file_label = ttk.Label(progress_frame, textvariable=self.current_scan_path_var, wraplength=700)
        self.current_file_label.pack(pady=(0, 5), anchor="w", fill=tk.X)

        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.scan_progress_var, length=400)
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)

        results_frame = ttk.LabelFrame(parent, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ("File", "Path", "Status", "Details")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")

        self.results_tree.heading("File", text="File Name")
        self.results_tree.column("File", width=150, anchor=tk.W)
        self.results_tree.heading("Path", text="Full Path / Archive Location")
        self.results_tree.column("Path", width=300, anchor=tk.W)
        self.results_tree.heading("Status", text="Status")
        self.results_tree.column("Status", width=100, anchor=tk.W)
        self.results_tree.heading("Details", text="Details (e.g., Hash Type)")
        self.results_tree.column("Details", width=150, anchor=tk.W)

        scrollbar_y = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        scrollbar_x = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def setup_realtime_tab(self, parent: ttk.Frame):
        status_frame = ttk.LabelFrame(parent, text="Protection Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)

        ttk.Label(status_frame, text="Real-time Protection:").pack(side=tk.LEFT, padx=5)
        self.realtime_status_display_label = ttk.Label(status_frame, textvariable=self.realtime_status_var)
        self.realtime_status_display_label.pack(side=tk.LEFT, padx=5)

        controls_frame = ttk.LabelFrame(parent, text="Controls", padding="10")
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Button(controls_frame, text="Enable Protection", command=self.enable_realtime).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(controls_frame, text="Disable Protection", command=self.disable_realtime).pack(side=tk.LEFT, padx=5, pady=5)

        paths_frame = ttk.LabelFrame(parent, text="Monitored Paths", padding="10")
        paths_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.paths_listbox = tk.Listbox(paths_frame, height=5, selectmode=tk.SINGLE)
        self.paths_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        path_buttons_frame = ttk.Frame(paths_frame)
        path_buttons_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Button(path_buttons_frame, text="Add Path...", command=self.add_monitor_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(path_buttons_frame, text="Remove Selected Path", command=self.remove_monitor_path).pack(side=tk.LEFT, padx=5)

        self.update_paths_listbox()

    def setup_quarantine_tab(self, parent: ttk.Frame):
        list_frame = ttk.LabelFrame(parent, text="Quarantined Files", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ("File", "Original Path Hint", "Date Quarantined", "Size")
        self.quarantine_tree = ttk.Treeview(list_frame, columns=columns, show="headings")

        self.quarantine_tree.heading("File", text="Quarantined File Name")
        self.quarantine_tree.column("File", width=250, anchor=tk.W)
        self.quarantine_tree.heading("Original Path Hint", text="Original Path (if known)")
        self.quarantine_tree.column("Original Path Hint", width=200, anchor=tk.W)
        self.quarantine_tree.heading("Date Quarantined", text="Date Quarantined")
        self.quarantine_tree.column("Date Quarantined", width=150, anchor=tk.W)
        self.quarantine_tree.heading("Size", text="Size")
        self.quarantine_tree.column("Size", width=100, anchor=tk.E)

        q_scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        q_scrollbar_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.quarantine_tree.xview)
        self.quarantine_tree.configure(yscrollcommand=q_scrollbar_y.set, xscrollcommand=q_scrollbar_x.set)

        q_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        q_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.quarantine_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        q_controls_frame = ttk.Frame(parent, padding="5 0 0 0")
        q_controls_frame.pack(fill=tk.X, pady=5)

        ttk.Button(q_controls_frame, text="Refresh List", command=self.refresh_quarantine_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(q_controls_frame, text="Restore Selected...", command=self.restore_from_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(q_controls_frame, text="Delete Selected Permanently", command=self.delete_from_quarantine).pack(side=tk.LEFT, padx=5)

        self.refresh_quarantine_list()

    def setup_settings_tab(self, parent: ttk.Frame):
        sig_frame = ttk.LabelFrame(parent, text="Signature Management", padding="10")
        sig_frame.pack(fill=tk.X, pady=5, anchor="n")

        add_sig_frame = ttk.Frame(sig_frame)
        add_sig_frame.pack(fill=tk.X, pady=5)

        ttk.Label(add_sig_frame, text="Signature (Hash):").pack(side=tk.LEFT, padx=(0, 5))
        self.sig_entry = ttk.Entry(add_sig_frame, width=50)
        self.sig_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.hash_type_var = tk.StringVar(value="SHA256")
        hash_combo = ttk.Combobox(add_sig_frame, textvariable=self.hash_type_var, values=["MD5", "SHA256"], width=8, state="readonly")
        hash_combo.pack(side=tk.LEFT, padx=5)

        ttk.Button(sig_frame, text="Add Signature to Database", command=self.add_signature_gui).pack(pady=5, anchor="e")

        stats_frame = ttk.LabelFrame(parent, text="Scan Statistics (Last Scan)", padding="10")
        stats_frame.pack(fill=tk.X, pady=5, anchor="n")

        self.stats_display_label = ttk.Label(stats_frame, text="No scans performed in this session yet.", justify=tk.LEFT)
        self.stats_display_label.pack(padx=5, pady=5, anchor="w")
        self.update_scan_statistics_display()

    def setup_log_tab(self, parent: ttk.Frame):
        self.log_text = scrolledtext.ScrolledText(parent, height=15, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_configure("ERROR", foreground="red")
        self.log_text.tag_configure("WARNING", foreground="orange")
        self.log_text.tag_configure("INFO", foreground="black")
        self.log_text.tag_configure("DEBUG", foreground="gray")

    # ---------- Logging callback ----------
    def log_to_gui_scrolledtext(self, message: str, level: str):
        """Thread-safe callback for log messages to GUI"""
        def _update_log_text():
            if self.log_text.winfo_exists():
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n", level.upper())
                self.log_text.config(state=tk.DISABLED)
                self.log_text.see(tk.END)

        if hasattr(self.root, "after_idle"):
            self.root.after_idle(_update_log_text)

    # ---------- Scanning ----------
    def _start_scan(self, scan_path: Path, scan_type_name: str):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "A scan is already in progress. Please wait or stop it.")
            return

        if not scan_path.exists():
            messagebox.showerror("Error", f"Scan path does not exist: {scan_path}")
            return

        self.logger.log(f"Starting {scan_type_name} on: {scan_path}", "INFO")
        self.results_tree.delete(*self.results_tree.get_children())
        self.scan_progress_var.set(0)
        self.current_scan_path_var.set("Initializing scan...")
        self.scan_status_label.config(text=f"Status: {scan_type_name} started...")

        self.scan_thread = threading.Thread(target=self.perform_scan_and_update_gui, args=(scan_path,), daemon=True)
        self.scan_thread.start()

    def quick_scan(self):
        downloads_path = Path.home() / "Downloads"
        self._start_scan(downloads_path, "Quick Scan")

    def full_scan(self):
        if platform.system() == "Windows":
            scan_path = Path(os.environ.get("USERPROFILE", "C:\\Users"))
            if not scan_path.exists():
                scan_path = Path("C:\\")
        else:
            scan_path = Path.home()

        if messagebox.askyesno("Full Scan Confirmation",
                               f"Full system scan will target: {scan_path}\nThis may take a significant amount of time. Continue?"):
            self._start_scan(scan_path, "Full System Scan")

    def custom_scan(self):
        path_str = filedialog.askdirectory(title="Select Folder to Scan")
        if path_str:
            self._start_scan(Path(path_str), "Custom Scan")

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the current scan?"):
                self.scanner.scanning = False
                self.scan_status_label.config(text="Status: Scan stopping...")
                self.logger.log("User requested scan stop.", "INFO")
        else:
            messagebox.showinfo("Stop Scan", "No scan is currently in progress.")

    def perform_scan_and_update_gui(self, scan_path: Path):
        """Performs the scan and updates GUI elements safely."""
        def progress_callback_gui(progress: float, current_file_display: str):
            if not self.root.winfo_exists(): return
            self.root.after_idle(lambda: self.scan_progress_var.set(progress))
            self.root.after_idle(lambda: self.current_scan_path_var.set(f"Scanning: {current_file_display}"))

        # NOTE: pass-through auto_action is intentionally None; we want to PROMPT after scan
        results = self.scanner.scan_directory(scan_path, progress_callback_gui, auto_action=None)

        if not self.root.winfo_exists():
            return
        self.root.after_idle(self.update_scan_results_tree, results)
        self.root.after_idle(self.update_scan_statistics_display)
        self.root.after_idle(lambda: self.scan_status_label.config(text="Status: Scan completed."))
        self.root.after_idle(lambda: self.current_scan_path_var.set(f"Completed scan of: {scan_path}"))
        self.root.after_idle(lambda: self.scan_progress_var.set(100))
        self.scanner.scanning = False

        # NEW: Prompt for action(s) AFTER scan completes
        self.root.after_idle(lambda: self._prompt_actions_after_scan(results))
    
    def _prompt_actions_after_scan(self, results: List[Dict]):
        """Iterate infected results and prompt user for Quarantine / Delete / Ignore."""
        infected_items: List[Tuple[Path, Dict]] = []
        for r in results:
            if r.get("status") == "infected":
                infected_items.append((Path(str(r["file"])), r))

        if not infected_items:
            return

        for file_path, r in infected_items:
            # If this was an archive detection with nested threats, we act on the archive itself.
            is_archive = file_path.suffix.lower() in config.archive_types

            # Build message
            details_lines = []
            if is_archive:
                details_lines.append(f"Threats found in archive: {file_path.name}")
                for t in r.get("threats", []):
                    ht = t.get("hash_types") or [t.get("hash_type", "N/A")]
                    if not isinstance(ht, list): ht = [ht]
                    details_lines.append(f"  - {t.get('file')}  |  Type(s): {', '.join(ht)}")
            else:
                t = (r.get("threats") or [{}])[0]
                ht = t.get("hash_types") or [t.get("hash_type", "N/A")]
                if not isinstance(ht, list): ht = [ht]
                details_lines.append(f"Threat: {file_path.name}  |  Type(s): {', '.join(ht)}")

            details_text = "\n".join(details_lines)
            action = self._modal_action_prompt(file_path, details_text)
            if action == "quarantine":
                ok, msg = self.scanner.quarantine_path(file_path)
                if ok:
                    self.logger.log(f"User quarantined: {file_path}", "WARNING")
                else:
                    self.logger.log(f"Quarantine failed: {file_path} ({msg})", "ERROR")
            elif action == "delete":
                ok, msg = self.scanner.delete_path(file_path)
                if ok:
                    self.logger.log(f"User deleted: {file_path}", "WARNING")
                else:
                    self.logger.log(f"Delete failed: {file_path} ({msg})", "ERROR")
            else:
                self.logger.log(f"User ignored: {file_path}", "INFO")

        # refresh quarantine tab in case items moved
        self.refresh_quarantine_list()
        # and refresh results tree styling (some files may have been moved/deleted)
        self.update_scan_results_tree(results)

    def _modal_action_prompt(self, file_path: Path, details_text: str) -> str:
        """
        Show a modal dialog with details and 3 buttons: Quarantine, Ignore, Delete.
        Returns one of {"quarantine","ignore","delete"}.
        """
        win = tk.Toplevel(self.root)
        win.title("Threat Detected")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        ttk.Label(win, text="Threat Detected", style="Header.TLabel").pack(padx=16, pady=(12, 8), anchor="w")
        msg = tk.Text(win, width=80, height=10, wrap=tk.WORD)
        msg.insert("1.0", f"Path: {file_path}\n\n{details_text}")
        msg.config(state=tk.DISABLED)
        msg.pack(padx=16, pady=(0, 12))

        choice = {"val": "ignore"}  # default

        btns = ttk.Frame(win)
        btns.pack(padx=16, pady=(0, 12), fill=tk.X)

        def _choose(val: str):
            choice["val"] = val
            win.destroy()

        q_btn = ttk.Button(btns, text="Quarantine", command=lambda: _choose("quarantine"))
        i_btn = ttk.Button(btns, text="Ignore", command=lambda: _choose("ignore"))
        d_btn = ttk.Button(btns, text="Delete", command=lambda: _choose("delete"))
        q_btn.pack(side=tk.LEFT, padx=(0, 8))
        i_btn.pack(side=tk.LEFT, padx=(0, 8))
        d_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Enter/Escape bindings
        win.bind("<Return>", lambda _e: _choose("quarantine"))
        win.bind("<Escape>", lambda _e: _choose("ignore"))

        # Center over root
        try:
            win.update_idletasks()
            rw = self.root.winfo_rootx()
            rh = self.root.winfo_rooty()
            rw2 = self.root.winfo_width()
            rh2 = self.root.winfo_height()
            ww = win.winfo_width()
            wh = win.winfo_height()
            x = rw + (rw2 - ww)//2
            y = rh + (rh2 - wh)//2
            win.geometry(f"+{x}+{y}")
        except Exception:
            pass

        win.wait_window()
        return choice["val"]


    def update_scan_results_tree(self, results: List[Dict]):
        """Update scan results in GUI Treeview."""
        self.results_tree.delete(*self.results_tree.get_children())

        for result in results:
            file_full_path = Path(result["file"])
            file_name = file_full_path.name
            status = result["status"].upper()

            if result["status"] == "infected":
                status_tag = "infected"
                if result.get("threats"):
                    # Non-archive file infection
                    if file_full_path.suffix.lower() not in config.archive_types:
                        threat_info = result["threats"][0]
                        ht = threat_info.get("hash_types") or [threat_info.get("hash_type", "N/A")]
                        if not isinstance(ht, list):
                            ht = [ht]
                        details = f"Type(s): {', '.join(ht)} Match"
                        self.results_tree.insert(
                            "", tk.END,
                            values=(file_name, str(file_full_path), status, details),
                            tags=(status_tag,)
                        )
                    # Archive infection(s)
                    else:
                        self.results_tree.insert(
                            "", tk.END,
                            values=(file_name, str(file_full_path), f"{status} (Contains Threats)", "See below"),
                            tags=(status_tag,)
                        )
                        for threat_in_archive in result["threats"]:
                            ht = threat_in_archive.get("hash_types") or [threat_in_archive.get("hash_type", "N/A")]
                            if not isinstance(ht, list):
                                ht = [ht]
                            details_archive = (
                                f"Inside {file_name}: {threat_in_archive.get('file')}, "
                                f"Type(s): {', '.join(ht)}"
                            )
                            self.results_tree.insert(
                                "", tk.END,
                                values=(f"↳ {threat_in_archive.get('file')}",
                                        str(file_full_path), "THREAT INSIDE", details_archive),
                                tags=("infected", "sub_item")
                            )
            elif result["status"] not in {"clean", "skipped_in_quarantine", "skipped_not_file"}:
                status_tag = "error"
                details = result.get("action_taken") or "Error during scan"
                self.results_tree.insert("", tk.END,
                    values=(file_name, str(file_full_path), status, details), tags=(status_tag,))

        self.results_tree.tag_configure("infected", foreground="red")
        self.results_tree.tag_configure("error", foreground="orange")
        self.results_tree.tag_configure("sub_item", foreground="#555555")

    def update_scan_statistics_display(self):
        """Update the statistics label in the Settings tab."""
        stats = self.scanner.scan_stats
        stats_text = (
            f"Files Scanned: {stats['files_scanned']}\n"
            f"Threats Found: {stats['threats_found']}\n"
            f"Archives Scanned: {stats['archives_scanned']}\n"
            f"Scan Errors: {stats['errors']}"
        )
        if hasattr(self, 'stats_display_label'):
            self.stats_display_label.config(text=stats_text)

    # ---------- Real-time controls ----------
    def enable_realtime(self):
        """
        Enable real-time protection and start the behavioral monitor.
        Start behavior monitor on success (idempotent), not in the exception block.
        """
        try:
            self.scanner.start_realtime_protection()

            # Start behavior monitor with GUI notifier (safe if already started)
            try:
                self.scanner.start_behavior_monitor(self._notify_behavior_incident_gui)
            except AttributeError:
                # MalwareScanner doesn't have behavior methods yet
                self.logger.log("Behavior monitor integration missing in MalwareScanner.", "ERROR")
            except Exception as e:
                self.logger.log(f"Failed to start behavior monitor: {e}", "ERROR")

            self.update_realtime_status_display()
            if config.realtime_enabled:
                messagebox.showinfo("Success", "Real-time protection has been enabled.")
            else:
                messagebox.showwarning(
                    "Real-Time Protection",
                    "Real-time protection could not be started. Check logs and monitored paths.",
                )
        except Exception as e:
            # Do NOT try to start behavior monitor here—startup failed above.
            self.logger.log(f"Failed to enable real-time protection via GUI: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to enable protection: {e}")
            self.update_realtime_status_display()

    def disable_realtime(self):
        """
        Stop the behavioral monitor, then disable real-time protection.
        Stopping behavior first avoids leaving any suspended PIDs if your monitor auto-suspends.
        """
        try:
            # Stop behavior monitor first (ignore if not available)
            try:
                self.scanner.stop_behavior_monitor()
            except AttributeError:
                pass
            except Exception as e:
                self.logger.log(f"Failed to stop behavior monitor: {e}", "ERROR")

            self.scanner.stop_realtime_protection()
            self.update_realtime_status_display()
            messagebox.showinfo("Success", "Real-time protection has been disabled.")
        except Exception as e:
            self.logger.log(f"Failed to disable real-time protection via GUI: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to disable protection: {e}")
            self.update_realtime_status_display()


    def update_realtime_status_display(self):
        if config.realtime_enabled:
            self.realtime_status_var.set("✅ Enabled")
            if hasattr(self, 'realtime_status_display_label'):
                self.realtime_status_display_label.config(style="Green.TLabel")
        else:
            self.realtime_status_var.set("❌ Disabled")
            if hasattr(self, 'realtime_status_display_label'):
                self.realtime_status_display_label.config(style="Red.TLabel")

    def add_monitor_path(self):
        path_str = filedialog.askdirectory(title="Select Folder to Monitor for Real-Time Protection")
        if path_str:
            path_to_add = str(Path(path_str).resolve())
            if path_to_add not in config.monitor_paths:
                config.monitor_paths.append(path_to_add)
                config.save_config()
                self.update_paths_listbox()
                self.logger.log(f"Added monitoring path: {path_to_add}", "INFO")

                if config.realtime_enabled:
                    messagebox.showinfo("Real-Time Protection", "Restarting real-time protection to apply new path.")
                    self.scanner.start_realtime_protection()
                    self.update_realtime_status_display()
            else:
                messagebox.showinfo("Info", "Path already in monitoring list.")

    def remove_monitor_path(self):
        selection_indices = self.paths_listbox.curselection()
        if selection_indices:
            index = selection_indices[0]
            path_to_remove = config.monitor_paths.pop(index)
            config.save_config()
            self.update_paths_listbox()
            self.logger.log(f"Removed monitoring path: {path_to_remove}", "INFO")

            if config.realtime_enabled:
                messagebox.showinfo("Real-Time Protection", "Restarting real-time protection to apply changes.")
                self.scanner.start_realtime_protection()
                self.update_realtime_status_display()
        else:
            messagebox.showwarning("Warning", "Please select a path to remove.")
            
    def _notify_threat_from_realtime(self, result: Dict) -> None:
        """GUI-side notifier for real-time infections: prompt user and act."""
        # This may be called from a watchdog thread; hop to Tk thread.
        def _show():
            file_path = Path(str(result["file"]))
            is_archive = file_path.suffix.lower() in config.archive_types

            # Build details text consistent with batch prompt
            details_lines = []
            if is_archive:
                details_lines.append(f"Threats found in archive: {file_path.name}")
                for t in result.get("threats", []):
                    ht = t.get("hash_types") or [t.get("hash_type", "N/A")]
                    if not isinstance(ht, list): ht = [ht]
                    details_lines.append(f"  - {t.get('file')}  |  Type(s): {', '.join(ht)}")
            else:
                t = (result.get("threats") or [{}])[0]
                ht = t.get("hash_types") or [t.get("hash_type", "N/A")]
                if not isinstance(ht, list): ht = [ht]
                details_lines.append(f"Threat: {file_path.name}  |  Type(s): {', '.join(ht)}")

            details_text = "\n".join(details_lines)
            action = self._modal_action_prompt(file_path, details_text)
            if action == "quarantine":
                ok, msg = self.scanner.quarantine_path(file_path)
                if ok:
                    self.logger.log(f"User quarantined (real-time): {file_path}", "WARNING")
                else:
                    self.logger.log(f"Quarantine failed (real-time): {file_path} ({msg})", "ERROR")
            elif action == "delete":
                ok, msg = self.scanner.delete_path(file_path)
                if ok:
                    self.logger.log(f"User deleted (real-time): {file_path}", "WARNING")
                else:
                    self.logger.log(f"Delete failed (real-time): {file_path} ({msg})", "ERROR")
            else:
                self.logger.log(f"User ignored (real-time): {file_path}", "INFO")

            # Keep Quarantine tab in sync
            self.refresh_quarantine_list()

        if hasattr(self.root, "after_idle"):
            self.root.after_idle(_show)
        else:
            _show()

    def _notify_behavior_incident_gui(self, incident: Dict[str, Any]) -> None:
        def _show():
            proc = incident.get("process", {})
            exe = proc.get("exe") or "Unknown"
            pid = incident.get("pid")
            score = incident.get("score", 0)
            reasons = "\n".join([f"- {rh['rule_id']}  (weight={rh['weight']})" for rh in incident.get("rule_hits", [])])

            details = f"PID: {pid}\nEXE: {exe}\nScore: {score}\n\nRules:\n{reasons}"
            # Reuse existing modal choice UX
            action = self._modal_action_prompt(Path(exe), details)  # returns "quarantine"|"ignore"|"delete"
            try:
                import psutil
                if action == "delete":
                    # Kill process then rollback
                    psutil.Process(int(pid)).kill()
                    cnt = self.scanner.behavior.rollback.rollback() if self.scanner.behavior else 0
                    self.logger.log(f"[BEHAVIOR] Deleted (killed) PID {pid}; rollback handled {cnt} files.", "WARNING")
                elif action == "quarantine":
                    # Suspend already done. Kill gently and rollback to quarantine
                    try:
                        psutil.Process(int(pid)).terminate()
                    except Exception:
                        pass
                    cnt = self.scanner.behavior.rollback.rollback() if self.scanner.behavior else 0
                    self.logger.log(f"[BEHAVIOR] Quarantined/removed {cnt} recent files for PID {pid}.", "WARNING")
                else:
                    # Resume if user ignores
                    try:
                        psutil.Process(int(pid)).resume()
                        self.logger.log(f"[BEHAVIOR] Resumed PID {pid} after user ignore.", "INFO")
                    except Exception:
                        pass
            except Exception as e:
                self.logger.log(f"[BEHAVIOR] GUI action error: {e}", "ERROR")

        if hasattr(self.root, "after_idle"):
            self.root.after_idle(_show)
        else:
            _show()

    def update_paths_listbox(self):
        self.paths_listbox.delete(0, tk.END)
        for path_item in config.monitor_paths:
            self.paths_listbox.insert(tk.END, path_item)

    # ---------- Quarantine ----------
    def refresh_quarantine_list(self):
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())

        if config.quarantine_dir.exists():
            for file_path in config.quarantine_dir.iterdir():
                if file_path.is_file() and file_path.name.endswith(".quarantined"):
                    try:
                        stat = file_path.stat()
                        date_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        size_mb = stat.st_size / (1024 * 1024)
                        size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{stat.st_size / 1024:.1f} KB"
                        parts = file_path.name.split('.')
                        original_name_hint = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

                        self.quarantine_tree.insert("", tk.END, values=(
                            file_path.name,
                            original_name_hint,
                            date_str,
                            size_str
                        ), iid=str(file_path))
                    except Exception as e:
                        self.logger.log(f"Error reading quarantine file info {file_path}: {e}", "ERROR")

    def restore_from_quarantine(self):
        selected_items = self.quarantine_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a file from the quarantine list to restore.")
            return

        selected_item_id = selected_items[0]
        quarantined_file_path = Path(selected_item_id)

        if quarantined_file_path.exists():
            parts = quarantined_file_path.name.split('.')
            suggested_original_name = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

            restore_path_str = filedialog.asksaveasfilename(
                title="Select Restore Location and Filename",
                initialfile=suggested_original_name,
                defaultextension=".*",
                initialdir=str(Path.home() / "Downloads")
            )

            if restore_path_str:
                restore_path = Path(restore_path_str)
                try:
                    shutil.move(str(quarantined_file_path), str(restore_path))
                    self.logger.log(f"File restored: {quarantined_file_path} -> {restore_path}", "INFO")
                    messagebox.showinfo("Success", f"File '{quarantined_file_path.name}' restored to '{restore_path}'.")
                    self.refresh_quarantine_list()
                except Exception as e:
                    self.logger.log(f"Failed to restore file {quarantined_file_path}: {e}", "ERROR")
                    messagebox.showerror("Error", f"Failed to restore file: {e}")
        else:
            messagebox.showerror("Error", "Selected quarantined file no longer exists.")
            self.refresh_quarantine_list()

    def delete_from_quarantine(self):
        selected_items = self.quarantine_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a file from the quarantine list to delete.")
            return

        selected_item_id = selected_items[0]
        quarantined_file_path = Path(selected_item_id)

        if messagebox.askyesno("Confirm Deletion",
                               f"Are you sure you want to permanently delete '{quarantined_file_path.name}'?\nThis action cannot be undone."):
            if quarantined_file_path.exists():
                try:
                    quarantined_file_path.unlink()
                    self.logger.log(f"File permanently deleted from quarantine: {quarantined_file_path}", "INFO")
                    messagebox.showinfo("Success", f"File '{quarantined_file_path.name}' permanently deleted.")
                    self.refresh_quarantine_list()
                except Exception as e:
                    self.logger.log(f"Failed to delete quarantined file {quarantined_file_path}: {e}", "ERROR")
                    messagebox.showerror("Error", f"Failed to delete file: {e}")
            else:
                messagebox.showerror("Error", "Selected quarantined file no longer exists.")
                self.refresh_quarantine_list()

    # ---------- Signatures ----------
    def add_signature_gui(self):
        signature = self.sig_entry.get().strip().lower()
        hash_type = self.hash_type_var.get().lower()

        if not signature:
            messagebox.showwarning("Input Error", "Signature field cannot be empty.")
            return

        if hash_type == "md5" and len(signature) != 32:
            messagebox.showerror("Input Error", "Invalid MD5 hash format. Must be 32 hexadecimal characters.")
            return
        if hash_type == "sha256" and len(signature) != 64:
            messagebox.showerror("Input Error", "Invalid SHA256 hash format. Must be 64 hexadecimal characters.")
            return
        if not all(c in "0123456789abcdef" for c in signature):
            messagebox.showerror("Input Error", "Invalid hash characters. Must be hexadecimal.")
            return

        try:
            if signature in self.scanner.sig_db.signatures[hash_type]:
                messagebox.showinfo("Info", f"{hash_type.upper()} signature already exists in the database.")
                return

            self.scanner.sig_db.add_signature(signature, hash_type)
            self.logger.log(f"User added {hash_type.UPPER()} signature: {signature}", "INFO")
            messagebox.showinfo("Success", f"{hash_type.upper()} signature added to the database.")
            self.sig_entry.delete(0, tk.END)
        except Exception as e:
            self.logger.log(f"Failed to add signature via GUI: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to add signature: {e}")
