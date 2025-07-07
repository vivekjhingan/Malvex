# malvex/gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
import platform
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any # Any for item from treeview
import shutil
import os

from .app_config import config
from .app_logger import Logger # For type hinting and instantiation
from .malware_scanner import MalwareScanner # For type hinting and instantiation

class AntivirusGUI:
    """Modern GUI for the antivirus"""
    
    def __init__(self, root: tk.Tk): # Pass root from main app
        self.root = root
        self.root.title(f"{config.app_name} v{config.version}")
        # Attempt to set a minimum size
        self.root.minsize(800, 600) 
        try:
            # More robust geometry setting
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            w, h = 900, 700
            x = (screen_width // 2) - (w // 2)
            y = (screen_height // 2) - (h // 2)
            self.root.geometry(f"{w}x{h}+{x}+{y}")
        except tk.TclError: # Handles cases where window manager might interfere
             self.root.geometry("900x700")

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam') # A theme that is usually available
        
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10, "bold"), padding=5)
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"), foreground="#333")
        self.style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        self.style.configure("Red.TLabel", foreground="red", background="#f0f0f0")
        self.style.configure("Green.TLabel", foreground="green", background="#f0f0f0")


        # Initialize components
        self.logger = Logger(self.log_to_gui_scrolledtext) # Pass the GUI callback
        self.scanner = MalwareScanner(self.logger, self.prompt_realtime_action)  # Scanner uses the same logger instance and prompt callback
        
        # GUI variables
        self.scan_progress_var = tk.DoubleVar()
        self.realtime_status_var = tk.StringVar(value="Initializing...")
        self.current_scan_path_var = tk.StringVar(value="N/A")

        self.scan_thread: Optional[threading.Thread] = None
        
        self.setup_gui()
        self.update_realtime_status_display() # Initial status update
        # Load initial logs if any
        self.load_initial_logs()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close

    def on_closing(self):
        if self.scan_thread and self.scan_thread.is_alive():
            if messagebox.askyesno("Scan in Progress", "A scan is currently in progress. Are you sure you want to exit?"):
                self.scanner.scanning = False # Signal scanner to stop
                if self.scan_thread: # Check again as it might have finished quickly
                    self.scan_thread.join(timeout=2) # Wait a bit for thread to finish
                self.cleanup_and_destroy()
            else:
                return # Don't close
        else:
            self.cleanup_and_destroy()

    def cleanup_and_destroy(self):
        self.logger.log("Malvex GUI closing...")
        if self.scanner.realtime_monitor and config.realtime_enabled:
             # No need to explicitly call stop here if config.realtime_enabled handles it,
             # but good for explicit cleanup if needed.
             # self.scanner.stop_realtime_protection() # This might save config again
             pass
        self.root.destroy()

    def load_initial_logs(self):
        if config.log_file.exists():
            try:
                with open(config.log_file, "r", encoding="utf-8") as f:
                    # Display last N lines or implement more sophisticated loading
                    lines = f.readlines()
                    for line in lines[-100:]: # Display last 100 lines
                        self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
            except Exception as e:
                self.logger.log(f"Could not load initial logs: {e}", "ERROR")
                
    def setup_gui(self):
        """Setup the main GUI"""
        main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(main_frame, text=config.app_name, style="Header.TLabel")
        title_label.pack(pady=(0, 20), anchor="center")
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Scan tab
        scan_frame = ttk.Frame(notebook, padding="10")
        notebook.add(scan_frame, text=" Scanner ") # Added padding in text for some themes
        self.setup_scan_tab(scan_frame)
        
        # Real-time protection tab
        realtime_frame = ttk.Frame(notebook, padding="10")
        notebook.add(realtime_frame, text=" Real-Time Protection ")
        self.setup_realtime_tab(realtime_frame)
        
        # Quarantine tab
        quarantine_frame = ttk.Frame(notebook, padding="10")
        notebook.add(quarantine_frame, text=" Quarantine ")
        self.setup_quarantine_tab(quarantine_frame)
        
        # Settings tab
        settings_frame = ttk.Frame(notebook, padding="10")
        notebook.add(settings_frame, text=" Settings ")
        self.setup_settings_tab(settings_frame)
        
        # Log tab
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
        self.scan_status_label.pack(pady=(0,5), anchor="w")

        self.current_file_label = ttk.Label(progress_frame, textvariable=self.current_scan_path_var, wraplength=700) # Wraps long paths
        self.current_file_label.pack(pady=(0,5), anchor="w", fill=tk.X)

        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.scan_progress_var, length=400) # Explicit length
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
        
        path_buttons_frame = ttk.Frame(paths_frame) # No LabelFrame needed here
        path_buttons_frame.pack(fill=tk.X, padx=5, pady=(0,5)) # Reduced pady
        
        ttk.Button(path_buttons_frame, text="Add Path...", command=self.add_monitor_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(path_buttons_frame, text="Remove Selected Path", command=self.remove_monitor_path).pack(side=tk.LEFT, padx=5)
        
        self.update_paths_listbox()

    def setup_quarantine_tab(self, parent: ttk.Frame):
        list_frame = ttk.LabelFrame(parent, text="Quarantined Files", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ("File", "Original Path Hint", "Date Quarantined", "Size") # Added original path hint
        self.quarantine_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        self.quarantine_tree.heading("File", text="Quarantined File Name")
        self.quarantine_tree.column("File", width=250, anchor=tk.W)
        self.quarantine_tree.heading("Original Path Hint", text="Original Path (if known)") # May not always be easily stored/retrieved
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
        sig_frame.pack(fill=tk.X, pady=5, anchor="n") # Anchor to north
        
        add_sig_frame = ttk.Frame(sig_frame) # Inner frame for better layout
        add_sig_frame.pack(fill=tk.X, pady=5)

        ttk.Label(add_sig_frame, text="Signature (Hash):").pack(side=tk.LEFT, padx=(0,5))
        self.sig_entry = ttk.Entry(add_sig_frame, width=50) # Wider entry
        self.sig_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.hash_type_var = tk.StringVar(value="SHA256")
        hash_combo = ttk.Combobox(add_sig_frame, textvariable=self.hash_type_var, 
                                  values=["MD5", "SHA256"], width=8, state="readonly")
        hash_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(sig_frame, text="Add Signature to Database", command=self.add_signature_gui).pack(pady=5, anchor="e")
        
        stats_frame = ttk.LabelFrame(parent, text="Scan Statistics (Last Scan)", padding="10")
        stats_frame.pack(fill=tk.X, pady=5, anchor="n")
        
        self.stats_display_label = ttk.Label(stats_frame, text="No scans performed in this session yet.", justify=tk.LEFT)
        self.stats_display_label.pack(padx=5, pady=5, anchor="w")
        self.update_scan_statistics_display() # Initialize display

    def setup_log_tab(self, parent: ttk.Frame):
        self.log_text = scrolledtext.ScrolledText(parent, height=15, wrap=tk.WORD, state=tk.DISABLED) # Start disabled for read-only
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Tag configurations for log levels
        self.log_text.tag_configure("ERROR", foreground="red")
        self.log_text.tag_configure("WARNING", foreground="orange")
        self.log_text.tag_configure("INFO", foreground="black")
        self.log_text.tag_configure("DEBUG", foreground="gray")


    def log_to_gui_scrolledtext(self, message: str, level: str):
        """Thread-safe callback for log messages to GUI"""
        def _update_log_text():
            if self.log_text.winfo_exists(): # Check if widget still exists
                self.log_text.config(state=tk.NORMAL) # Enable writing
                self.log_text.insert(tk.END, message + "\n", level.upper()) # Use tag for level
                self.log_text.config(state=tk.DISABLED) # Disable writing
                self.log_text.see(tk.END) # Scroll to the end
        
        # Ensure GUI updates are done in the main thread
        if hasattr(self.root, "after_idle"): # Check if root has after_idle (it should)
            self.root.after_idle(_update_log_text)

    def _start_scan(self, scan_path: Path, scan_type_name: str):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "A scan is already in progress. Please wait or stop it.")
            return
        
        if not scan_path.exists():
            messagebox.showerror("Error", f"Scan path does not exist: {scan_path}")
            return

        self.logger.log(f"Starting {scan_type_name} on: {scan_path}", "INFO")
        self.results_tree.delete(*self.results_tree.get_children()) # Clear previous results
        self.scan_progress_var.set(0)
        self.current_scan_path_var.set("Initializing scan...")
        self.scan_status_label.config(text=f"Status: {scan_type_name} started...")

        # Run the scan in a separate thread to keep GUI responsive
        self.scan_thread = threading.Thread(target=self.perform_scan_and_update_gui, args=(scan_path,), daemon=True)
        self.scan_thread.start()

    def quick_scan(self):
        downloads_path = Path.home() / "Downloads"
        self._start_scan(downloads_path, "Quick Scan")
    
    def full_scan(self):
        if platform.system() == "Windows":
            # Scanning C:\ can be very long and hit permission issues.
            # Consider scanning user's profile or common infection vectors instead for a "safer" full scan.
            scan_path = Path(os.environ.get("USERPROFILE", "C:\\Users")) # Scan user's profile
            if not scan_path.exists(): scan_path = Path("C:\\") # Fallback if USERPROFILE not found
        else:
            scan_path = Path.home() # Scan user's home directory on Unix-like
            # scan_path = Path("/") # True full scan, often problematic
        
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
                self.scanner.scanning = False # Signal the scanner to stop
                self.scan_status_label.config(text="Status: Scan stopping...")
                self.logger.log("User requested scan stop.", "INFO")
        else:
            messagebox.showinfo("Stop Scan", "No scan is currently in progress.")

    def perform_scan_and_update_gui(self, scan_path: Path):
        """Performs the scan and updates GUI elements safely."""
        
        def progress_callback_gui(progress: float, current_file_display: str):
            if not self.root.winfo_exists(): return # Stop if GUI is gone
            self.root.after_idle(lambda: self.scan_progress_var.set(progress))
            self.root.after_idle(lambda: self.current_scan_path_var.set(f"Scanning: {current_file_display}"))

        results = self.scanner.scan_directory(scan_path, progress_callback_gui)
        
        if not self.root.winfo_exists(): return # Stop if GUI is gone during scan
        self.root.after_idle(self.update_scan_results_tree, results)
        self.root.after_idle(self.update_scan_statistics_display)
        self.root.after_idle(lambda: self.scan_status_label.config(text="Status: Scan completed."))
        self.root.after_idle(lambda: self.current_scan_path_var.set(f"Completed scan of: {scan_path}"))
        self.root.after_idle(lambda: self.scan_progress_var.set(100)) # Ensure progress is 100 at end
        self.scanner.scanning = False # Ensure flag is reset

    def update_scan_results_tree(self, results: List[Dict]):
        """Update scan results in GUI Treeview."""
        self.results_tree.delete(*self.results_tree.get_children()) # Clear previous results

        for result in results:
            file_full_path = Path(result["file"])
            file_name = file_full_path.name
            status = result["status"].upper()
            details = ""

            if result["status"] == "infected":
                status_tag = "infected" # For potential coloring later
                if result.get("threats"):
                    # For file threats
                    if not file_full_path.suffix.lower() in config.archive_types:
                        threat_info = result["threats"][0] # Assuming one threat dict for the file itself
                        details = f"Type: {threat_info.get('hash_type', 'N/A')} Match"
                        self.results_tree.insert("", tk.END, values=(
                            file_name, str(file_full_path), status, details), tags=(status_tag,))
                    # For threats within archives
                    else:
                        # Main archive entry
                        self.results_tree.insert("", tk.END, values=(
                            file_name, str(file_full_path), f"{status} (Contains Threats)", "See below"), tags=(status_tag,))
                        # List threats inside the archive
                        for threat_in_archive in result["threats"]:
                            details_archive = f"Inside {file_name}: {threat_in_archive.get('file')}, Type: {threat_in_archive.get('hash_type', 'N/A')}"
                            self.results_tree.insert("", tk.END, values=(
                                f"↳ {threat_in_archive.get('file')}", # Indent or mark as sub-item
                                str(file_full_path), # Archive path
                                "THREAT INSIDE", 
                                details_archive), tags=(status_tag, "sub_item"))
            elif result["status"] != "clean" and result["status"] != "skipped_in_quarantine" and result["status"] != "skipped_not_file":
                status_tag = "error"
                details = result.get("action_taken", "N/A") if result.get("action_taken") else "Error during scan"
                self.results_tree.insert("", tk.END, values=(
                    file_name, str(file_full_path), status, details), tags=(status_tag,))
            # Optionally, show clean files if a setting is enabled, or skip them from view
            # else: # Clean files
            #    self.results_tree.insert("", tk.END, values=(
            #        file_name, str(file_full_path), status, "Clean"), tags=("clean",))


        # Configure tags for coloring (example)
        self.results_tree.tag_configure("infected", foreground="red")
        self.results_tree.tag_configure("error", foreground="orange")
        self.results_tree.tag_configure("sub_item", foreground="#555555") # Dark grey for sub-items


    def update_scan_statistics_display(self):
        """Update the statistics label in the Settings tab."""
        stats = self.scanner.scan_stats
        stats_text = (
            f"Files Scanned: {stats['files_scanned']}\n"
            f"Threats Found: {stats['threats_found']}\n"
            f"Archives Scanned: {stats['archives_scanned']}\n"
            f"Scan Errors: {stats['errors']}"
        )
        if hasattr(self, 'stats_display_label'): # Check if label exists
            self.stats_display_label.config(text=stats_text)
    
    def enable_realtime(self):
        try:
            self.scanner.start_realtime_protection() # This now handles config saving and logging
            self.update_realtime_status_display()
            if config.realtime_enabled: # Check if it was successfully enabled
                 messagebox.showinfo("Success", "Real-time protection has been enabled.")
            else:
                 messagebox.showwarning("Real-Time Protection", "Real-time protection could not be started. Check logs and monitored paths.")
        except Exception as e:
            self.logger.log(f"Failed to enable real-time protection via GUI: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to enable protection: {e}")
            self.update_realtime_status_display() # Reflect actual state
    
    def disable_realtime(self):
        try:
            self.scanner.stop_realtime_protection() # This now handles config saving and logging
            self.update_realtime_status_display()
            messagebox.showinfo("Success", "Real-time protection has been disabled.")
        except Exception as e:
            self.logger.log(f"Failed to disable real-time protection via GUI: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to disable protection: {e}")
            self.update_realtime_status_display() # Reflect actual state
    
    def update_realtime_status_display(self):
        if config.realtime_enabled:
            self.realtime_status_var.set("✅ Enabled")
            if hasattr(self, 'realtime_status_display_label'): # Check existence
                self.realtime_status_display_label.config(style="Green.TLabel")
        else:
            self.realtime_status_var.set("❌ Disabled")
            if hasattr(self, 'realtime_status_display_label'):
                self.realtime_status_display_label.config(style="Red.TLabel")

    def add_monitor_path(self):
        path_str = filedialog.askdirectory(title="Select Folder to Monitor for Real-Time Protection")
        if path_str:
            path_to_add = str(Path(path_str).resolve()) # Normalize path
            if path_to_add not in config.monitor_paths:
                config.monitor_paths.append(path_to_add)
                config.save_config()
                self.update_paths_listbox()
                self.logger.log(f"Added monitoring path: {path_to_add}", "INFO")
                
                if config.realtime_enabled: # If protection is active, restart it to include new path
                    messagebox.showinfo("Real-Time Protection", "Restarting real-time protection to apply new path.")
                    self.scanner.start_realtime_protection() 
                    self.update_realtime_status_display()
            else:
                messagebox.showinfo("Info", "Path already in monitoring list.")
    
    def remove_monitor_path(self):
        selection_indices = self.paths_listbox.curselection()
        if selection_indices:
            index = selection_indices[0]
            path_to_remove = config.monitor_paths.pop(index) # Remove by index
            config.save_config()
            self.update_paths_listbox()
            self.logger.log(f"Removed monitoring path: {path_to_remove}", "INFO")

            if config.realtime_enabled: # If protection is active, restart it
                messagebox.showinfo("Real-Time Protection", "Restarting real-time protection to apply changes.")
                self.scanner.start_realtime_protection()
                self.update_realtime_status_display()
        else:
            messagebox.showwarning("Warning", "Please select a path to remove.")
    
    def update_paths_listbox(self):
        self.paths_listbox.delete(0, tk.END)
        for path_item in config.monitor_paths:
            self.paths_listbox.insert(tk.END, path_item)
    
    def refresh_quarantine_list(self):
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        
        if config.quarantine_dir.exists():
            for file_path in config.quarantine_dir.iterdir():
                if file_path.is_file() and file_path.name.endswith(".quarantined"): # Filter for our quarantined files
                    try:
                        stat = file_path.stat()
                        date_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        size_mb = stat.st_size / (1024 * 1024)
                        size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{stat.st_size / 1024:.1f} KB"
                        
                        # Try to parse original name (everything before the last two dots if structure is name.timestamp.quarantined)
                        parts = file_path.name.split('.')
                        original_name_hint = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

                        self.quarantine_tree.insert("", tk.END, values=(
                            file_path.name, # Full quarantined name
                            original_name_hint, # Original name hint
                            date_str,
                            size_str
                        ), iid=str(file_path)) # Use full path as item ID
                    except Exception as e:
                        self.logger.log(f"Error reading quarantine file info {file_path}: {e}", "ERROR")
    
    def restore_from_quarantine(self):
        selected_items = self.quarantine_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a file from the quarantine list to restore.")
            return
        
        selected_item_id = selected_items[0] # Get the iid (which we set as the full path)
        quarantined_file_path = Path(selected_item_id)

        if quarantined_file_path.exists():
            # Suggest original name for restoration
            parts = quarantined_file_path.name.split('.')
            suggested_original_name = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

            restore_path_str = filedialog.asksaveasfilename(
                title="Select Restore Location and Filename",
                initialfile=suggested_original_name,
                defaultextension=".*", # Keep original extension if possible
                initialdir=str(Path.home() / "Downloads") # Suggest Downloads folder
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
             self.refresh_quarantine_list() # Refresh list if file is missing

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
                
    def prompt_realtime_action(self, file_path: Path, result: Dict) -> str:
        """Prompt the user for action when a real-time threat is detected."""
        q = queue.Queue()

        def ask():
            win = tk.Toplevel(self.root)
            win.title("Real-Time Threat Detected")
            ttk.Label(
                win,
                text=f"Threat detected:\n{file_path}\nStatus: {result['status'].upper()}\nChoose action:",
                wraplength=400,
            ).pack(padx=10, pady=10)

            def choose(action: str):
                q.put(action)
                win.destroy()

            btn_frame = ttk.Frame(win)
            btn_frame.pack(pady=5)
            ttk.Button(btn_frame, text="Ignore", command=lambda: choose('ignore')).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Quarantine", command=lambda: choose('quarantine')).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Delete", command=lambda: choose('delete')).pack(side=tk.LEFT, padx=5)
            win.grab_set()

        self.root.after(0, ask)
        return q.get()

    def add_signature_gui(self):
        signature = self.sig_entry.get().strip().lower() # Ensure lowercase
        hash_type = self.hash_type_var.get().lower()
        
        if not signature:
            messagebox.showwarning("Input Error", "Signature field cannot be empty.")
            return
        
        # Basic validation for hash length
        if hash_type == "md5" and len(signature) != 32:
            messagebox.showerror("Input Error", "Invalid MD5 hash format. Must be 32 hexadecimal characters.")
            return
        if hash_type == "sha256" and len(signature) != 64:
            messagebox.showerror("Input Error", "Invalid SHA256 hash format. Must be 64 hexadecimal characters.")
            return
        # Check if all characters are hexadecimal
        if not all(c in "0123456789abcdef" for c in signature):
            messagebox.showerror("Input Error", "Invalid hash characters. Must be hexadecimal.")
            return

        try:
            # Check if signature already exists
            if signature in self.scanner.sig_db.signatures[hash_type]:
                 messagebox.showinfo("Info", f"{hash_type.upper()} signature already exists in the database.")
                 return

            self.scanner.sig_db.add_signature(signature, hash_type) # This also saves
            self.logger.log(f"User added {hash_type.upper()} signature: {signature}", "INFO")
            messagebox.showinfo("Success", f"{hash_type.upper()} signature added to the database.")
            self.sig_entry.delete(0, tk.END) # Clear entry field
        except Exception as e:
            self.logger.log(f"Failed to add signature via GUI: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to add signature: {e}")

    # run() method is no longer here, it's handled by the main script launching the GUI