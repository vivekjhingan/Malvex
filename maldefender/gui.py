"""
MalDefender — Tk GUI (production)
Integrates with MalwareScanner, Real-Time monitor, Signature DB, and Quarantine.

Key improvements vs previous GUI:
- No stubbed detections; uses real MalwareScanner and its real-time callback.
- Correct SignatureDatabase() construction (no logger argument).
- Correct RealTime lifecycle via MalwareScanner.start/stop_realtime_protection().
- Quarantine tab auto-refreshes (polling watcher).
- Logger routes to UI via gui_callback.
"""

from __future__ import annotations

import os
import sys
import json
import time
import threading
import queue
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Iterable, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---- Project imports ----
from .app_config import config
from .app_logger import Logger
from .malware_scanner import MalwareScanner
from .signature_db import SignatureDatabase

# ---- UI Theme ----
class UITheme:
    BG0 = "#0a0f18"
    BG1 = "#0f172a"
    BG2 = "#0b1222"
    PANEL = "#0c1627"
    TEXT = "#dbe7ff"
    MUTED = "#94a3b8"
    BORDER = "#1e293b"
    PRI = "#1f6feb"
    PRI_D = "#1a5cd1"
    WARN = "#d29922"
    DANGER = "#f85149"
    OK = "#22c55e"

    @classmethod
    def apply(cls, root: tk.Tk):
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        root.configure(bg=cls.BG0)
        for name, opts in {
            "TFrame": dict(background=cls.BG0),
            "Panel.TFrame": dict(background=cls.PANEL, borderwidth=1, relief="solid"),
            "TLabel": dict(background=cls.BG0, foreground=cls.TEXT),
            "Dim.TLabel": dict(background=cls.BG0, foreground=cls.MUTED),
            "H1.TLabel": dict(background=cls.BG0, foreground=cls.TEXT, font=("Segoe UI", 16, "bold")),
            "H2.TLabel": dict(background=cls.BG0, foreground=cls.TEXT, font=("Segoe UI", 12, "bold")),
            "TButton": dict(font=("Segoe UI", 10, "bold")),
            "Primary.TButton": dict(background=cls.PRI, foreground="white"),
            "Warn.TButton": dict(background=cls.WARN, foreground="black"),
            "Danger.TButton": dict(background=cls.DANGER, foreground="black"),
        }.items():
            style.configure(name, **opts)
        style.map("TButton", background=[("active", cls.PRI_D)])
        style.configure("Treeview",
                        background=cls.BG1, fieldbackground=cls.BG1,
                        foreground=cls.TEXT, bordercolor=cls.BORDER)
        style.configure("Treeview.Heading",
                        background=cls.BG2, foreground=cls.TEXT)
        style.configure("TProgressbar", background="#58a6ff", troughcolor=cls.BG2)

# ---- Data Models ----
@dataclass
class ScanTask:
    mode: str  # "quick" | "full" | "custom"
    paths: List[Path]
    auto_action: str = ""  # "", "quarantine", "delete"

# ---- Helpers ----
def _human_size(n: int) -> str:
    try:
        n = int(n)
    except Exception:
        return str(n)
    units = ["B","KB","MB","GB","TB","PB"]
    i = 0
    v = float(n)
    while v >= 1024 and i < len(units)-1:
        v /= 1024.0
        i += 1
    return f"{v:.1f} {units[i]}"

class ThreatModal(tk.Toplevel):
    def __init__(self, parent: tk.Misc, file_path: str, details: str):
        super().__init__(parent)
        self.title("Threat Detected")
        self.configure(bg=UITheme.BG1)
        self.resizable(False, False)
        self.grab_set()
        self.result: str = "ignore"

        frm = ttk.Frame(self, padding=12, style="Panel.TFrame")
        frm.grid(sticky="nsew")
        ttk.Label(frm, text="Threat Detected", style="H2.TLabel").grid(row=0, column=0, sticky="w")
        txt = tk.Text(frm, height=10, width=72, bg=UITheme.BG0, fg=UITheme.TEXT,
                      insertbackground=UITheme.TEXT, relief="flat", wrap="word")
        txt.grid(row=1, column=0, sticky="nsew", pady=(8, 8))
        txt.insert("1.0", f"Path: {file_path}\n\nDetails: {details or 'Malicious indicators detected.'}")
        txt.configure(state="disabled")

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, sticky="e")
        ttk.Button(btns, text="Quarantine (Enter)", style="Primary.TButton",
                   command=lambda: self._close("quarantine")).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Ignore (Esc)",
                   command=lambda: self._close("ignore")).grid(row=0, column=1, padx=4)
        ttk.Button(btns, text="Delete", style="Danger.TButton",
                   command=lambda: self._close("delete")).grid(row=0, column=2, padx=4)

        self.bind("<Escape>", lambda e: self._close("ignore"))
        self.bind("<Return>", lambda e: self._close("quarantine"))

    def _close(self, res: str):
        self.result = res
        self.grab_release()
        self.destroy()

def prompt_threat(root: tk.Misc, file_path: str, details: str) -> str:
    dlg = ThreatModal(root, file_path, details)
    root.wait_window(dlg)
    return dlg.result

# ---- GUI ----
class AntivirusGUI:
    """Tk GUI integrating MalwareScanner, Real-Time, Signatures, and Quarantine."""

    # --------------- Lifecycle ---------------
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{config.app_name} GUI")
        self.root.geometry("1120x720")
        self.root.minsize(980, 620)
        UITheme.apply(self.root)

        # Logger → route to GUI
        self._log_lines: List[str] = []
        self.logger = Logger(gui_callback=self._on_gui_log)

        # Backends
        self.scanner = MalwareScanner(self.logger, notify_callback=self._notify_threat_gui)
        # Use scanner.sig_db and scanner internals rather than creating divergent instances
        self.sigdb: SignatureDatabase = self.scanner.sig_db  # correct ctor is no-arg

        # UI state/queues/threads
        self._scan_thread: Optional[threading.Thread] = None
        self._scan_stop = threading.Event()
        self._uiq: "queue.Queue[Callable[[], None]]" = queue.Queue()

        # Real-time state
        self._rt_enabled = bool(config.realtime_enabled)
        self._rt_paths: List[str] = list(config.monitor_paths or [])
        if not self._rt_paths:
            # default to Downloads once
            self._rt_paths = [str(Path.home() / "Downloads")]
            config.monitor_paths = self._rt_paths[:]
            config.save_config()

        # Quarantine watcher
        self._q_stop = threading.Event()
        self._q_thread: Optional[threading.Thread] = None
        self._q_last_snapshot: Dict[str, float] = {}

        # Build UI
        self._build_ui()

        # start UI pump
        self._pump_ui()

        # initial states
        if self._rt_enabled:
            self._enable_rt(startup=True)

        self.logger.log("GUI loaded.", "INFO")

    def destroy(self):
        try:
            self._q_stop.set()
            if self._q_thread:
                self._q_thread.join(timeout=1.5)
        except Exception:
            pass
        try:
            self.scanner.stop_realtime_protection()
        except Exception:
            pass

    # --------------- Logging ---------------
    def _on_gui_log(self, line: str, level: str):
        # line already formatted by Logger
        try:
            self._log_lines.append(line)
            if len(self._log_lines) > 4000:
                self._log_lines = self._log_lines[-4000:]
            self._uiq.put(lambda: self._append_log(line))
        except Exception:
            pass

    def _append_log(self, s: str):
        try:
            self.txt_log.insert("end", s + "\n")
            self.txt_log.see("end")
        except Exception:
            pass

    # --------------- UI Build ---------------
    def _build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.nb = nb

        self._tab_dashboard(nb)
        self._tab_scan(nb)
        self._tab_realtime(nb)
        self._tab_quarantine(nb)
        self._tab_signatures(nb)
        self._tab_logs(nb)

    def _tab_dashboard(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Dashboard")

        status = ttk.Frame(f, padding=10, style="Panel.TFrame")
        status.pack(fill="x", pady=(0, 10))
        ttk.Label(status, text="Protection Status", style="H2.TLabel").pack(anchor="w")
        row = ttk.Frame(status); row.pack(fill="x", pady=(6, 0))
        self.var_rt_chip = tk.StringVar(value="Real-Time: On" if self._rt_enabled else "Real-Time: Off")
        ttk.Label(row, textvariable=self.var_rt_chip, style="Dim.TLabel").pack(side="left")
        ttk.Button(row, text="Manage", style="Primary.TButton",
                   command=lambda: self.nb.select(self._rt_tab)).pack(side="right")

        card = ttk.Frame(f, padding=10, style="Panel.TFrame"); card.pack(fill="both", expand=True)
        ttk.Label(card, text="Recent Results", style="H2.TLabel").pack(anchor="w")
        cols = ("file","status","details")
        tv = ttk.Treeview(card, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (520, 100, 360)):
            tv.heading(c, text=c.capitalize()); tv.column(c, width=w, stretch=True)
        tv.pack(fill="both", expand=True, pady=(6, 0))
        self.recent_tv = tv

    def _tab_scan(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Scan"); self._scan_tab = f

        top = ttk.Frame(f, padding=10, style="Panel.TFrame"); top.pack(fill="x")
        ttk.Button(top, text="Quick Scan (Downloads)", style="Primary.TButton",
                   command=lambda: self._start_scan("quick")).pack(side="left", padx=4)
        ttk.Button(top, text="Full System Scan",
                   command=lambda: self._start_scan("full")).pack(side="left", padx=4)
        ttk.Button(top, text="Custom Scan…",
                   command=self._choose_custom_scan).pack(side="left", padx=4)
        ttk.Button(top, text="Stop", style="Warn.TButton",
                   command=self._stop_scan).pack(side="left", padx=8)

        ttk.Label(top, text="Auto action:", style="Dim.TLabel").pack(side="left", padx=(16, 4))
        self.var_auto_action = tk.StringVar(value="")
        cb = ttk.Combobox(top, width=14, state="readonly", textvariable=self.var_auto_action,
                          values=["", "quarantine", "delete"])
        cb.pack(side="left")

        prog = ttk.Frame(f, padding=10, style="Panel.TFrame"); prog.pack(fill="x", pady=(10, 10))
        self.var_scan_status = tk.StringVar(value="Ready")
        ttk.Label(prog, textvariable=self.var_scan_status).pack(anchor="w")
        self.pb = ttk.Progressbar(prog, mode="determinate", maximum=100); self.pb.pack(fill="x", pady=(6, 0))
        self.var_scan_current = tk.StringVar(value="—")
        ttk.Label(prog, textvariable=self.var_scan_current, style="Dim.TLabel").pack(anchor="w", pady=(6, 0))

        card = ttk.Frame(f, padding=10, style="Panel.TFrame"); card.pack(fill="both", expand=True)
        ttk.Label(card, text="Results", style="H2.TLabel").pack(anchor="w")
        cols = ("file","status","details","action")
        tv = ttk.Treeview(card, columns=cols, show="headings")
        for c, w in zip(cols, (520, 120, 360, 100)):
            tv.heading(c, text=c.capitalize()); tv.column(c, width=w, stretch=True)
        tv.pack(fill="both", expand=True, pady=(6, 0))
        self.scan_tv = tv

    def _tab_realtime(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Real-Time"); self._rt_tab = f

        card = ttk.Frame(f, padding=10, style="Panel.TFrame"); card.pack(fill="x")
        ttk.Label(card, text="Status & Controls", style="H2.TLabel").pack(anchor="w")
        row = ttk.Frame(card); row.pack(fill="x", pady=(6, 0))
        self.var_rt_state = tk.StringVar(value="Enabled" if self._rt_enabled else "Disabled")
        ttk.Label(row, textvariable=self.var_rt_state).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Enable", style="Primary.TButton",
                   command=self._enable_rt).pack(side="left", padx=4)
        ttk.Button(row, text="Disable",
                   command=self._disable_rt).pack(side="left", padx=4)
        ttk.Button(row, text="Simulate",
                   style="Warn.TButton", command=self._simulate_rt).pack(side="right", padx=4)

        card2 = ttk.Frame(f, padding=10, style="Panel.TFrame"); card2.pack(fill="both", expand=True, pady=(10, 0))
        ttk.Label(card2, text="Monitored Paths", style="H2.TLabel").pack(anchor="w")
        prow = ttk.Frame(card2); prow.pack(fill="x", pady=(6, 0))
        self.var_rt_path = tk.StringVar()
        ttk.Entry(prow, textvariable=self.var_rt_path).pack(side="left", fill="x", expand=True)
        ttk.Button(prow, text="Add", command=self._add_rt_path).pack(side="left", padx=6)
        ttk.Button(prow, text="Remove Selected", command=self._remove_rt_path).pack(side="left", padx=6)

        tv = ttk.Treeview(card2, columns=("path",), show="headings", height=8)
        tv.heading("path", text="Path"); tv.column("path", width=820, stretch=True)
        tv.pack(fill="both", expand=True, pady=(6, 0))
        self.rt_tv = tv
        self._refresh_rt_paths()

    def _tab_quarantine(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Quarantine")

        top = ttk.Frame(f, padding=10, style="Panel.TFrame"); top.pack(fill="x")
        ttk.Label(top, text="Items", style="H2.TLabel").pack(side="left")
        ttk.Button(top, text="Refresh", command=self._q_refresh).pack(side="right", padx=4)
        ttk.Button(top, text="Delete Selected", style="Danger.TButton",
                   command=self._q_delete_selected).pack(side="right", padx=4)
        ttk.Button(top, text="Restore Selected…",
                   command=self._q_restore_selected).pack(side="right", padx=4)

        card = ttk.Frame(f, padding=10, style="Panel.TFrame")
        card.pack(fill="both", expand=True, pady=(10, 0))
        cols = ("file","path","date","size")
        tv = ttk.Treeview(card, columns=cols, show="headings", selectmode="extended")
        for c, w in zip(cols, (360, 420, 160, 120)):
            tv.heading(c, text=c.capitalize()); tv.column(c, width=w, stretch=True)
        tv.pack(fill="both", expand=True)
        self.q_tv = tv

        # start watcher
        self._start_quarantine_watcher()
        self._q_refresh()

    def _tab_signatures(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Signatures")

        form = ttk.Frame(f, padding=10, style="Panel.TFrame"); form.pack(fill="x")
        ttk.Label(form, text="Add Signature", style="H2.TLabel").pack(anchor="w")
        row = ttk.Frame(form); row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, text="Hash:").pack(side="left")
        self.var_sig_hash = tk.StringVar()
        ttk.Entry(row, textvariable=self.var_sig_hash, width=60).pack(side="left", padx=6)
        ttk.Label(row, text="Type:").pack(side="left", padx=(12, 4))
        self.var_sig_type = tk.StringVar(value="sha256")
        ttk.Combobox(row, textvariable=self.var_sig_type, state="readonly",
                     values=["sha256","md5"], width=10).pack(side="left")
        ttk.Button(row, text="Add", style="Primary.TButton",
                   command=self._sig_add).pack(side="left", padx=8)

        row2 = ttk.Frame(form); row2.pack(fill="x", pady=(6, 0))
        ttk.Button(row2, text="Export JSON",
                   command=self._sig_export).pack(side="left", padx=4)
        ttk.Button(row2, text="Import JSON…",
                   command=self._sig_import).pack(side="left", padx=4)

        card = ttk.Frame(f, padding=10, style="Panel.TFrame"); card.pack(fill="both", expand=True, pady=(10, 0))
        ttk.Label(card, text="Signature Store", style="H2.TLabel").pack(anchor="w")
        tv = ttk.Treeview(card, columns=("type","hash"), show="headings", selectmode="extended")
        tv.heading("type", text="Type"); tv.column("type", width=100)
        tv.heading("hash", text="Hash"); tv.column("hash", width=820, stretch=True)
        tv.pack(fill="both", expand=True, pady=(6, 0))
        self.sig_tv = tv
        self._sig_refresh()

    def _tab_logs(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Logs")
        top = ttk.Frame(f, padding=10, style="Panel.TFrame"); top.pack(fill="x")
        ttk.Label(top, text="Logs", style="H2.TLabel").pack(side="left")
        ttk.Button(top, text="Copy", command=self._log_copy).pack(side="right", padx=4)
        ttk.Button(top, text="Open Log File", command=self._open_log_file).pack(side="right", padx=4)

        body = ttk.Frame(f, padding=10, style="Panel.TFrame"); body.pack(fill="both", expand=True, pady=(10, 0))
        self.txt_log = tk.Text(body, wrap="word", bg=UITheme.BG1, fg=UITheme.TEXT,
                               insertbackground=UITheme.TEXT, relief="flat")
        self.txt_log.pack(fill="both", expand=True)

    # --------------- UI pump ---------------
    def _pump_ui(self):
        try:
            for _ in range(100):
                cb = self._uiq.get_nowait()
                cb()
        except queue.Empty:
            pass
        self.root.after(50, self._pump_ui)

    # --------------- Scanning ---------------
    def _choose_custom_scan(self):
        sel = filedialog.askdirectory(title="Choose folder to scan")
        if not sel: return
        self._start_scan("custom", [Path(sel)])

    def _start_scan(self, mode: str, paths: Optional[List[Path]] = None):
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showwarning("Scan", "A scan is already running.")
            return

        if mode == "quick":
            paths = [Path(p) for p in (config.monitor_paths or [])] or [Path.home() / "Downloads"]
        elif mode == "full":
            paths = [Path("/") if os.name != "nt" else Path(os.environ.get("SystemDrive", "C:") + "\\")]
        else:
            paths = paths or []
            if not paths:
                messagebox.showwarning("Scan", "No paths selected for custom scan.")
                return

        task = ScanTask(mode=mode, paths=paths, auto_action=self.var_auto_action.get() or "")
        self.scan_tv.delete(*self.scan_tv.get_children())
        self.var_scan_status.set("Starting…"); self.var_scan_current.set("—"); self.pb["value"] = 0
        self._scan_stop.clear()
        self._scan_thread = threading.Thread(target=self._scan_worker, args=(task,), daemon=True)
        self._scan_thread.start()
        self.logger.log(f"Starting {mode} scan on {len(paths)} path(s)")

    def _iter_files(self, roots: Iterable[Path]) -> Iterable[Path]:
        for rp in roots:
            try:
                if rp.is_file():
                    yield rp
                elif rp.is_dir():
                    for root, _, files in os.walk(rp):
                        for name in files:
                            yield Path(root) / name
            except Exception as e:
                self.logger.log(f"Enumerate error for {rp}: {e}", "WARNING")

    def _scan_worker(self, task: ScanTask):
        files = list(self._iter_files(task.paths))
        total = max(1, len(files))
        processed = 0

        def cb_progress(pct: float, current: str):
            self._uiq.put(lambda: self._scan_progress(pct, current))

        for fp in files:
            if self._scan_stop.is_set():
                break

            auto = task.auto_action if task.auto_action in {"quarantine","delete"} else None
            res = self.scanner.scan_file(fp, auto_action=auto)
            processed += 1
            pct = int(processed * 100 / total)
            cb_progress(pct, str(fp))

            if res.get("status") == "infected" and not auto:
                details = self._format_threats(res.get("threats") or [])
                choice = prompt_threat(self.root, res.get("file",""), details)
                if choice in {"quarantine","delete"}:
                    # apply action directly
                    if choice == "quarantine":
                        ok, msg = self.scanner.quarantine_path(Path(res["file"]))
                        res["action"] = "quarantine"; res["action_ok"] = ok
                        if not ok: res["action_error"] = msg
                    else:
                        ok, msg = self.scanner.delete_path(Path(res["file"]))
                        res["action"] = "delete"; res["action_ok"] = ok
                        if not ok: res["action_error"] = msg
                else:
                    res["action"] = "ignore"

            self._uiq.put(lambda r=res: self._scan_row(r))

        self._uiq.put(self._scan_done)

    def _stop_scan(self):
        self._scan_stop.set()
        self.logger.log("Stopping scan…", "INFO")

    def _scan_progress(self, pct: float, current: str):
        self.var_scan_status.set(f"Scanning… {int(pct)}%")
        self.var_scan_current.set(f"Current: {current}")
        self.pb["value"] = pct

    def _scan_row(self, res: Dict[str, Any]):
        det = self._format_threats(res.get("threats") or [])
        action = res.get("action", res.get("action_taken", "—"))
        vals = (res.get("file",""), res.get("status",""), det, action)
        self.scan_tv.insert("", "end", values=vals)
        # dashboard recent
        self.recent_tv.insert("", 0, values=(vals[0], vals[1], vals[2]))
        if len(self.recent_tv.get_children()) > 8:
            for iid in self.recent_tv.get_children()[8:]:
                self.recent_tv.delete(iid)

    def _scan_done(self):
        self.var_scan_status.set("Completed")
        self.var_scan_current.set("Done")
        self.pb["value"] = 100
        self.logger.log("Scan completed.", "INFO")

    @staticmethod
    def _format_threats(threats: List[Dict[str, Any]]) -> str:
        out = []
        for t in threats:
            # MalwareScanner can produce: hash_types (list), yara_rule, etc.
            htypes = t.get("hash_types")
            if not htypes:
                ht = t.get("hash_type")
                htypes = [ht] if ht else []
            if isinstance(htypes, str):
                htypes = [htypes]
            tag = ", ".join(str(x) for x in htypes) if htypes else "Indicators"
            name = t.get("yara_rule") or t.get("name") or "Detection"
            out.append(f"{name} — {tag}")
        return "; ".join(out)

    # --------------- Real-Time ---------------
    def _enable_rt(self, startup: bool = False):
        try:
            config.monitor_paths = self._rt_paths[:]
            self.scanner.start_realtime_protection()
            self._rt_enabled = True
            self.var_rt_state.set("Enabled"); self.var_rt_chip.set("Real-Time: On")
            if not startup:
                self.logger.log("Real-time protection enabled.", "INFO")
        except Exception as e:
            messagebox.showerror("Real-Time", f"Failed to enable: {e}")
            self.logger.log(f"Real-time enable failed: {e}", "ERROR")

    def _disable_rt(self):
        try:
            self.scanner.stop_realtime_protection()
        except Exception:
            pass
        self._rt_enabled = False
        self.var_rt_state.set("Disabled"); self.var_rt_chip.set("Real-Time: Off")
        self.logger.log("Real-time protection disabled.", "INFO")

    def _add_rt_path(self):
        p = self.var_rt_path.get().strip()
        if not p: return
        if p not in self._rt_paths:
            self._rt_paths.append(p)
            config.monitor_paths = self._rt_paths[:]
            config.save_config()
            self._refresh_rt_paths()
            self.logger.log(f"Added real-time path: {p}", "INFO")

    def _remove_rt_path(self):
        sel = self.rt_tv.selection()
        removed = 0
        for iid in sel:
            val = self.rt_tv.item(iid, "values")[0]
            if val in self._rt_paths:
                self._rt_paths.remove(val)
                removed += 1
        if removed:
            config.monitor_paths = self._rt_paths[:]
            config.save_config()
            self._refresh_rt_paths()
            self.logger.log(f"Removed {removed} path(s) from real-time monitor.", "INFO")

    def _refresh_rt_paths(self):
        self.rt_tv.delete(*self.rt_tv.get_children())
        for p in self._rt_paths:
            self.rt_tv.insert("", "end", values=(p,))

    def _simulate_rt(self):
        # optional helper for quick test
        fake = str(Path.home() / "Downloads" / "suspicious.exe")
        self._notify_threat_gui({"file": fake, "status": "infected", "threats": [{"name":"Simulated","hash_types":["TEST"]}]})

    def _notify_threat_gui(self, result: Dict[str, Any]) -> None:
        """
        Callback set on MalwareScanner to handle real-time detections.
        Presents modal and applies quarantine/delete through scanner helpers.
        """
        try:
            file_path = Path(str(result.get("file","")))
            details = self._format_threats(result.get("threats") or [])
            self.logger.log(f"[REAL-TIME] Threat detected: {file_path}", "WARNING")
            choice = prompt_threat(self.root, str(file_path), details)

            if choice == "quarantine":
                ok, msg = self.scanner.quarantine_path(file_path)
                self.logger.log(f"[REAL-TIME] {'Quarantined' if ok else 'Failed to quarantine'}: {file_path}", "WARNING" if ok else "ERROR")
            elif choice == "delete":
                ok, msg = self.scanner.delete_path(file_path)
                self.logger.log(f"[REAL-TIME] {'Deleted' if ok else 'Failed to delete'}: {file_path}", "WARNING" if ok else "ERROR")
            else:
                self.logger.log(f"[REAL-TIME] Ignored by user: {file_path}", "INFO")

            # reflect in tables
            self.scan_tv.insert("", 0, values=(str(file_path), result.get("status","infected"), details, choice or "—"))
            self.recent_tv.insert("", 0, values=(str(file_path), result.get("status","infected"), details))
        except Exception as e:
            self.logger.log(f"Real-time UI handling error: {e}", "ERROR")

    # --------------- Quarantine ---------------
    def _q_snapshot(self) -> Dict[str, float]:
        snap: Dict[str, float] = {}
        qd = Path(config.quarantine_dir)
        if not qd.exists(): return snap
        for p in qd.rglob("*"):
            if p.is_file():
                try:
                    snap[str(p)] = p.stat().st_mtime
                except Exception:
                    pass
        return snap

    def _start_quarantine_watcher(self):
        def loop():
            self._q_last_snapshot = self._q_snapshot()
            while not self._q_stop.wait(2.0):
                cur = self._q_snapshot()
                if cur != self._q_last_snapshot:
                    self._q_last_snapshot = cur
                    self._uiq.put(self._q_refresh)
        self._q_thread = threading.Thread(target=loop, name="quarantine-watch", daemon=True)
        self._q_thread.start()

    def _q_refresh(self):
        self.q_tv.delete(*self.q_tv.get_children())
        qdir = Path(config.quarantine_dir)
        if not qdir.exists(): return
        for p in sorted(qdir.rglob("*")):
            if not p.is_file(): continue
            try:
                st = p.stat()
                self.q_tv.insert(
                    "", "end", iid=str(p),
                    values=(p.name, str(p), datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"), _human_size(st.st_size))
                )
            except Exception:
                pass

    def _q_selected_paths(self) -> List[Path]:
        return [Path(iid) for iid in self.q_tv.selection()]

    def _q_restore_selected(self):
        paths = self._q_selected_paths()
        if not paths: return
        dest_dir = filedialog.askdirectory(title="Restore to folder")
        if not dest_dir: return
        restored = 0
        for p in paths:
            try:
                target = Path(dest_dir) / p.name
                # ensure unique
                i = 1
                while target.exists():
                    target = Path(dest_dir) / f"{p.stem}.{i}{p.suffix}"
                    i += 1
                os.makedirs(target.parent, exist_ok=True)
                os.replace(p, target)
                restored += 1
            except Exception as e:
                self.logger.log(f"Restore failed for {p}: {e}", "ERROR")
        self.logger.log(f"Restored {restored} item(s).", "INFO")
        self._q_refresh()

    def _q_delete_selected(self):
        paths = self._q_selected_paths()
        if not paths: return
        if not messagebox.askyesno("Quarantine", f"Delete {len(paths)} selected item(s)?"):
            return
        cnt = 0
        for p in paths:
            try:
                p.unlink(missing_ok=True)
                cnt += 1
            except Exception as e:
                self.logger.log(f"Delete failed for {p}: {e}", "ERROR")
        self.logger.log(f"Deleted {cnt} quarantined item(s).", "INFO")
        self._q_refresh()

    # --------------- Signatures ---------------
    def _sig_add(self):
        h = self.var_sig_hash.get().strip().lower()
        t = self.var_sig_type.get().lower()
        if not h or not all(c in "0123456789abcdef" for c in h):
            messagebox.showwarning("Signatures", "Hash must be hexadecimal.")
            return
        if t == "md5" and len(h) != 32:
            messagebox.showwarning("Signatures", "MD5 must be 32 hex chars.")
            return
        if t == "sha256" and len(h) != 64:
            messagebox.showwarning("Signatures", "SHA256 must be 64 hex chars.")
            return
        try:
            if h in self.sigdb.signatures[t]:
                messagebox.showinfo("Signatures", "Already exists.")
                return
            self.sigdb.add_signature(h, t)
            self._sig_refresh()
            self.logger.log(f"Added {t.upper()} signature: {h}", "INFO")
            self.var_sig_hash.set("")
        except Exception as e:
            messagebox.showerror("Signatures", f"Failed: {e}")

    def _sig_export(self):
        try:
            data = {
                "md5": sorted(self.sigdb.signatures["md5"]),
                "sha256": sorted(self.sigdb.signatures["sha256"]),
            }
        except Exception:
            data = {"md5": [], "sha256": []}
        out = filedialog.asksaveasfilename(defaultextension=".json",
                                           filetypes=[("JSON","*.json")],
                                           title="Export Signatures")
        if not out: return
        Path(out).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.logger.log(f"Exported signatures to {out}", "INFO")

    def _sig_import(self):
        fn = filedialog.askopenfilename(filetypes=[("JSON","*.json")], title="Import Signatures")
        if not fn: return
        try:
            data = json.loads(Path(fn).read_text(encoding="utf-8"))
            md5s = [str(x).lower() for x in data.get("md5", [])]
            sha256s = [str(x).lower() for x in data.get("sha256", [])]
            for h in md5s: self.sigdb.add_signature(h, "md5")
            for h in sha256s: self.sigdb.add_signature(h, "sha256")
            self._sig_refresh()
            self.logger.log(f"Imported signatures: MD5={len(md5s)} SHA256={len(sha256s)}", "INFO")
        except Exception as e:
            messagebox.showerror("Import", f"Failed: {e}")

    def _sig_refresh(self):
        self.sig_tv.delete(*self.sig_tv.get_children())
        try:
            rows = [("MD5", h) for h in sorted(self.sigdb.signatures["md5"])]
            rows += [("SHA256", h) for h in sorted(self.sigdb.signatures["sha256"])]
        except Exception:
            rows = []
        for typ, h in rows:
            self.sig_tv.insert("", "end", values=(typ, h))

    # --------------- Logs ---------------
    def _log_copy(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(self._log_lines))
            messagebox.showinfo("Logs", "Logs copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Logs", str(e))

    def _open_log_file(self):
        try:
            log_path = Path(config.log_file)
            messagebox.showinfo("Logs", f"Log file: {log_path}")
        except Exception as e:
            messagebox.showerror("Logs", str(e))


# For manual execution
if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    def _on_close():
        try:
            app.destroy()
        except Exception:
            pass
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()
