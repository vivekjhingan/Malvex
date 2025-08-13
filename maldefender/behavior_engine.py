# maldefender/behavior_engine.py
"""
Behavioral Analysis Engine (portable baseline + optional Windows enhancements)

Key capabilities
- Monitors runtime behavior with low overhead:
  * Process events: spawn tree, parent-child chains, suspicious command-lines (LOLBins), privilege context
  * File system events: new/modified/deleted executables & scripts in user-writable locations
  * Network activity: new outbound connections, fan-out, unusual ports
- Correlates within a time window and produces a risk score with explainable reasons
- Maintains allowlist/denylist and a reputation cache
- On incident: logs rich context and can take actions (suspend/kill, quarantine dropped file(s), rollback)

Design notes
- Portable baseline uses psutil polling + watchdog hooks you already ship.
- Windows extras (optional): will bind if pywin32 is present to add token/admin context hints.
- All threads are daemonized and fail-safe (never crash the app).
- The engine exposes a `notify_incident` callback, mirroring your malware scan notifier.

Dependencies (add to requirements.txt if missing):
  psutil>=5.9.0
"""

from __future__ import annotations

import os
import re
import json
import time
import queue
import psutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .app_config import config
from .app_logger import Logger
from .reputation_cache import ReputationCache
from .rollback_journal import RollbackJournal

NotifyIncident = Callable[[Dict[str, Any]], None]


# ---- Utility: safe set membership for names/paths ----

_LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "wmic.exe", "schtasks.exe",
    # nix equivalents / script engines
    "bash", "sh", "python", "perl", "ruby", "node"
}

_EXEC_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".py", ".jar", ".apk"}
_USER_WRITE_HINTS = {"downloads", "appdata", "temp", "tmp", "desktop"}

# Suspicious paths (heuristic) - case-insensitive contains check
def _path_suspicious_user_writable(p: Path) -> bool:
    s = str(p).lower()
    return any(h in s for h in _USER_WRITE_HINTS)


# ---- Datamodels ----

@dataclass
class ProcInfo:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    create_time: float
    is_elevated_hint: bool = False  # Best-effort, true if admin/root (when detectable)


@dataclass
class NetEvent:
    ts: float
    pid: int
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str


@dataclass
class FSEvent:
    ts: float
    op: str  # "create" | "modify" | "delete"
    path: str
    pid_hint: Optional[int] = None


@dataclass
class RuleHit:
    rule_id: str
    weight: int
    reason: str


@dataclass
class CorrelatedWindow:
    """Events for a PID grouped by time-window."""
    pid: int
    proc: Optional[ProcInfo]
    fsevents: List[FSEvent] = field(default_factory=list)
    netevents: List[NetEvent] = field(default_factory=list)
    children: Set[int] = field(default_factory=set)
    rule_hits: List[RuleHit] = field(default_factory=list)

    def score(self) -> int:
        return sum(r.weight for r in self.rule_hits)


# ---- BehaviorEngine ----

class BehaviorEngine:
    """
    Coordinates watchers (process, network, fs), correlates within a sliding window, evaluates rules,
    and emits incidents for scored windows above threshold.

    Public API:
      start(), stop()
      ingest_fs_create/modify/delete(...)  # to receive callbacks from realtime_monitor (optional)
      allowlist_add/remove, denylist_add/remove
      set_notify_incident(callback)
    """

    def __init__(
        self,
        logger: Logger,
        notify_incident: Optional[NotifyIncident] = None,
        window_seconds: int = 30,
        emit_threshold: int = 80,
        max_backlog: int = 5000,
    ):
        self.logger = logger
        self.notify_incident = notify_incident

        self.window_seconds = max(10, window_seconds)
        self.emit_threshold = max(1, emit_threshold)
        self.max_backlog = max(1000, max_backlog)

        self._run = threading.Event()
        self._run.clear()

        self._proc_lock = threading.Lock()
        self._known_pids: Dict[int, ProcInfo] = {}

        self._windows_lock = threading.Lock()
        self._windows: Dict[int, CorrelatedWindow] = {}

        # Back-pressure queues to keep overhead low
        self._fs_q: "queue.Queue[FSEvent]" = queue.Queue(maxsize=self.max_backlog)
        self._net_q: "queue.Queue[NetEvent]" = queue.Queue(maxsize=self.max_backlog)

        self._threads: List[threading.Thread] = []

        # Reputation + Rollback
        self.reputation = ReputationCache(logger)
        self.rollback = RollbackJournal(logger)

        # Allow/Deny
        self.allowlist_paths: Set[str] = set()
        self.denylist_paths: Set[str] = set()

        # Precompiled patterns
        self._enc_cmd_pat = re.compile(r"(?:-enc|-encodedcommand|frombase64string)", re.IGNORECASE)

        # Try Windows elevation hint (optional)
        self._platform = os.name
        self._win_has_pywin32 = False
        try:
            import win32api  # type: ignore
            import win32security  # type: ignore
            self._win_has_pywin32 = True
        except Exception:
            self._win_has_pywin32 = False

        self.logger.log("[Behavior] Engine initialized", "INFO")

    # -------- Lifecycle --------

    def start(self) -> None:
        """Start polling watchers."""
        if self._run.is_set():
            return

        self._run.set()
        self._threads = [
            threading.Thread(target=self._proc_watcher, name="bhv-proc", daemon=True),
            threading.Thread(target=self._net_watcher, name="bhv-net", daemon=True),
            threading.Thread(target=self._correlator_loop, name="bhv-corr", daemon=True),
        ]
        for t in self._threads:
            t.start()
        self.logger.log("[Behavior] Engine started", "INFO")

    def stop(self) -> None:
        """Stop watchers and flush state (non-blocking)."""
        self._run.clear()
        for t in self._threads:
            try:
                t.join(timeout=1.5)
            except Exception:
                pass
        self._threads.clear()
        self.logger.log("[Behavior] Engine stopped", "INFO")

    def set_notify_incident(self, cb: NotifyIncident) -> None:
        self.notify_incident = cb

    # -------- Optional FS ingestion (from realtime_monitor) --------

    def ingest_fs_create(self, path: Path, pid_hint: Optional[int] = None) -> None:
        self._enqueue_fs("create", path, pid_hint)

    def ingest_fs_modify(self, path: Path, pid_hint: Optional[int] = None) -> None:
        self._enqueue_fs("modify", path, pid_hint)

    def ingest_fs_delete(self, path: Path, pid_hint: Optional[int] = None) -> None:
        self._enqueue_fs("delete", path, pid_hint)

    def _enqueue_fs(self, op: str, path: Path, pid_hint: Optional[int]) -> None:
        ev = FSEvent(ts=time.time(), op=op, path=str(path), pid_hint=pid_hint)
        try:
            self._fs_q.put_nowait(ev)
            # Journal file creations for possible rollback
            if op == "create":
                self.rollback.record_creation(Path(ev.path))
        except queue.Full:
            self.logger.log("[Behavior] FS queue full; dropping event", "WARNING")

    # -------- Allow/Deny --------

    def allowlist_add(self, path_or_exe: str) -> None:
        self.allowlist_paths.add(path_or_exe.lower())
        self.logger.log(f"[Behavior] Allowlisted: {path_or_exe}", "INFO")

    def allowlist_remove(self, path_or_exe: str) -> None:
        self.allowlist_paths.discard(path_or_exe.lower())

    def denylist_add(self, path_or_exe: str) -> None:
        self.denylist_paths.add(path_or_exe.lower())
        self.logger.log(f"[Behavior] Denylisted: {path_or_exe}", "WARNING")

    def denylist_remove(self, path_or_exe: str) -> None:
        self.denylist_paths.discard(path_or_exe.lower())

    # -------- Watchers --------

    def _proc_watcher(self) -> None:
        """Poll process table; detect spawns, capture metadata, track children."""
        # Initial snapshot
        try:
            for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
                self._remember_proc(p)
        except Exception as e:
            self.logger.log(f"[Behavior] Initial process snapshot error: {e}", "ERROR")

        # Poll loop (low frequency to keep overhead down)
        while self._run.is_set():
            start = time.time()
            try:
                seen: Set[int] = set()
                for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
                    seen.add(p.info["pid"])
                    if p.info["pid"] not in self._known_pids:
                        pi = self._remember_proc(p)
                        if pi:
                            # Link as child in parent window for correlation
                            with self._windows_lock:
                                par = self._windows.get(pi.ppid)
                                if par:
                                    par.children.add(pi.pid)
                            # Rule seeds (spawn anomalies evaluated in correlator)
            except Exception as e:
                self.logger.log(f"[Behavior] Process poll error: {e}", "ERROR")

            # GC: remove exits
            with self._proc_lock:
                dead = [pid for pid in self._known_pids if pid not in seen]
                for pid in dead:
                    self._known_pids.pop(pid, None)

            # 500ms baseline cadence
            elapsed = time.time() - start
            time.sleep(max(0.2, 0.5 - elapsed))

    def _remember_proc(self, p: psutil.Process) -> Optional[ProcInfo]:
        try:
            info = p.as_dict(attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"])
            exe = info.get("exe") or info.get("name") or ""
            cmd = info.get("cmdline") or []
            elevated = self._elevated_hint(p)
            pi = ProcInfo(
                pid=info.get("pid", -1),
                ppid=info.get("ppid", -1),
                name=(info.get("name") or "")[:255],
                exe=(exe or "")[:1024],
                cmdline=[str(x)[:4096] for x in cmd],
                username=str(info.get("username") or ""),
                create_time=float(info.get("create_time") or time.time()),
                is_elevated_hint=elevated,
            )
            with self._proc_lock:
                self._known_pids[pi.pid] = pi
            # Initialize window on first sight
            with self._windows_lock:
                self._windows.setdefault(pi.pid, CorrelatedWindow(pid=pi.pid, proc=pi))
            return pi
        except Exception as e:
            self.logger.log(f"[Behavior] remember_proc error: {e}", "ERROR")
            return None

    def _elevated_hint(self, p: psutil.Process) -> bool:
        """Best-effort elevation indicator. On Windows uses admin group; on *nix uid==0."""
        try:
            if os.name == "nt":
                # psutil cannot directly tell; approximate by username contains 'Administrator' or admin group.
                name = (p.username() or "").lower()
                if "administrator" in name:  # heuristic
                    return True
                # Optional: pywin32 groups (if available)
                if self._win_has_pywin32:
                    try:
                        import win32security  # type: ignore
                        import win32api  # type: ignore
                        h = win32api.OpenProcess(0x0400, False, p.pid)  # PROCESS_QUERY_INFORMATION
                        token = win32security.OpenProcessToken(h, 0x0008)  # TOKEN_QUERY
                        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
                        for sid, attrs in groups:
                            try:
                                name, dom, _ = win32security.LookupAccountSid(None, sid)
                                if name.lower() in {"administrators", "system"}:
                                    return True
                            except Exception:
                                pass
                    except Exception:
                        pass
                return False
            else:
                return p.uids().effective == 0  # type: ignore[attr-defined]
        except Exception:
            return False

    def _net_watcher(self) -> None:
        """Poll net connections and enqueue new outbound events."""
        seen: Set[Tuple[int, str, int, str, int]] = set()
        while self._run.is_set():
            start = time.time()
            try:
                conns = psutil.net_connections(kind="inet")
                now = time.time()
                for c in conns:
                    if not c.raddr:  # only outbound with remote
                        continue
                    tup = (c.pid or -1, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                    if tup in seen:
                        continue
                    seen.add(tup)
                    ev = NetEvent(
                        ts=now,
                        pid=c.pid or -1,
                        laddr=c.laddr.ip, lport=c.laddr.port,
                        raddr=c.raddr.ip, rport=c.raddr.port,
                        status=c.status
                    )
                    try:
                        self._net_q.put_nowait(ev)
                    except queue.Full:
                        # Keep it silent but visible in logs
                        self.logger.log("[Behavior] NET queue full; dropping event", "WARNING")
            except Exception as e:
                self.logger.log(f"[Behavior] net poll error: {e}", "ERROR")

            # 1s cadence is enough and low overhead
            elapsed = time.time() - start
            time.sleep(max(0.5, 1.0 - elapsed))

    # -------- Correlator & Rules --------

    def _correlator_loop(self) -> None:
        """
        Consumes FS/NET queues, updates correlation windows per PID, applies rules,
        emits incidents for windows over threshold, and garbage-collects stale windows.
        """
        while self._run.is_set():
            now = time.time()

            # Drain FS events quickly (bounded per tick to keep latency predictable)
            for _ in range(128):
                try:
                    fe = self._fs_q.get_nowait()
                except queue.Empty:
                    break
                self._attach_fs_event(fe)

            # Drain NET events quickly
            for _ in range(128):
                try:
                    ne = self._net_q.get_nowait()
                except queue.Empty:
                    break
                self._attach_net_event(ne)

            # Evaluate rules for active windows and emit
            self._evaluate_and_emit(now)

            # GC old windows
            self._gc_windows(now)

            time.sleep(0.2)

    def _attach_fs_event(self, ev: FSEvent) -> None:
        pid = ev.pid_hint or -1
        # If pid unknown, associate to special bucket -1 (still evaluated for global ransomware-like spikes)
        with self._windows_lock:
            win = self._windows.setdefault(pid, CorrelatedWindow(pid=pid, proc=self._known_pids.get(pid)))
            win.fsevents.append(ev)

    def _attach_net_event(self, ev: NetEvent) -> None:
        with self._windows_lock:
            win = self._windows.setdefault(ev.pid, CorrelatedWindow(pid=ev.pid, proc=self._known_pids.get(ev.pid)))
            win.netevents.append(ev)

    def _evaluate_and_emit(self, now: float) -> None:
        cutoff = now - self.window_seconds
        emit: List[CorrelatedWindow] = []

        with self._windows_lock:
            for pid, win in list(self._windows.items()):
                # Keep only events in window
                win.fsevents = [e for e in win.fsevents if e.ts >= cutoff]
                win.netevents = [e for e in win.netevents if e.ts >= cutoff]
                win.rule_hits.clear()

                # Apply rule set (now includes allow/deny)
                self._apply_rules(win)

                if win.score() >= self.emit_threshold:
                    emit.append(win)

        for win in emit:
            self._emit_incident(win)

    def _apply_rules(self, win: CorrelatedWindow) -> None:
        """
        Explainable, additive rules. Weights are conservative to minimize false positives.
        """
        p = win.proc
        name = (p.name if p else "").lower()
        exe = Path((p.exe if p else "") or "")
        cmd = " ".join(p.cmdline) if p else ""
        is_user_writable = _path_suspicious_user_writable(exe)

        # R1: LOLBin started from user-writable location
        if name in _LOLBINS and is_user_writable:
            win.rule_hits.append(RuleHit(
                "spawn.lolbin.userwrite", 50,
                f"LOLBin '{name}' launched from user-writable path: {exe}"
            ))

        # R2: Encoded/obfuscated command-lines (common with PowerShell)
        if cmd and self._enc_cmd_pat.search(cmd):
            win.rule_hits.append(RuleHit(
                "cmd.obfuscated", 45,
                "Command-line with encoded content/flags detected"
            ))

        # R3: High fan-out outbound connections in window
        fanout = len({(e.raddr, e.rport) for e in win.netevents})
        if fanout >= 8:
            win.rule_hits.append(RuleHit(
                "net.fanout", 30 + (fanout // 8) * 10,
                f"High outbound fan-out: {fanout} unique remote endpoints"
            ))

        # R4: Unusual outbound ports (not 80/443/53/123/587/993 etc.)
        unusual = [e for e in win.netevents if e.rport not in {80, 443, 53, 123, 587, 993}]
        if len(unusual) >= 4:
            win.rule_hits.append(RuleHit(
                "net.unusual_ports", 25,
                f"Multiple connections to uncommon ports: sample={[(e.raddr, e.rport) for e in unusual[:3]]}"
            ))

        # R5: File dropper behavior (creates executable/script in user dirs)
        created_execs = [e for e in win.fsevents if e.op == "create" and Path(e.path).suffix.lower() in _EXEC_EXT]
        created_execs_usr = [e for e in created_execs if _path_suspicious_user_writable(Path(e.path))]
        if created_execs_usr:
            win.rule_hits.append(RuleHit(
                "fs.drop.exec.user", 45,
                f"Created executable/script in user area: sample={created_execs_usr[0].path}"
            ))

        # R6: Write-burst heuristic (ransomware-like bursts; rough proxy)
        modifies = [e for e in win.fsevents if e.op in {"create", "modify"}]
        if len(modifies) >= 200:
            win.rule_hits.append(RuleHit(
                "fs.write_burst.heavy", 60,
                f"Very high file write burst in window: {len(modifies)} ops"
            ))
        elif len(modifies) >= 80:
            win.rule_hits.append(RuleHit(
                "fs.write_burst.medium", 30,
                f"Elevated file write burst in window: {len(modifies)} ops"
            ))

        # R7: Elevated process from user-writable path
        if p and p.is_elevated_hint and is_user_writable:
            win.rule_hits.append(RuleHit(
                "priv.elev_user_path", 40,
                f"Elevated process executing from user path: {exe}"
            ))

        # R8: Suspicious parent-child chain (office -> script/LOLBin; browser -> powershell)
        suspicious_child = False
        if p:
            parent = self._known_pids.get(p.ppid)
            if parent:
                parent_n = (parent.name or "").lower()
                if any(x in parent_n for x in ("winword", "excel", "powerpnt", "acrord", "chrome", "edge", "firefox")) \
                   and (name in _LOLBINS or name in {"python", "wscript.exe", "cscript.exe"}):
                    suspicious_child = True
        if suspicious_child:
            win.rule_hits.append(RuleHit(
                "chain.office_to_lolbin", 55,
                "Office/PDF/Browser spawned a LOLBin or script engine"
            ))

        # R9: Reputation dampening/boost
        rep = self.reputation.repute(exe)
        if rep == "known_good":
            win.rule_hits.append(RuleHit("rep.good", -40, "Reputation: known good"))
        elif rep == "known_bad":
            win.rule_hits.append(RuleHit("rep.bad", 60, "Reputation: known bad"))

        # R10: Policy lists (moved here so tests that call _apply_rules see these hits)
        proc_path = (str(exe) if exe else "").lower()
        if any(d in proc_path for d in self.denylist_paths):
            win.rule_hits.append(RuleHit("denylist.hit", 100, f"Explicit denylist match: {proc_path}"))
        if any(a in proc_path for a in self.allowlist_paths):
            win.rule_hits.append(RuleHit("allowlist.dampen", -60, f"Explicit allowlist match: {proc_path}"))

    def _emit_incident(self, win: CorrelatedWindow) -> None:
        p = win.proc
        exe = Path((p.exe if p else "") or "")
        score = win.score()

        context: Dict[str, Any] = {
            "type": "behavior_incident",
            "score": score,
            "pid": p.pid if p else win.pid,
            "ppid": p.ppid if p else None,
            "process": {
                "name": p.name if p else None,
                "exe": str(exe) if p else None,
                "cmdline": p.cmdline if p else None,
                "username": p.username if p else None,
                "create_time": p.create_time if p else None,
                "is_elevated_hint": p.is_elevated_hint if p else False,
            },
            "children": sorted(list(win.children)),
            "fs_activity": [e.__dict__ for e in win.fsevents][:100],  # cap for log
            "net_activity": [e.__dict__ for e in win.netevents][:100],
            "rule_hits": [r.__dict__ for r in win.rule_hits],
            "window_seconds": self.window_seconds,
        }

        self.logger.log(f"[Behavior] INCIDENT score={score} exe={exe} pid={context['pid']}", "WARNING")
        self.logger.log(json.dumps({"behavior_incident": context}, default=str), "DEBUG")

        # Default preventive action: suspend process (safe), then let UI decide
        self._suspend_safe(context["pid"])

        if self.notify_incident:
            try:
                self.notify_incident(context)
            except Exception as e:
                self.logger.log(f"[Behavior] notify_incident error: {e}", "ERROR")

    def _suspend_safe(self, pid: int) -> None:
        try:
            if pid <= 0:
                return
            p = psutil.Process(pid)
            p.suspend()
            self.logger.log(f"[Behavior] Suspended PID {pid} pending user action", "WARNING")
        except Exception as e:
            self.logger.log(f"[Behavior] Suspend failed for PID {pid}: {e}", "ERROR")

    def _gc_windows(self, now: float) -> None:
        cutoff = now - max(self.window_seconds * 3, 90)
        with self._windows_lock:
            stale = [pid for pid, w in self._windows.items()
                     if (w.proc and w.proc.create_time < cutoff and not w.fsevents and not w.netevents)
                     or (pid == -1 and not w.fsevents and not w.netevents)]
            for pid in stale:
                self._windows.pop(pid, None)
