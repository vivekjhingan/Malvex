# devtools/simulate_behavior.py
from __future__ import annotations
import time
from pathlib import Path

from maldefender.app_logger import Logger
from maldefender.behavior_engine import (
    BehaviorEngine,
    ProcInfo,
    FSEvent,
    NetEvent,
    CorrelatedWindow,
)

def main():
    logger = Logger()
    eng = BehaviorEngine(logger=logger, emit_threshold=40, window_seconds=15)
    eng._suspend_safe = lambda pid: None  # prevent psutil suspend attempt in simulation

    def notify(incident: dict) -> None:
        print("\n=== INCIDENT ===")
        print(f"PID={incident.get('pid')} SCORE={incident.get('score')}")
        for rh in incident.get("rule_hits", []):
            print(f" - {rh['rule_id']} (w={rh['weight']}) :: {rh['reason']}")
        print("=== END ===\n")

    eng.set_notify_incident(notify)

    # Process in a user-writable path (LOLBin + obfuscated cmd)
    exe = Path.cwd() / "Downloads" / "powershell.exe"
    proc = ProcInfo(
        pid=7777, ppid=777, name="powershell.exe", exe=str(exe),
        cmdline=["powershell.exe", "-enc", "JABvAGIAZgA="],
        username="user", create_time=time.time()
    )

    # Register process + window correctly
    eng._known_pids[proc.pid] = proc
    eng._windows[proc.pid] = CorrelatedWindow(pid=proc.pid, proc=proc)

    # FS create of an .exe in Desktop (tie it to this PID!)
    eng._attach_fs_event(FSEvent(ts=time.time(), op="create",
                                 path=str(Path.cwd() / "Desktop" / "d.exe"),
                                 pid_hint=proc.pid))

    # A few outbound connections to different endpoints
    for i in range(8):
        eng._attach_net_event(NetEvent(ts=time.time(), pid=proc.pid,
                                       laddr="127.0.0.1", lport=40000+i,
                                       raddr=f"198.51.100.{i}", rport=8000+i,
                                       status="ESTABLISHED"))

    # Correlate and emit
    eng._evaluate_and_emit(time.time())

if __name__ == "__main__":
    main()
