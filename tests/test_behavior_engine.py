# tests/test_behavior_engine.py
"""
BehaviorEngine tests: synthetic events drive the correlator and check scoring,
rule hits, allow/deny behavior, reputation dampening/boost, and emission.
No destructive actions are taken: suspend/kill are monkeypatched.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

# Import from your package
from maldefender.app_logger import Logger
from maldefender.behavior_engine import (
    BehaviorEngine,
    ProcInfo,
    NetEvent,
    FSEvent,
    CorrelatedWindow,
)

# ------------------------
# Helpers
# ------------------------

def make_engine(threshold: int = 80) -> BehaviorEngine:
    """Engine with a test logger and lowered threshold for faster assertions."""
    eng = BehaviorEngine(logger=Logger(), emit_threshold=threshold, window_seconds=30)
    # Disable actual suspends during tests
    eng._suspend_safe = lambda pid: None  # type: ignore[attr-defined]
    return eng

def add_window_with_proc(eng: BehaviorEngine, proc: ProcInfo) -> CorrelatedWindow:
    """Register a process and return its correlation window."""
    eng._known_pids[proc.pid] = proc
    win = eng._windows.setdefault(proc.pid, CorrelatedWindow(pid=proc.pid, proc=proc))
    return win

def now() -> float:
    return time.time()

# ------------------------
# Tests
# ------------------------

def test_rule_lolbin_from_user_writable(tmp_path: Path):
    eng = make_engine()
    # Simulate LOLBin executed from user-writable path (e.g., Downloads)
    exe = tmp_path / "Downloads" / "powershell.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    proc = ProcInfo(
        pid=1111, ppid=1, name="powershell.exe", exe=str(exe),
        cmdline=["powershell.exe", "-NoProfile"], username="user", create_time=now()
    )
    win = add_window_with_proc(eng, proc)

    eng._apply_rules(win)
    hit_ids = {h.rule_id for h in win.rule_hits}
    assert "spawn.lolbin.userwrite" in hit_ids, f"Got hits: {hit_ids}"

def test_rule_obfuscated_command_line(tmp_path: Path):
    eng = make_engine()
    exe = tmp_path / "Downloads" / "powershell.exe"
    proc = ProcInfo(
        pid=1112, ppid=1, name="powershell.exe", exe=str(exe),
        cmdline=["powershell.exe", "-enc", "JABvAGIAZgA="], username="user", create_time=now()
    )
    win = add_window_with_proc(eng, proc)

    eng._apply_rules(win)
    hit_ids = {h.rule_id for h in win.rule_hits}
    assert "cmd.obfuscated" in hit_ids

def test_rule_network_fanout():
    eng = make_engine()
    proc = ProcInfo(
        pid=1200, ppid=1, name="curl.exe", exe="C:\\Users\\u\\Downloads\\curl.exe",
        cmdline=["curl", "http://x"], username="user", create_time=now()
    )
    win = add_window_with_proc(eng, proc)

    # Inject >= 8 unique remote endpoints
    for i in range(10):
        ne = NetEvent(ts=now(), pid=proc.pid, laddr="127.0.0.1", lport=50000+i,
                      raddr=f"203.0.113.{i}", rport=80+i, status="ESTABLISHED")
        eng._attach_net_event(ne)

    eng._apply_rules(win)
    hit_ids = {h.rule_id for h in win.rule_hits}
    assert "net.fanout" in hit_ids

def test_rule_drop_exec_in_user_area(tmp_path: Path):
    eng = make_engine()
    proc = ProcInfo(
        pid=1300, ppid=1, name="unknown.exe", exe=str(tmp_path / "Downloads" / "unknown.exe"),
        cmdline=["unknown.exe"], username="user", create_time=now()
    )
    win = add_window_with_proc(eng, proc)

    # Create executable in Desktop (user writable)
    path = tmp_path / "Desktop" / "dropped.exe"
    path.parent.mkdir(parents=True, exist_ok=True)
    fe = FSEvent(ts=now(), op="create", path=str(path), pid_hint=proc.pid)
    eng._attach_fs_event(fe)

    eng._apply_rules(win)
    hit_ids = {h.rule_id for h in win.rule_hits}
    assert "fs.drop.exec.user" in hit_ids

def test_rule_parent_office_to_lolbin(tmp_path: Path):
    eng = make_engine()
    # Parent = WINWORD.exe
    parent = ProcInfo(
        pid=2000, ppid=1, name="WINWORD.EXE", exe="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        cmdline=["WINWORD.EXE", "report.docm"], username="user", create_time=now()
    )
    eng._known_pids[parent.pid] = parent
    eng._windows[parent.pid] = CorrelatedWindow(pid=parent.pid, proc=parent)

    # Child = powershell.exe started from user dir
    child_exe = tmp_path / "Downloads" / "powershell.exe"
    child = ProcInfo(
        pid=2001, ppid=parent.pid, name="powershell.exe", exe=str(child_exe),
        cmdline=["powershell.exe", "-NoP"], username="user", create_time=now()
    )
    win = add_window_with_proc(eng, child)

    eng._apply_rules(win)
    hit_ids = {h.rule_id for h in win.rule_hits}
    assert "chain.office_to_lolbin" in hit_ids

def test_reputation_good_dampens_and_bad_boosts(tmp_path: Path):
    eng = make_engine()
    good_exe = tmp_path / "Downloads" / "goodtool.exe"
    bad_exe = tmp_path / "Downloads" / "badtool.exe"

    proc_good = ProcInfo(pid=3001, ppid=1, name="goodtool.exe", exe=str(good_exe),
                         cmdline=[], username="user", create_time=now())
    proc_bad = ProcInfo(pid=3002, ppid=1, name="badtool.exe", exe=str(bad_exe),
                        cmdline=[], username="user", create_time=now())

    win_good = add_window_with_proc(eng, proc_good)
    win_bad = add_window_with_proc(eng, proc_bad)

    eng.reputation.set_path(good_exe, "known_good")
    eng.reputation.set_path(bad_exe, "known_bad")

    eng._apply_rules(win_good)
    eng._apply_rules(win_bad)

    good_ids = {h.rule_id for h in win_good.rule_hits}
    bad_ids = {h.rule_id for h in win_bad.rule_hits}

    assert "rep.good" in good_ids
    assert "rep.bad" in bad_ids

def test_allowlist_and_denylist_affect_score(tmp_path: Path):
    eng = make_engine(threshold=10)  # lower threshold to force emission
    exe = tmp_path / "Downloads" / "tool.exe"
    proc = ProcInfo(pid=4000, ppid=1, name="tool.exe", exe=str(exe),
                    cmdline=[], username="user", create_time=now())
    win = add_window_with_proc(eng, proc)

    # Denylist should add strong positive weight
    eng.denylist_add(str(exe))
    # Denylist weight is appended during emission evaluation
    eng._evaluate_and_emit(now())
    assert win.score() >= 10  # denylist.hit adds 100, so this should pass

    # Allowlist should dampen (add negative weight)
    win.rule_hits.clear()
    eng.allowlist_add(str(exe))
    eng._apply_rules(win)
    assert any(h.rule_id == "allowlist.dampen" for h in win.rule_hits)

def test_incident_emission_triggers_notifier(tmp_path: Path):
    notified = {}

    def capture(incident: dict) -> None:
        notified["incident"] = incident

    eng = make_engine(threshold=10)
    eng.set_notify_incident(capture)

    # Build a window with a definite hit (denylist)
    exe = tmp_path / "Downloads" / "sus.exe"
    proc = ProcInfo(pid=5000, ppid=1, name="sus.exe", exe=str(exe),
                    cmdline=[], username="user", create_time=now())
    win = add_window_with_proc(eng, proc)
    eng.denylist_add(str(exe))

    # Evaluate and emit
    eng._evaluate_and_emit(now=time.time())

    assert "incident" in notified, "No incident emitted"
    inc = notified["incident"]
    assert inc["pid"] == 5000
    assert inc["score"] >= 10
    assert any(r["rule_id"].startswith("denylist.") for r in inc["rule_hits"])
