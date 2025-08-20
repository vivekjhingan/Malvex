# malvex/realtime_monitor.py
import time
import threading
from pathlib import Path
from typing import List, Callable, Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

from .app_config import config

_IGNORE_GLOBS = {"~$*", "*.part", "*.crdownload", "*.tmp", ".*.swp", ".*.swx", ".*.swp", ".*.tmp"}
_DEBOUNCE_MS = 750
_STABLE_WAIT_MS = 400

class RealTimeMonitor(FileSystemEventHandler):
    """Real-time file system monitoring with debounce & stability check."""

    def __init__(self, scanner_callback: Callable[[Path], None]):
        super().__init__()
        self.scanner_callback = scanner_callback
        self.observers: List[Observer] = []
        self._timers: Dict[Path, threading.Timer] = {}
        self._lock = threading.Lock()

    def _ignored(self, p: Path) -> bool:
        name = p.name
        for pat in _IGNORE_GLOBS:
            if p.match(pat) or Path(name).match(pat):
                return True
        return False

    def _schedule_scan(self, p: Path):
        try:
            rp = p.resolve()
        except Exception:
            return
        if not rp.is_file() or self._ignored(rp):
            return
        # ignore quarantine dir early
        try:
            if config.quarantine_dir.resolve() in rp.parents:
                return
        except Exception:
            pass
        with self._lock:
            t = self._timers.get(rp)
            if t:
                t.cancel()
            timer = threading.Timer(_DEBOUNCE_MS / 1000.0, self._scan_if_stable, args=(rp,))
            self._timers[rp] = timer
            timer.start()

    def _scan_if_stable(self, p: Path):
        def stat_tuple(path: Path):
            try:
                st = path.stat()
                return (st.st_size, st.st_mtime)
            except Exception:
                return None

        first = stat_tuple(p)
        if not first:
            return
        time.sleep(_STABLE_WAIT_MS / 1000.0)
        second = stat_tuple(p)
        if first == second:
            try:
                self.scanner_callback(p)
            finally:
                with self._lock:
                    self._timers.pop(p, None)

    def on_created(self, event: FileCreatedEvent):
        if not event.is_directory:
            self._schedule_scan(Path(event.src_path))

    def on_modified(self, event: FileModifiedEvent):
        if not event.is_directory:
            self._schedule_scan(Path(event.src_path))

    def start_monitoring(self, paths: List[str]):
        self.stop_monitoring()
        self.observers = []
        for path_str in paths:
            p = Path(path_str)
            if p.exists() and p.is_dir():
                obs = Observer()
                obs.schedule(self, path_str, recursive=True)
                obs.start()
                self.observers.append(obs)
            else:
                print(f"Warning: Real-time monitoring path invalid: {path_str}")

    def stop_monitoring(self):
        with self._lock:
            for t in self._timers.values():
                try: t.cancel()
                except Exception: pass
            self._timers.clear()
        for obs in self.observers:
            try:
                obs.stop()
                obs.join(timeout=2)
            except Exception as e:
                print(f"Error stopping observer: {e}")
        self.observers.clear()
