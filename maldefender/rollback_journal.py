# malvex/rollback_journal.py
"""
Rollback journal for created files.

- Records file creations to allow best-effort rollback (delete or move to quarantine) if user chooses.
- We keep the journal small and prune old entries.

Notes:
- True content rollback for modified files requires VSS/snapshots or kernel minifilter; out of scope here.
- Our best-effort focus: dropper cleanup (new executables/scripts) and bulk write bursts.
"""

from __future__ import annotations

import time
import json
import shutil
from pathlib import Path
from typing import Dict, List

from .app_config import config
from .app_logger import Logger


class RollbackJournal:
    def __init__(self, logger: Logger, max_entries: int = 5000, ttl_seconds: int = 2 * 3600):
        self.logger = logger
        self.store_path = config.base_dir / "rollback_journal.json"
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._entries: List[Dict[str, float]] = []
        self._load()

    def _load(self) -> None:
        try:
            if self.store_path.exists():
                self._entries = json.loads(self.store_path.read_text(encoding="utf-8"))
        except Exception as e:
            self.logger.log(f"[Rollback] load error: {e}", "ERROR")

    def _save(self) -> None:
        try:
            self.store_path.write_text(json.dumps(self._entries[-self.max_entries:], indent=2), encoding="utf-8")
        except Exception as e:
            self.logger.log(f"[Rollback] save error: {e}", "ERROR")

    def record_creation(self, path: Path) -> None:
        try:
            self._entries.append({"path": str(path), "ts": time.time()})
            # prune here lightly
            cutoff = time.time() - self.ttl_seconds
            self._entries = [e for e in self._entries if e["ts"] >= cutoff]
            self._save()
        except Exception as e:
            self.logger.log(f"[Rollback] record error: {e}", "ERROR")

    def list_recent(self, seconds: int = 3600) -> List[Path]:
        cutoff = time.time() - seconds
        res = []
        for e in self._entries:
            if e["ts"] >= cutoff:
                res.append(Path(e["path"]))
        return res

    def rollback(self, quarantine_dir: Path | None = None) -> int:
        """
        Best-effort rollback: move recent created files to quarantine (or delete if move fails).
        Returns number of files handled.
        """
        handled = 0
        qdir = quarantine_dir or config.quarantine_dir
        qdir.mkdir(parents=True, exist_ok=True)

        for p in self.list_recent(self.ttl_seconds):
            try:
                if not p.exists() or p.is_dir():
                    continue
                dest = qdir / f"{p.name}.{int(p.stat().st_size)}.rollback.quarantined"
                shutil.move(str(p), str(dest))
                handled += 1
            except Exception:
                # try delete as fallback
                try:
                    p.unlink(missing_ok=True)
                    handled += 1
                except Exception as e:
                    self.logger.log(f"[Rollback] failed to handle {p}: {e}", "ERROR")

        return handled
