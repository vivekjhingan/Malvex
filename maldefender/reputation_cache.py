# maldefender/reputation_cache.py
"""
Simple, local reputation cache.

- Stores path-based and hash-based reputations (good/bad/unknown).
- Persistence under config.base_dir / reputation.json
- Thread-safe and low overhead.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Literal, Optional

from .app_config import config
from .app_logger import Logger
from .file_utils import FileHasher

Repute = Literal["known_good", "known_bad", "unknown"]


class ReputationCache:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.path = config.base_dir / "reputation.json"
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, str]] = {"paths": {}, "sha256": {}}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as e:
            self.logger.log(f"[Reputation] load error: {e}", "ERROR")

    def _save(self) -> None:
        try:
            self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception as e:
            self.logger.log(f"[Reputation] save error: {e}", "ERROR")

    def repute(self, file_path: Path) -> Repute:
        try:
            key = str(file_path).lower()
            with self._lock:
                rp = self._data.get("paths", {}).get(key)
                if rp:
                    return rp  # type: ignore[return-value]
            # Fallback: hash
            _, sha256 = FileHasher.get_hashes(file_path)
            if not sha256:
                return "unknown"
            with self._lock:
                return self._data.get("sha256", {}).get(sha256.lower(), "unknown")  # type: ignore[return-value]
        except Exception:
            return "unknown"

    def set_path(self, file_path: Path, rep: Repute) -> None:
        with self._lock:
            self._data["paths"][str(file_path).lower()] = rep
            self._save()

    def set_hash(self, sha256_hex: str, rep: Repute) -> None:
        with self._lock:
            self._data["sha256"][sha256_hex.lower()] = rep
            self._save()
