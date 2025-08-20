# maldefender/yara_scanner.py
"""
YARA-based static analysis for MalDefender.

Design goals:
- Compile-once (cached) ruleset with thread-safe reuse.
- Graceful degradation if 'yara-python' is not installed or rules file is missing.
- Safe defaults: filesize cap, match timeout, limited string extraction.
- Clear, structured results for integration with CLI/GUI.

Dependencies:
    yara-python  (pip install yara-python)
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import threading
import traceback

from .app_config import config
from .app_logger import Logger

try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except Exception:
    yara = None  # type: ignore
    _YARA_AVAILABLE = False


# ------------------------------
# Data model for a YARA match
# ------------------------------

@dataclass
class YaraStringHit:
    """Represents a single string match in a YARA rule."""
    identifier: str
    offset: int
    snippet: str  # hex or short preview

@dataclass
class YaraMatch:
    """Structured YARA match result for a file."""
    rule: str
    namespace: Optional[str]
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[YaraStringHit]
    score: int  # derived from meta.score if present, else heuristic

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Keep output small: truncate meta values that are too large
        for k, v in list(d["meta"].items()):
            try:
                s = str(v)
                if len(s) > 512:
                    d["meta"][k] = s[:512] + "...(truncated)"
            except Exception:
                pass
        return d


# ------------------------------
# YaraScanner implementation
# ------------------------------

class YaraScanner:
    """
    Compile and run YARA rules against files.

    Usage:
        ys = YaraScanner(logger)
        matches = ys.scan_file(Path("/path/to/file"))

    Integration contract (with MalwareScanner):
      - When matches are returned (len>0), you may mark the file as 'infected'
        and attach a threat entry with 'hash_types' containing ["YARA"] so
        existing UI paths render consistently.
    """

    # Compile cache shared by all instances (process-wide)
    _lock = threading.Lock()
    _compiled_rules: Optional["yara.Rules"] = None  # type: ignore

    def __init__(
        self,
        logger: Logger,
        rules_path: Optional[Path] = None,
        match_timeout_ms: int = 1500,
        max_preview_bytes: int = 32,
    ):
        self.logger = logger
        self.rules_path = rules_path or config.yara_rules_file
        self.match_timeout_ms = max(200, int(match_timeout_ms))
        self.max_preview_bytes = max(8, int(max_preview_bytes))

        if not _YARA_AVAILABLE:
            self.logger.log(
                "YARA not available (yara-python not installed). YARA scanning disabled.",
                "WARNING"
            )

        # Lazy compilation occurs on first scan to avoid startup cost.

    # ---------- Public API ----------

    def scan_file(self, file_path: Path) -> Tuple[List[YaraMatch], Optional[str]]:
        """
        Scan a file with YARA rules.

        Returns:
            (matches, error)
            - matches: list of YaraMatch
            - error: None on success; otherwise a short error string (already logged)
        """
        if not _YARA_AVAILABLE:
            return [], "yara_unavailable"

        try:
            # Basic sanity checks to avoid expensive/pointless scans
            if not file_path.exists() or not file_path.is_file():
                return [], "not_a_file"

            # Skip very large files by default; tune via config.yara_max_filesize_mb
            max_bytes = int(config.yara_max_filesize_mb * 1024 * 1024)
            try:
                if file_path.stat().st_size > max_bytes:
                    return [], f"filesize_gt_{config.yara_max_filesize_mb}mb"
            except Exception:
                # If stat fails, continue and let YARA handle stream errors
                pass

            rules = self._get_or_compile_rules()
            if rules is None:
                return [], "compile_failed"

            # NB: yara.Rules.match() can raise yara.TimeoutError on timeout
            raw_matches = rules.match(
                filepath=str(file_path),
                timeout=self.match_timeout_ms // 1000 or 1  # seconds (yara expects seconds)
            )

            matches: List[YaraMatch] = []
            for m in raw_matches:
                # Convert string tuples to structured, bounded previews.
                strings: List[YaraStringHit] = []
                try:
                    for (off, ident, data) in m.strings[:64]:  # cap number of strings per rule
                        preview = data[: self.max_preview_bytes]
                        # Convert to safe printable preview
                        snippet = preview.hex() if isinstance(preview, (bytes, bytearray)) else str(preview)[:self.max_preview_bytes]
                        strings.append(YaraStringHit(identifier=str(ident), offset=int(off), snippet=snippet))
                except Exception:
                    # If any malformed string tuple appears, ignore strings but keep the rule
                    pass

                # Score: from rule meta.score if provided, else default 50
                score = 50
                try:
                    if hasattr(m, "meta") and "score" in m.meta:
                        score = int(m.meta["score"])
                except Exception:
                    pass

                ym = YaraMatch(
                    rule=str(getattr(m, "rule", "")),
                    namespace=str(getattr(m, "namespace", "")) if getattr(m, "namespace", None) else None,
                    tags=list(getattr(m, "tags", [])) or [],
                    meta=dict(getattr(m, "meta", {}) or {}),
                    strings=strings,
                    score=score,
                )
                matches.append(ym)

            return matches, None

        except getattr(yara, "TimeoutError", RuntimeError) as e:  # type: ignore[attr-defined]
            self.logger.log(f"YARA scan timeout for {file_path}: {e}", "WARNING")
            return [], "timeout"
        except PermissionError as e:
            self.logger.log(f"YARA permission error for {file_path}: {e}", "WARNING")
            return [], "permission"
        except Exception as e:
            self.logger.log(f"YARA scan error for {file_path}: {e}", "ERROR")
            self.logger.log(traceback.format_exc(), "DEBUG")
            return [], "exception"

    # ---------- Internals ----------

    def _get_or_compile_rules(self) -> Optional["yara.Rules"]:  # type: ignore[name-defined]
        """Compile rules once and cache. Thread-safe."""
        if YaraScanner._compiled_rules is not None:
            return YaraScanner._compiled_rules

        with YaraScanner._lock:
            if YaraScanner._compiled_rules is not None:
                return YaraScanner._compiled_rules

            try:
                rp = self._resolve_rules_path()
                if not rp or not rp.exists():
                    self.logger.log(
                        f"YARA rules file not found at {self.rules_path} (resolved to: {rp}).",
                        "WARNING",
                    )
                    return None

                # Namespaced compile allows growth (split by sections in one file).
                YaraScanner._compiled_rules = yara.compile(filepath=str(rp))
                self.logger.log(f"YARA rules compiled from {rp}", "INFO")
            except Exception as e:
                self.logger.log(f"Failed to compile YARA rules: {e}", "ERROR")
                self.logger.log(traceback.format_exc(), "DEBUG")
                YaraScanner._compiled_rules = None

        return YaraScanner._compiled_rules

    def _resolve_rules_path(self) -> Optional[Path]:
        """
        Resolve a rules path in this priority:
          1) Explicit path from config.yara_rules_file if it exists.
          2) Project-relative fallback maldefender/yara_rules/maldefender_rules.yar
        """
        try:
            # 1) Configured
            if self.rules_path and Path(self.rules_path).exists():
                return Path(self.rules_path)

            # 2) Project default
            project_default = Path(__file__).resolve().parent / "yara_rules" / "maldefender_rules.yar"
            if project_default.exists():
                return project_default
        except Exception:
            pass
        return None
