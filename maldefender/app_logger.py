# maldefender/app_logger.py
from datetime import datetime
from typing import Callable, Optional
from pathlib import Path
from .app_config import config

class Logger:
    """Enhanced logger with GUI integration"""
    
    def __init__(self, gui_callback: Optional[Callable[[str, str], None]] = None):
        self.gui_callback = gui_callback

    from pathlib import Path

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"

        _MAX_LOG = 10 * 1024 * 1024
        log_path = Path(config.log_file)

        # Rotate before writing
        try:
            if log_path.exists() and log_path.stat().st_size > _MAX_LOG:
                rotated = log_path.with_name(log_path.name + ".1")
                if rotated.exists():
                    rotated.unlink()
                log_path.rename(rotated)
        except Exception:
            pass

        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Logging error: {e}")

        if self.gui_callback:
            try:
                self.gui_callback(log_entry, level)
            except Exception as e:
                print(f"GUI callback error: {e}")
        else:
            print(log_entry)
