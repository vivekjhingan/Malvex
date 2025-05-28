# maldefender/app_logger.py
from datetime import datetime
from typing import Callable, Optional

from .app_config import config

class Logger:
    """Enhanced logger with GUI integration"""
    
    def __init__(self, gui_callback: Optional[Callable[[str, str], None]] = None):
        self.gui_callback = gui_callback
    
    def log(self, message: str, level: str = "INFO"):
        """Log a message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Write to file
        try:
            with open(config.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Logging error: {e}") # Fallback to print if file logging fails
        
        # Send to GUI if available
        if self.gui_callback:
            try:
                self.gui_callback(log_entry, level)
            except Exception as e:
                print(f"GUI callback error: {e}") # Log if GUI callback fails
        else:
            # If no GUI callback, print to console (useful for CLI mode or if GUI isn't ready)
            print(log_entry)