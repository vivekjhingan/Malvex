# malvex/app_config.py
import os
import sys
import platform
import json
from pathlib import Path

class Config:
    def __init__(self):
        self.app_name = "Malvex Pro"
        self.version = "2.0"
        self.demo_mode = True  # ✅ New: demo mode toggle

        # Paths - OS agnostic
        if platform.system() == "Windows":
            self.base_dir = Path(os.environ.get('APPDATA', Path.home() / "AppData" / "Roaming")) / "Malvex"
        else:
            self.base_dir = Path.home() / ".malvex"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir = self.base_dir / "quarantine"
        self.signatures_file = self.base_dir / "signatures.json"
        self.log_file = self.base_dir / "malware_scan.log"
        self.config_file = self.base_dir / "config.json"
        
        # Ensure directories exist
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Supported file types
        self.supported_types = {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".py", ".js",
            ".jar", ".apk", ".deb", ".rpm", ".msi", ".dmg", ".pkg",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"
        }
        
        # Archive types
        self.archive_types = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
        
        # Real-time monitoring
        self.realtime_enabled = False
        self.monitor_paths = [str(Path.home() / "Downloads")]

        # YARA configuration
        self.yara_enabled: bool = True
        # Default rules location; can be overridden by user by placing a file at this path
        self.yara_rules_file = self.base_dir / "yara_rules" / "malvex_rules.yar"
        self.yara_max_filesize_mb: int = 64  # per-file soft guard for scanning

        # Ensure rules directory exists (non-fatal if creation fails)
        try:
            self.yara_rules_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    config_data = json.load(f)
                    self.realtime_enabled = config_data.get("realtime_enabled", False)
                    self.monitor_paths = config_data.get("monitor_paths", self.monitor_paths)
                    self.demo_mode = config_data.get("demo_mode", True)  # ✅ Load demo_mode
            except Exception as e:
                print(f"Error loading config: {e}") # Basic logging for config loading issues

    def save_config(self):
        """Save configuration to file"""
        config_data = {
            "realtime_enabled": self.realtime_enabled,
            "monitor_paths": self.monitor_paths,
            "demo_mode": self.demo_mode  # ✅ Save demo_mode
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}") # Basic logging for config saving issues

# Initialize global config instance
config = Config()
