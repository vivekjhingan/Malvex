# maldefender/realtime_monitor.py
import os
from pathlib import Path
from typing import List, Callable, Any
from watchdog.observers import Observer # Ensure watchdog is handled in main installation check
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

class RealTimeMonitor(FileSystemEventHandler):
    """Real-time file system monitoring"""
    
    def __init__(self, scanner_callback: Callable[[Path], None]):
        super().__init__()
        self.scanner_callback = scanner_callback
        self.observers: List[Observer] = [] # Type hint for observers list
    
    def on_created(self, event: FileCreatedEvent): # More specific event type
        if not event.is_directory:
            # Scan newly created files
            self.scanner_callback(Path(event.src_path))
    
    def on_modified(self, event: FileModifiedEvent): # More specific event type
        if not event.is_directory:
            # Scan modified files
            self.scanner_callback(Path(event.src_path))
    
    def start_monitoring(self, paths: List[str]):
        """Start monitoring specified paths"""
        self.stop_monitoring() # Stop existing observers before starting new ones
        
        self.observers = [] # Clear the list before adding new observers
        for path_str in paths:
            path_obj = Path(path_str) # Convert to Path object for checks
            if path_obj.exists() and path_obj.is_dir(): # Check if path exists and is a directory
                observer = Observer()
                observer.schedule(self, path_str, recursive=True)
                observer.start()
                self.observers.append(observer)
            else:
                # Optionally log a warning if a path is invalid, via a logger if available
                print(f"Warning: Real-time monitoring path does not exist or is not a directory: {path_str}")

    def stop_monitoring(self):
        """Stop all monitoring"""
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=1) # Add a timeout to join to prevent indefinite blocking
            except Exception as e:
                 # Optionally log error if an observer fails to stop/join
                print(f"Error stopping observer: {e}")
        self.observers.clear()